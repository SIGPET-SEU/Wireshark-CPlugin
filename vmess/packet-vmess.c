/* packet-vmess.c
 *
 * Updated routines for VMess protocol packet dissection
 * By Linxiao Yu <yulinxiaoybbb@gmail.com>
 *
 * Routines for VMess protocol packet disassembly
 * By Linxiao Yu <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: https://xtls.github.io/development/protocols/vmess.html
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include <wsutil/file_util.h>
#include <wsutil/wslog.h>
#include <string.h>
#include <epan/tfs.h>
#include "packet-vmess.h"

/*
 * Key log file handle. Opened on demand (when keys are actually looked up),
 * closed when the capture file closes.
 */
static FILE* vmess_keylog_file;
static vmess_key_map_t vmess_key_map; /* Structure used for recording auth, key and IV's */

static dissector_handle_t vmess_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t vmess_request_handle;

static char* TLS_signiture[TLS_SIGNUM] = {
    "\x14\x03\x03", /* Change Cipher Spec */
    "\x15\x03\x03", /* Alert */
    "\x16\x03\x03", /* Handshake */
    "\x16\x03\x01", /* Handshake Legacy */
    "\x17\x03\x03"  /* Application Data */
};

static bool vmess_desegment = true; /* VMess is run atop of TCP */

/* Keylog and decryption related variables and routines */
static bool vmess_decryption_supported;
static const gchar* pref_keylog_file;

static int proto_vmess;

/****************VMess Fields******************/
static int hf_vmess_request_auth;
static int hf_vmess_request_length;
static int hf_vmess_request_conn_nonce;
static int hf_vmess_response_header;
static int hf_vmess_payload_length;

/**
 * MSB          ---->            LSB
 * ---------------------------------
 * |        Options(8 bits)        |
 * ---------------------------------
 * | X | X | X | X | X | M | R | S | 
 * ---------------------------------
 * 
 * X stands for reserved bit
 * 
 */

/* Option masks */
#define OPT_S       0x01
#define OPT_R       0x02
#define OPT_M       0x04
#define OPT_RES     0xF8
#define OPT_MASK    0xFF

static int hf_vmess_request_opt;
static int hf_vmess_request_opt_res;/* Reserved */
static int hf_vmess_request_opt_M;  /* Meta info obfuscation */
static int hf_vmess_request_opt_R;  /* Reuse TCP connection, deprecated since XRay Ver. 2.23+ */
static int hf_vmess_request_opt_S;  /* Standard stream format */

/**
 * The VMess spec for encryption method seems to differ from the Clash and X2Ray implementations.
 */
static const value_string encryption_method[] = {
        { 0x03, "AES-128-GCM" },
        { 0x04, "ChaCha20-Poly1305" },
        { 0x05, "None" },
        { 0, NULL },
};

#define PADDING_MASK    0xF0
#define ENC_METHOD_MASK 0x0F

static int hf_vmess_request_P;          /* Random padding*/
static int hf_vmess_request_enc;        /* Encryption method */

static const value_string request_cmd[] = {
        { 0x01, "TCP" },
        { 0x02, "UDP" },
        { 0, NULL },
};

static int hf_vmess_request_cmd;        /* TCP/UDP */
static int hf_vmess_request_port;       /* Port */

static const value_string request_addr_type[] = {
        { 0x01, "IPv4" },
        { 0x02, "Domain" },
        { 0x03, "IPv6" },
        { 0, NULL },
};

static int hf_vmess_request_addr_type;       /* Address type */
static int hf_vmess_request_addr;       /* Address */

// heads for displaying reassembly information
static int hf_msg_fragments;
static int hf_msg_fragment;
static int hf_msg_fragment_overlap;
static int hf_msg_fragment_overlap_conflicts;
static int hf_msg_fragment_multiple_tails;
static int hf_msg_fragment_too_long_fragment;
static int hf_msg_fragment_error;
static int hf_msg_fragment_count;
static int hf_msg_reassembled_in;
static int hf_msg_reassembled_length;
static int hf_msg_body_segment;
/**************VMess Fields End****************/

/**************VMess ETT Fileds****************/

static int ett_vmess;

static gint ett_msg_fragment;
static gint ett_msg_fragments;
static gint ett_vmess_opt;

/************VMess ETT Fileds End**************/

static const fragment_items msg_frag_items = {
    &ett_msg_fragment,
    &ett_msg_fragments,
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    &hf_msg_reassembled_in,
    &hf_msg_reassembled_length,
};

static GString* kdfSaltConstAuthIDEncryptionKey;
static GString* kdfSaltConstAEADRespHeaderLenKey;
static GString* kdfSaltConstAEADRespHeaderLenIV;
static GString* kdfSaltConstAEADRespHeaderPayloadKey;
static GString* kdfSaltConstAEADRespHeaderPayloadIV;
static GString* kdfSaltConstVMessAEADKDF;
static GString* kdfSaltConstVMessHeaderPayloadAEADKey;
static GString* kdfSaltConstVMessHeaderPayloadAEADIV;
static GString* kdfSaltConstVMessHeaderPayloadLengthAEADKey;
static GString* kdfSaltConstVMessHeaderPayloadLengthAEADIV;

/**
 * The VMess request with AEAD encryption is divided into 4 parts:
 * ----------------------------------------------------------------------------------------------------------------------------
 * | generatedID (16B) | payloadHeaderLengthAEADEncrypted (18B) | connectionNonce (8B) | payloadLengthAEADEncrypted (Len+16B) |
 * ----------------------------------------------------------------------------------------------------------------------------
 * Where payloadHeaderLengthAEADEncrypted consists of actual length (2B) along with 16B tag (for AES-GCM);
 * When we successfully decrypt the actual length, we fetch its value (Len), which is used for header decryption.
 * 
 * The actual decryption algorithm for this routine runs as follows:
 * 1. Initialize the req_length_decoder and req_decoder separately, using vmess_kdf for key derivation;
 * 2. Fetch the pointer to tvb+16 with length=18, and perform header length decryption using req_length_decoder;
 * 3. Add the actual header length to the dissect tree;
 * 4. Fetch the pointer to tvb+42 with length=Len+16, and perform header decryption using req_decoder;
 * 5. Dissect the decrypted header, and append necessary information to the dissect tree;
 * 6. Add the decrypted header bytes to a new tab.
 * 
 * TODO: Error handling and logging.
 * 
 * @param tvb, pinfo, offset
 * @param conv_data     The conversation data related to the current VMess conversation.
 */
static gboolean
decrypt_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint32 offset, vmess_conv_t* conv_data) {
    GString* req_key = (GString *)g_hash_table_lookup(vmess_key_map.req_key, conv_data->auth);
    if (req_key == NULL) {
        vmess_debug_printf("VMess key not found, impossible to decrypt.\n");
        return false; /* Decryption failed */
    }
    GString* req_iv = (GString*)g_hash_table_lookup(vmess_key_map.req_iv, conv_data->auth);
    if (req_iv == NULL) {
        vmess_debug_printf("VMess IV not found, impossible to decrypt.\n");
        return false; /* Decryption failed */
    }

    /************************ Header Length AEAD Decryption ************************/
    guchar* payloadHeaderLengthAEADKey = g_malloc(AES_128_KEY_SIZE);
    /* payloadHeaderLengthAEADNonce should have the same liftspan as the decoder.
     * See https://docs.gtk.org/glib/type_func.ByteArray.append.html
     */
    guchar* payloadHeaderLengthAEADNonce = wmem_alloc(wmem_file_scope(), GCM_IV_SIZE);
    guchar* tmp_derived_key;
    
    /* Initialize the request_len_decoder */
    tmp_derived_key = vmess_kdf(req_key->str, req_key->len, 3,
        kdfSaltConstVMessHeaderPayloadLengthAEADKey,
        conv_data->auth,
        req_iv);
    memcpy(payloadHeaderLengthAEADKey, tmp_derived_key, AES_128_KEY_SIZE);
    g_free(tmp_derived_key);

    tmp_derived_key = vmess_kdf(req_key->str, req_key->len, 3,
        kdfSaltConstVMessHeaderPayloadLengthAEADIV,
        conv_data->auth,
        req_iv);
    memcpy(payloadHeaderLengthAEADNonce, tmp_derived_key, GCM_IV_SIZE);
    g_free(tmp_derived_key);

    conv_data->req_length_decoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                                    payloadHeaderLengthAEADKey, payloadHeaderLengthAEADNonce, 0);
    guint aeadPayloadLengthSize = 2;
    guchar* AEADPayloadLengthSerializedByte = g_malloc(aeadPayloadLengthSize);

    gcry_error_t err = vmess_byte_decryption(conv_data->req_length_decoder,
                                            tvb_get_ptr(tvb, 16, aeadPayloadLengthSize + 16),
                                            aeadPayloadLengthSize + 16,
                                            AEADPayloadLengthSerializedByte,
                                            aeadPayloadLengthSize,
                                            conv_data->auth->str, conv_data->auth->len);
    if (err != 0) {
        vmess_debug_printf("VMess header length decryption failed: %s.\n", gcry_strsource(err));
        return false; /* Decryption failed */
    }
    /* Get the length of header. */
    guint16 aeadPayloadLength = (guint16)AEADPayloadLengthSerializedByte[0] << 8 | (guint16)AEADPayloadLengthSerializedByte[1];

    /* DO NOT free the payloadHeaderLengthAEADNonce. */
    g_free(payloadHeaderLengthAEADKey);
    g_free(AEADPayloadLengthSerializedByte);


    /************************ Header Payload AEAD Decryption ************************/
    guchar* payloadHeaderAEADKey = g_malloc(AES_128_KEY_SIZE);
    guchar* payloadHeaderAEADNonce = wmem_alloc(wmem_file_scope(), GCM_IV_SIZE);
    /* Initialize the request_len_decoder */
    tmp_derived_key = vmess_kdf(req_key->str, req_key->len, 3,
        kdfSaltConstVMessHeaderPayloadAEADKey,
        conv_data->auth,
        req_iv);
    memcpy(payloadHeaderAEADKey, tmp_derived_key, AES_128_KEY_SIZE);
    g_free(tmp_derived_key);

    tmp_derived_key = vmess_kdf(req_key->str, req_key->len, 3,
        kdfSaltConstVMessHeaderPayloadAEADIV,
        conv_data->auth,
        req_iv);
    memcpy(payloadHeaderAEADNonce, tmp_derived_key, GCM_IV_SIZE);
    g_free(tmp_derived_key);

    guchar* aeadPayload = g_malloc(aeadPayloadLength);

    conv_data->req_decoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
        payloadHeaderAEADKey, payloadHeaderAEADNonce, 0);

    err = vmess_byte_decryption(conv_data->req_decoder,
        tvb_get_ptr(tvb, 42, aeadPayloadLength + 16),
        aeadPayloadLength + 16,
        aeadPayload, aeadPayloadLength,
        conv_data->auth->str, conv_data->auth->len);
    if (err != 0) {
        vmess_debug_printf("VMess header payload decryption failed: %s.\n", gcry_strsource(err));
        return false; /* Decryption failed */
    }

    /* It seems that key=0 in p_add_proto_data is enough for VMess */
    vmess_packet_info_t* packet = (vmess_packet_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_vmess, 0);
    if (!packet) {
        packet = wmem_new0(wmem_file_scope(), vmess_packet_info_t);
        packet->from_server = FALSE;
        packet->messages = NULL;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_vmess, 0, packet);
    }

    gint record_id = tvb_raw_offset(tvb) + offset;

    vmess_message_info_t* message = wmem_new0(wmem_file_scope(), vmess_message_info_t);
    message->type = VMESS_REQUEST;
    message->data_len = aeadPayloadLength;
    message->id = 0; /* Should be record_id, set to 0 for testing purpose */
    message->plain_data = wmem_memdup(wmem_file_scope(), aeadPayload, aeadPayloadLength);
    message->next = NULL;

    vmess_message_info_t** pmessages = &packet->messages;
    while (*pmessages) /* Iterate to the tail */
        pmessages = &(*pmessages)->next;
    *pmessages = message; /* Append to the tail */

    return true;
}


int dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Request");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMess");
    proto_item* ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    proto_tree* vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_request_auth, tvb, 0, 16, ENC_BIG_ENDIAN);
    /* Add the connectionNonce to the tree */
    proto_tree_add_item(vmess_tree, hf_vmess_request_conn_nonce, tvb, 34, 8, ENC_BIG_ENDIAN);
    conversation_t* conversation;
    vmess_conv_t* conv_data;
    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);
    /* get associated state information, create if necessary */
    conv_data = get_vmess_conv(conversation, proto_vmess);
    copy_address_wmem(wmem_file_scope(), &conv_data->srv_addr, &pinfo->dst);
    conv_data->srv_port = pinfo->destport;

    /* If the header packet is decrypted, try to perform decryption */
    if (!conv_data->req_decrypted){
        gboolean success = decrypt_vmess_request(tvb, pinfo, vmess_tree, 0, conv_data);
        if (!success) return 0; /* Give up decryption upon failure. */
        conv_data->req_decrypted = TRUE;
    }

    vmess_message_info_t* msg = get_vmess_message(pinfo, 0);
    if (!msg)
        return 0;

    proto_tree_add_uint(vmess_tree, hf_vmess_request_length, tvb, 0, 0, msg->data_len);
    dissect_decrypted_vmess_request(tvb, pinfo, vmess_tree, msg);

    return 0;
}

int dissect_decrypted_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, vmess_message_info_t* msg)
{
    guchar* plaintext = msg->plain_data;
    guint plaintext_len = msg->data_len;
    proto_item* opt_ti;
    proto_tree* opt_tree;

    tvbuff_t* packet_tvb = tvb_new_child_real_data(tvb, plaintext, plaintext_len, plaintext_len);
    add_new_data_source(pinfo, packet_tvb, "Decrypted VMess");

    /* Dissect Opt as a subtree and add human-friendly info */
    guint8 opt = (guint8)plaintext[34];
    opt_ti = proto_tree_add_uint(tree, hf_vmess_request_opt, packet_tvb, 34, 1, opt);
    opt_tree = proto_item_add_subtree(opt_ti, ett_vmess_opt);
    proto_tree_add_boolean(opt_tree, hf_vmess_request_opt_res, packet_tvb, 34, 1, (gboolean)(opt & OPT_RES));
    proto_tree_add_boolean(opt_tree, hf_vmess_request_opt_M, packet_tvb, 34, 1, (gboolean)(opt & OPT_M));
    proto_tree_add_boolean(opt_tree, hf_vmess_request_opt_R, packet_tvb, 34, 1, (gboolean)(opt & OPT_R));
    proto_tree_add_boolean(opt_tree, hf_vmess_request_opt_S, packet_tvb, 34, 1, (gboolean)(opt & OPT_S));

    proto_tree_add_uint(tree, hf_vmess_request_P, packet_tvb, 35, 1, (guint8)((plaintext[35] & PADDING_MASK) >> 4));
    proto_tree_add_uint(tree, hf_vmess_request_enc, packet_tvb, 35, 1, (guint8)(plaintext[35] & ENC_METHOD_MASK));


    proto_tree_add_uint(tree, hf_vmess_request_cmd, packet_tvb, 37, 1, plaintext[37]);
    guint16 port = plaintext[38] << 8 | plaintext[39];
    proto_tree_add_uint(tree, hf_vmess_request_port, packet_tvb, 38, 2, port);

    proto_tree_add_uint(tree, hf_vmess_request_addr_type, packet_tvb, 40, 1, plaintext[40]);
    guint N = plaintext_len - 4 - (guint)((plaintext[35] & PADDING_MASK) >> 4) - 41; /* Compute the length of addr */
    proto_tree_add_item(tree, hf_vmess_request_addr, packet_tvb, 41, N, ENC_ASCII);

    /* TODO: Check F and log possible warnings */

    return 0;
}

guint get_dissect_vmess_response_len(packet_info* pinfo _U_, tvbuff_t* tvb,
    int offset, void* data _U_) {
    return tvb_get_ntohs(tvb, offset + 38) + 40;
}

int dissect_vmess_response_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_tree* vmess_tree;
    proto_item* ti;
    tvbuff_t* next_tvb;

    conversation_t* conversation;
    vmess_conv_t* conv_data;
    int offset = 0;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = get_vmess_conv(conversation, proto_vmess);

    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Response");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMess");
    ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_response_header, tvb, 0, 38, ENC_BIG_ENDIAN);
    proto_tree_add_item(vmess_tree, hf_vmess_payload_length, tvb, 38, 2, ENC_BIG_ENDIAN);
    

    next_tvb = tvb_new_subset_remaining(tvb, 40);

    if (next_tvb) {
        reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
            vmess_tree, tree, proto_vmess_streaming_reassembly_table,
            conv_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
            proto_tree_get_parent_tree(tree), NULL, "VMess", &msg_frag_items, hf_msg_body_segment);
    }

    return 0;
}

guint get_dissect_vmess_data_len(packet_info* pinfo _U_, tvbuff_t* tvb,
    int offset, void* data _U_) {
    return tvb_get_ntohs(tvb, offset) + 2;
}

/**
 * Decrypt the data packets. According to the Clash implementation, the AEAD encryption maintains the counter
 * to generate the AEAD nonce. Therefore, we have to add the from_server, count_server, and count_client fields
 * to enable AEAD decryption.
 * 
 * TODO: Calculate the from_server
 * 
 * \param tvb
 * \param pinfo
 * \param tree
 * \param offset
 * \param conv_data
 * \return 
 */
static gboolean
decrypt_vmess_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint32 offset, vmess_conv_t* conv_data) {

}

int dissect_vmess_data_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_tree* vmess_tree;
    proto_item* ti;
    tvbuff_t* next_tvb;

    conversation_t* conversation;
    vmess_conv_t* conv_data;
    int offset = 0;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = get_vmess_conv(conversation, proto_vmess);

    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Data");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMess");
    ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_payload_length, tvb, 0, 2, ENC_BIG_ENDIAN);
    /* TODO: Perform decryption on the tvb */
    guint16 payload_length = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);

    /* TODO: The next_tvb should be the decrypted one */
    next_tvb = tvb_new_subset_length(tvb, 2, payload_length);

    if (next_tvb) {
        reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
            vmess_tree, tree, proto_vmess_streaming_reassembly_table,
            conv_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
            proto_tree_get_parent_tree(tree), NULL, "VMess", &msg_frag_items, hf_msg_body_segment);
    }

    return 0;
}

int dissect_vmess(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t* conversation;
    vmess_conv_t* conv_data = NULL;
    port_type save_port_type;
    guint16 save_can_desegment;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = get_vmess_conv(conversation, proto_vmess);

    vmess_keylog_read();

    bool is_request = false;

    /* The request could be dissected only once, since it occupies exactly one packet. */
    if (tvb_reported_length(tvb) > 61) { /* Minimum VMess request length */
        gchar* tmp_auth_raw_data = (gchar*)g_malloc((VMESS_AUTH_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth_raw_data, (VMESS_AUTH_LENGTH + 1));

        GString* tmp_auth = g_string_new_len(tmp_auth_raw_data, VMESS_AUTH_LENGTH);
        g_free(tmp_auth_raw_data);

        GString* key = (GString*)g_hash_table_lookup(vmess_key_map.req_key, tmp_auth);
        if (key) {
            if (!PINFO_FD_VISITED(pinfo) && !conv_data->auth) {
                /* Only when the auth is found should we create a auth in file scope */
                conv_data->auth = wmem_new0(wmem_file_scope(), GString);
                conv_data->auth = g_string_append_len(conv_data->auth, tmp_auth->str, tmp_auth->len);
            }
            is_request = true;
        }
        g_string_free(tmp_auth, true);
    }

    if (is_request) {

        dissect_vmess_request(tvb, pinfo, tree, data);

        vmess_debug_flush();

        return tvb_captured_length(tvb);
    }

    bool is_response = false;
    gint pos = tvb_find_TLS_signiture(tvb);
    if (pos == 40) is_response = true;

    save_port_type = pinfo->ptype;
    pinfo->ptype = PT_NONE;
    save_can_desegment = pinfo->can_desegment;
    pinfo->can_desegment = pinfo->saved_can_desegment;

    if (conv_data && is_response && pinfo->num > conv_data->startframe) {
        tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment,
            VMESS_RESPONSE_HEADER_LENGTH,
            get_dissect_vmess_response_len,
            dissect_vmess_response_pdu, data);
    }
    else {
        tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment,
            VMESS_DATA_HEADER_LENGTH, get_dissect_vmess_data_len,
            dissect_vmess_data_pdu, data);
    }

    pinfo->ptype = save_port_type;
    pinfo->can_desegment = save_can_desegment;

    vmess_debug_flush();

    return tvb_reported_length(tvb);
}

void vmess_keylog_read(void) {
    if (!vmess_decryption_supported) {
        return;
    }

    if (!pref_keylog_file || !*pref_keylog_file) {
        vmess_debug_printf("No Keylog file is selected.\n");
        return;
    }

    // Reopen file if it got deleted/overwritten.
    if (vmess_keylog_file && file_needs_reopen(ws_fileno(vmess_keylog_file), pref_keylog_file)) {
        ws_debug("Key log file got changed or deleted, trying to re-open.");
        vmess_keylog_reset();
        vmess_keylog_remove(&vmess_key_map);
    }

    if (!vmess_keylog_file) {
        vmess_keylog_file = ws_fopen(pref_keylog_file, "r");
        if (!vmess_keylog_file) {
            ws_debug("Failed to open key log file %s: %s", pref_keylog_file, g_strerror(errno));
            return;
        }
        ws_debug("Opened key log file %s", pref_keylog_file);
    }

    for (;;) {
        char buf[512], *line;
        line = fgets(buf, sizeof(buf), vmess_keylog_file);
        if (!line) {
            if (feof(vmess_keylog_file)) {
                clearerr(vmess_keylog_file);
                /* For debugging, print the key map table. */
//#define VMESS_DEBUG_PRINT_KEY_MAP
#ifdef VMESS_DEBUG_PRINT_KEY_MAP
                //vmess_debug_print_hash_table(vmess_key_map);
#endif // VMESS_DEBUG_PRINT_KEY_MAP
            }
            else if (ferror(vmess_keylog_file)) {
                ws_debug("Error while reading %s, closing it.", pref_keylog_file);
                vmess_keylog_reset();
                vmess_keylog_remove(&vmess_key_map);
            }
            break;
        }
        vmess_keylog_process_line((const guint8*)line, strlen(line), &vmess_key_map);
    }

}

static GRegex*
vmess_compile_keyfile_regex(void)
{
#define OCTET "(?:[[:xdigit:]]{2})"
    const gchar* pattern =
        "(?:"
        /* VMess AUTH to Derived Secrets mapping. */
        "HEADER_KEY (?<header_key>" OCTET "{16})"
        "|HEADER_IV (?<header_iv>" OCTET "{16})"
        "|DATA_KEY (?<data_key>" OCTET "{16})"
        "|DATA_IV (?<data_iv>" OCTET "{16})"
        "|RESPONSE_TOKEN (?<response_token>" OCTET "{16})"
        ") (?<secret>" OCTET "+)";
#undef OCTET
    static GRegex* regex = NULL;
    GError* gerr = NULL;
    if (!regex) {
        regex = g_regex_new(pattern,
            (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_ANCHORED, &gerr);
        if (gerr) {
            g_print("%s failed to compile regex: %s\n", G_STRFUNC,
                gerr->message);
            g_error_free(gerr);
            regex = NULL;
        }
    }
    return regex;
}

void vmess_keylog_process_line(const char* data, const guint8 datalen, vmess_key_map_t* km)
{
    ws_noisy("vmess process line: %s", data);

    vmess_key_match_group_t km_group[] = {
        {"header_key", km->req_key},
        {"header_iv", km->req_iv},
        {"data_key", km->data_key},
        {"data_iv", km->data_iv},
        {"response_token", km->response_token}
    };

    GRegex* regex = vmess_compile_keyfile_regex();
    if (!regex)
        return;

    /* We follow the keylog structure as that defined in
     * https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html.
     *
     * Each line of the keylog file should follow the format:
     * <LABEL>   <AUTH>   <SECRET>
     * where <LABEL> MUST be one of the following:
     * HEADER_KEY: Used to encrypt the header;
     * HEADER_IV: Used as the nonce to encrypt the header;
     * DATA_KEY: Used to encrypt the data;
     * DATA_IV: Used as the nonce to encrypt the data;
     * RESPONSE_TOKEN: Used to match VMess requests and responses.
     */

    /*
     * Use wmem_xxx first, then consider g_xxx, finally seek for xxx in standard C lib.
     * See https://gitlab.com/wireshark/wireshark/-/blob/master/doc/README.wmem
     * 
     * NOTE: Memory allocated by wmem_alloc should be freed with wmem_free,
     * memory allocated by g_malloc should be freed using g_free.
     * Otherwise, it may cause Access Violation Reading exception.
     */

    /* Strip possible newline characters, e.g., '\r', '\n'. */
    const char* next_line = (const char*)data;
    const char* line_end = next_line + datalen;
    const char* line = next_line;
    next_line = (const char*)memchr(line, '\n', line_end - line);
    gssize linelen;

    if (next_line) {
        linelen = next_line - line;
        next_line++;    /* drop LF */
    }
    else {
        linelen = (gssize)(line_end - line);
    }
    if (linelen > 0 && line[linelen - 1] == '\r') {
        linelen--;      /* drop CR */
    }

    GMatchInfo* mi;
    gboolean result = g_regex_match_full(regex, line, linelen, 0, G_REGEX_MATCH_ANCHORED, &mi, NULL);
    if (result) {
        /* Note that the secret read in is in plaintext form, it should be converted into hex form later. */
        gchar* hex_secret;
        gchar* hex_auth;
        GString* auth = wmem_new(wmem_file_scope(), GString);
        GString* secret = wmem_new(wmem_file_scope(), GString); /* We use byte array to store the hex-formed secrets. */
        GHashTable* ht = NULL;

        hex_secret = g_match_info_fetch_named(mi, "secret");

        /* G_N_ELEMENTS counts the number of entries in a static initialized array,
         * by computing sizeof(arr)/sizeof(arr[0]). Therefore, calling this macro
         * on a dynamically allocated array gives an incorrect answer.
         */
        for (int i = 0; i < G_N_ELEMENTS(km_group); i++) {
            vmess_key_match_group_t* g = &km_group[i];
            hex_auth = g_match_info_fetch_named(mi, g->re_group_name);
            if (hex_auth && *hex_auth) {
                ht = g->key_ht;
                from_hex(hex_auth, auth, strlen(hex_auth));
                from_hex(hex_secret, secret, strlen(hex_secret));
                g_free(hex_auth);
                break;
            }
            g_free(hex_auth);
        }
        g_free(hex_secret);
        g_hash_table_insert(ht, auth, secret);
    }
    else if (linelen > 0 && line[0] != '#') {
        return; /* In VMess dissection, here one should raise some exception. */
    }
    /* always free match info even if there is no match. */
    g_match_info_free(mi);
}


gboolean vmess_decrypt_init(void) {
    return TRUE;
}

void vmess_keylog_remove(vmess_key_map_t* mk)
{
    g_hash_table_remove_all(mk->data_iv);
    g_hash_table_remove_all(mk->data_key);
    g_hash_table_remove_all(mk->req_iv);
    g_hash_table_remove_all(mk->req_key);
    g_hash_table_remove_all(mk->response_token);
}

static void
vmess_keylog_reset(void)
{
    if (vmess_keylog_file) {
        fclose(vmess_keylog_file);
        vmess_keylog_file = NULL;
    }
}

VMessDecoder*
vmess_decoder_new(int algo, int mode, guchar* key, guchar* iv, guint flags) {
    VMessDecoder* decoder = wmem_new0(wmem_file_scope(), VMessDecoder);

    vmess_cipher_suite_t* suite = wmem_new0(wmem_file_scope(), vmess_cipher_suite_t);
    suite->mode = mode;
    suite->algo = algo;
    decoder->cipher_suite = suite;

    guint key_len = gcry_cipher_get_algo_keylen(algo);
    guint iv_len;
    switch (mode) {
        // For GCM and POLY1305, bulk length needs to be overwritten.
    case GCRY_CIPHER_MODE_GCM:
        iv_len = GCM_IV_SIZE;
        break;
    case GCRY_CIPHER_MODE_POLY1305:
        iv_len = POLY1305_IV_SIZE;
        break;
    default:
        iv_len = gcry_cipher_get_algo_blklen(algo);
    }
    vmess_cipher_init(&decoder->evp, algo, mode, key, key_len, iv, iv_len, flags);
    /* Save IV for possible cipher reset */
    decoder->write_iv = wmem_new0(wmem_file_scope(), GString);
    decoder->write_iv = g_string_append_len(decoder->write_iv, iv, iv_len);
    return decoder;
}

gcry_error_t
vmess_cipher_init(gcry_cipher_hd_t* hd, int algo, int mode, guchar* key, gsize key_len, guchar* iv, gsize iv_len, guint flags)
{
    /*
     * As the libgcrypt manual indicates (Sec 3.2.1), the gcry_error_t consists of code and source
     * components. However, when set to 0, the error itself represents a success.
     */
    gcry_error_t err = 0;
    err = gcry_cipher_open(hd, algo, mode, flags);
    GCRYPT_CHECK(err)

    if (key_len == 0) key_len = gcry_cipher_get_algo_keylen(algo);
    err = gcry_cipher_setkey(*hd, key, key_len);
    GCRYPT_CHECK(err)

    if (iv_len == 0) iv_len = gcry_cipher_get_algo_blklen(algo);
    err = gcry_cipher_setiv(*hd, iv, iv_len);
    GCRYPT_CHECK(err)
    return err;
}

HMACCreator*
hmac_creator_new(HMACCreator* parent, const guchar* value, gsize value_len) {
    HMACCreator* creator = malloc(sizeof(HMACCreator));
    creator->parent = parent;
    creator->h_in = malloc(sizeof(gcry_md_hd_t));
    creator->h_out = malloc(sizeof(gcry_md_hd_t));

    creator->value_len = value_len;
    creator->value = malloc(value_len);
    memcpy(creator->value, value, creator->value_len);

    return creator;
}

void
hmac_creator_free(HMACCreator* creator) {
    if (creator->parent)
        hmac_creator_free(creator->parent);

    gcry_md_close(*creator->h_in);
    gcry_md_close(*creator->h_out);
    g_free(creator->value);
    g_free(creator->h_in);
    g_free(creator->h_out);
    g_free(creator);
}

gcry_error_t
hmac_create(const HMACCreator* creator) {
    gcry_error_t err = 0;
    if (creator->parent == NULL) {
        /* No HMAC flags are set since we handle HMAC by our implementation. */
        gcry_md_open(creator->h_in, GCRY_MD_SHA256, 0);
        gcry_md_open(creator->h_out, GCRY_MD_SHA256, 0);
        /* If the length of key is smaller than block size, pad it with 0's */
        guchar block_key[SHA_256_BLOCK_SIZE] = { 0 };
        guchar key_ipad[SHA_256_BLOCK_SIZE], key_opad[SHA_256_BLOCK_SIZE];
        /*
         * HMAC use the key following the rules below:
         * If value_len > block_size, key = HASH(value);
         * Otherwise, key = value
         */
        if (creator->value_len > SHA_256_BLOCK_SIZE) {
            gcry_md_hd_t h_copy;
            err = gcry_md_copy(&h_copy, *creator->h_out);
            GCRYPT_CHECK(err)
                gcry_md_write(h_copy, creator->value, creator->value_len);
            memcpy(block_key, gcry_md_read(h_copy, gcry_md_get_algo(h_copy)), gcry_md_get_algo_dlen(GCRY_MD_SHA256));
            gcry_md_close(h_copy);
        }
        else {
            memcpy(block_key, creator->value, creator->value_len);
        }
        /* Create key_ipad and key_opad */
        for (guint i = 0; i < SHA_256_BLOCK_SIZE; i++) {
            key_ipad[i] = 0x36 ^ block_key[i];
            key_opad[i] = 0x5c ^ block_key[i];
        }
        gcry_md_write(*creator->h_in, key_ipad, SHA_256_BLOCK_SIZE);
        gcry_md_write(*creator->h_out, key_opad, SHA_256_BLOCK_SIZE);
    }
    else {
        err = hmac_create(creator->parent);
        GCRYPT_CHECK(err)
            gcry_md_copy(creator->h_in, *creator->parent->h_in);
        gcry_md_copy(creator->h_out, *creator->parent->h_in);
        guchar block_key[SHA_256_BLOCK_SIZE] = { 0 };
        guchar key_ipad[SHA_256_BLOCK_SIZE], key_opad[SHA_256_BLOCK_SIZE];
        if (creator->value_len > SHA_256_BLOCK_SIZE) {
            /* For KDF functions, this subroutine should NOT be hit. */
            /* NOT IMPLEMENTED */
        }
        else {
            memcpy(block_key, creator->value, creator->value_len);
        }
        /* Create key_ipad and key_opad */
        for (guint i = 0; i < SHA_256_BLOCK_SIZE; i++) {
            key_ipad[i] = 0x36 ^ block_key[i];
            key_opad[i] = 0x5c ^ block_key[i];
        }
        gcry_md_write(*creator->h_in, key_ipad, SHA_256_BLOCK_SIZE);
        gcry_md_write(*creator->h_out, key_opad, SHA_256_BLOCK_SIZE);
    }
    return 0;
}

/*
 * Create the request order based on the size. The hash requests are
 * performed on the array, so only numeric order is needed.
 */
static guint*
request_order(int size) {
    if (size < 2) return NULL; /* This should not happen since HMAC requires at least 2 hash handles. */
    guint* tmp, * result;
    result = malloc((1 << (size - 1)) * sizeof(guint));
    result[0] = 0, result[1] = 1; /* Initializer */

    for (int i = 3; i <= size; i++) {
        int tmp_size = 1 << (i - 1);
        tmp = g_malloc(tmp_size * sizeof(guint));
        for (int j = 0; j < tmp_size; j += 2) {
            tmp[j] = result[j / 2];
            tmp[j + 1] = i - 1;
        }
        memcpy(result, tmp, tmp_size * sizeof(guint));
        g_free(tmp);
    }

    return result;
}

HMACDigester* hmac_digester_new(HMACCreator* creator) {
    if (!creator) return NULL;

    /* Create handler array */
    HMACDigester* digester = malloc(sizeof(HMACDigester));
    int size = 1; // creator->h_in
    for (HMACCreator* p = creator; p; p = p->parent)
        size++; // All other hash handles needed are p->h_out

    digester->size = size;
    digester->head = malloc(size * sizeof(gcry_md_hd_t*));

    digester->head[0] = malloc(sizeof(gcry_md_hd_t));
    gcry_md_copy(digester->head[0], *creator->h_in);

    HMACCreator* p = creator;
    for (guint i = 1; i < size; i++) {
        digester->head[i] = malloc(sizeof(gcry_md_hd_t));
        gcry_md_copy(digester->head[i], *p->h_out);
        p = p->parent;
    }

    /* Create hash request order */
    digester->order = request_order(size);
    return digester;
}

void
hmac_digester_free(HMACDigester* digester) {
    for (int i = 0; i < digester->size; i++) {
        gcry_md_close(*digester->head[i]);
        g_free(digester->head[i]);
    }
    g_free(digester->head);
    g_free(digester->order);
    g_free(digester);
}

gcry_error_t
hmac_digest(HMACDigester* digester, const guchar* msg, gssize msg_len, guchar* digest) {
    gcry_error_t err = 0;
    /* Initializer */
    err = hmac_digest_on_copy(*digester->head[0], msg, msg_len, digest);
    GCRYPT_CHECK(err)

        for (int i = 1; i < 1 << (digester->size - 1); i++) {
            guint cur_hd_order = digester->order[i];
            err = hmac_digest_on_copy(*digester->head[cur_hd_order], digest,
                gcry_md_get_algo_dlen(GCRY_MD_SHA256), digest);
            GCRYPT_CHECK(err)
        }
    return err;
}

gcry_error_t
hmac_digest_on_copy(gcry_md_hd_t hd, const guchar* msg, gssize msg_len, guchar* digest) {
    gcry_error_t err = 0;
    guint digest_size = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    gcry_md_hd_t hd_copy;
    err = gcry_md_copy(&hd_copy, hd);
    GCRYPT_CHECK(err)
        gcry_md_write(hd_copy, msg, msg_len);
    memcpy(digest, gcry_md_read(hd_copy, GCRY_MD_SHA256), digest_size);
    gcry_md_close(hd_copy);
    return err;
}

guchar* vmess_kdf(const guchar* key, guint key_len, guint num, ...) {

    HMACCreator* creator = hmac_creator_new(NULL,
        (const guchar*)kdfSaltConstVMessAEADKDF->str,
        kdfSaltConstVMessAEADKDF->len);
    va_list valist;
    va_start(valist, num);
    for (guint i = 0; i < num; i++) {
        const GString* path = va_arg(valist, const GString*);
        creator = hmac_creator_new(creator, (const guchar*)path->str, path->len);
    }
    va_end(valist);

    hmac_create(creator);

    guchar* digest = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    HMACDigester* digester = hmac_digester_new(creator);
    hmac_digest(digester, key, key_len, digest);

    hmac_creator_free(creator);
    hmac_digester_free(digester);

    return digest;
}

gcry_error_t
vmess_byte_decryption(VMessDecoder* decoder, const guchar* in, const gsize inl, guchar* out, gsize outl, const guchar* ad,
    gsize ad_len) {
    gcry_error_t err = 0;
    if (ad) {
        err = gcry_cipher_authenticate(decoder->evp, ad, ad_len);
        GCRYPT_CHECK(err)
    }
    guint tag_len;
    switch (decoder->cipher_suite->mode) {
    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_POLY1305:
        tag_len = 16;
        break;
    default:
        tag_len = -1;
        /* Unsupported encryption mode. */
        return gcry_error(GPG_ERR_NOT_IMPLEMENTED);
    }
    gsize ciphertext_len = inl - tag_len;
    err = gcry_cipher_decrypt(decoder->evp, out, outl, in, ciphertext_len);
    GCRYPT_CHECK(err)

    guchar* calc_tag = g_malloc(tag_len);
    err = gcry_cipher_final(decoder->evp);
    GCRYPT_CHECK(err)

    err = gcry_cipher_gettag(decoder->evp, calc_tag, tag_len);
    if (memcmp(calc_tag, in + ciphertext_len, tag_len) != 0)
        return gcry_error(GPG_ERR_DECRYPT_FAILED);
    g_free(calc_tag);
    return err;
}

///**
// * vmess_equal and vmess_hash are stolen from packet-tls-utils.c
// */
//gboolean vmess_equal(gconstpointer a, gconstpointer b) {
//    const GByteArray* val1;
//    const GByteArray* val2;
//    val1 = (const GByteArray*)a;
//    val2 = (const GByteArray*)b;
//
//    if (val1->len == val2->len &&
//        !memcmp(val1->data, val2->data, val2->len)) {
//        return 1;
//    }
//    return 0;
//};
//
//guint vmess_hash(gconstpointer v) {
//    const GByteArray* arr;
//    guint l, hash;
//    const guint* cur;
//    hash = 0;
//    arr = (const GByteArray*)v;
//
//    /*  id and id->data are mallocated in ssl_save_master_key().  As such 'data'
//     *  should be aligned for any kind of access (for example as a guint as
//     *  is done below).  The intermediate void* cast is to prevent "cast
//     *  increases required alignment of target type" warnings on CPUs (such
//     *  as SPARCs) that do not allow misaligned memory accesses.
//     */
//    cur = (const guint*)(void*)arr->data;
//
//    for (l = 4; (l < arr->len); l += 4, cur++)
//        hash = hash ^ (*cur);
//
//    return hash;
//}

void vmess_common_init(vmess_key_map_t* km)
{
    // Use wmem to manage memory, instead of using g_free.
    km->req_iv = g_hash_table_new(g_string_hash, g_string_equal);
    km->req_key = g_hash_table_new(g_string_hash, g_string_equal);
    km->data_iv = g_hash_table_new(g_string_hash, g_string_equal);
    km->data_key = g_hash_table_new(g_string_hash, g_string_equal);
    km->response_token = g_hash_table_new(g_string_hash, g_string_equal);
}

void vmess_init(void)
{
    /* Allocate memory for key map, refer to packet-tls.c for a more complex key map management.
     * Currently, the k/v of key map are all plain strings. Therefore, the built-in g_xxx
     * funtions should be enough:)
     */
    vmess_common_init(&vmess_key_map);
    vmess_debug_flush();
}

void vmess_common_clean(vmess_key_map_t* km)
{
    g_hash_table_destroy(km->data_iv);
    g_hash_table_destroy(km->data_key);
    g_hash_table_destroy(km->req_iv);
    g_hash_table_destroy(km->req_key);
    g_hash_table_destroy(km->response_token);
}

void vmess_cleanup(void)
{
    vmess_common_clean(&vmess_key_map);
    if (vmess_keylog_file) {
        fclose(vmess_keylog_file);
        vmess_keylog_file = NULL;
    }
}

void vmess_free(gpointer data)
{
    if (data == NULL)
        return;

    /* Note that the memory allocated by wmem_alloc should be freed
     * by wmem_free, instead of g_free.
     */
    wmem_free(wmem_file_scope(), data);
}

#ifdef VMESS_DECRYPT_DEBUG
void
vmess_debug_printf(const gchar* fmt, ...)
{
    va_list ap;

    if (!vmess_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(vmess_debug_file, fmt, ap);
    va_end(ap);
}

void
vmess_set_debug(const gchar* name) {
    static gint debug_file_must_be_closed;
    gint        use_stderr;

    use_stderr = name ? (strcmp(name, VMESS_DEBUG_USE_STDERR) == 0) : 0;

    if (debug_file_must_be_closed)
        fclose(vmess_debug_file);

    if (use_stderr)
        vmess_debug_file = stderr;
    else if (!name || (strcmp(name, "") == 0))
        vmess_debug_file = NULL;
    else
        vmess_debug_file = ws_fopen(name, "w");

    if (!use_stderr && vmess_debug_file)
        debug_file_must_be_closed = 1;
    else
        debug_file_must_be_closed = 0;

    vmess_debug_printf("Wireshark VMess debug log \n\n");
}

void
vmess_prefs_apply_cb(void) {
    vmess_set_debug(vmess_debug_file_name);
}

void
vmess_debug_flush(void)
{
    if (vmess_debug_file)
        fflush(vmess_debug_file);
}

void vmess_debug_print_hash_table(GHashTable* hash_table) {
    vmess_debug_printf("VMess Key Map size: %d\n", g_hash_table_size(hash_table));
    g_hash_table_foreach(hash_table, (GHFunc)vmess_debug_print_key_value, NULL);
}

void vmess_debug_print_key_value(gpointer key, gpointer value, gpointer user_data) {
    vmess_debug_printf("Key: %s, Value: %s\n", (char*)key, (char*)value);
}

#endif

gboolean from_hex(const char* in, GString* out, guint datalen) {
    if (datalen & 1) /* The datalen should never be odd */
        return FALSE;

    gsize i;

    for (i = 0; i < datalen; i += 2) {
        char a, b;
        a = ws_xton(in[i]), b = ws_xton(in[i + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        g_string_append_c(out, (guint8)(a << 4 | b));
    }
    return TRUE;
}

gboolean from_hex_raw(const char* in, gchar * out, guint datalen)
{
    if (datalen & 1) /* The datalen should never be odd */
        return FALSE;
    gsize i;

    for (i = 0; i < datalen; i += 2) {
        char a, b;
        a = ws_xton(in[i]), b = ws_xton(in[i + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        out[i / 2] = (guint8)(a << 4 | b);
    }
    out[datalen / 2] = '\0';
    return TRUE;
}

void
proto_register_vmess(void)
{
    module_t* vmess_module;

    /* Initialize key derive labels */
    /* TODO: Free the paths when the file is closed */
    kdfSaltConstAuthIDEncryptionKey = g_string_new_take("AES Auth ID Encryption");
    kdfSaltConstAEADRespHeaderLenKey = g_string_new_take("AEAD Resp Header Len Key");
    kdfSaltConstAEADRespHeaderLenIV = g_string_new_take("AEAD Resp Header Len IV");
    kdfSaltConstAEADRespHeaderPayloadKey = g_string_new_take("AEAD Resp Header Key");
    kdfSaltConstAEADRespHeaderPayloadIV = g_string_new_take("AEAD Resp Header IV");
    kdfSaltConstVMessAEADKDF = g_string_new_take("VMess AEAD KDF");
    kdfSaltConstVMessHeaderPayloadAEADKey = g_string_new_take("VMess Header AEAD Key");
    kdfSaltConstVMessHeaderPayloadAEADIV = g_string_new_take("VMess Header AEAD Nonce");
    kdfSaltConstVMessHeaderPayloadLengthAEADKey = g_string_new_take("VMess Header AEAD Key_Length");
    kdfSaltConstVMessHeaderPayloadLengthAEADIV = g_string_new_take("VMess Header AEAD Nonce_Length");

    static hf_register_info hf[] = {
        { &hf_vmess_request_auth,
            {"Auth", "vmess.request.auth",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_conn_nonce,
            {"Connection Nonce", "vmess.request.conn_nonce",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_length,
            {"Request Length", "vmess.request.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_opt,
            {"Options", "vmess.request.opt",
            FT_UINT8, BASE_HEX,
            NULL, OPT_MASK,
            NULL, HFILL }
        },
        { &hf_vmess_request_opt_res,
            {"Reserved", "vmess.request.opt.res",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset_vmess), OPT_RES,
            NULL, HFILL }
        },
        { &hf_vmess_request_opt_M,
            {"Meta Obfuscate", "vmess.request.opt.m",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset_vmess), OPT_M,
            NULL, HFILL }
        },
        { &hf_vmess_request_opt_R,
            {"Reuse", "vmess.request.opt.r",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset_vmess), OPT_R,
            NULL, HFILL }
        },
        { &hf_vmess_request_opt_S,
            {"Standard Form", "vmess.request.opt.s",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset_vmess), OPT_S,
            NULL, HFILL }
        },
        { &hf_vmess_request_P,
            {"Random Padding Length", "vmess.request.padding",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_enc,
            {"Encryption Method", "vmess.request.enc_method",
            FT_UINT8, BASE_HEX,
            VALS(encryption_method), 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_cmd,
            {"Command", "vmess.request.cmd",
            FT_UINT8, BASE_HEX,
            VALS(request_cmd), 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_port,
            {"Port", "vmess.request.port",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_request_addr_type,
            {"Address Type", "vmess.request.addr_type",
            FT_UINT16, BASE_HEX,
            VALS(request_addr_type), 0x0,
            NULL, HFILL }
        },
        /* TODO: Convert the base to human-friendly string */
        { &hf_vmess_request_addr,
            {"Address", "vmess.request.addr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_response_header,
            {"VMess Response Header", "vmess.response.header",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_payload_length,
            {"VMess Payload Length", "vmess.payload.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_msg_fragments,
            {"Reassembled VMess Message fragments", "vmess.msg.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_fragment,
            {"Message fragment", "vmess.msg.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_overlap,
            {"Message fragment overlap", "vmess.msg.fragment.overlap",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_overlap_conflicts,
            {"Message fragment overlapping with conflicting data",
            "vmess.msg.fragment.overlap.conflicts",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_multiple_tails,
            {"Message has multiple tail fragments",
            "vmess.msg.fragment.multiple_tails",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_too_long_fragment,
            {"Message fragment too long", "vmess.msg.fragment.too_long_fragment",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_error,
            {"Message defragmentation error", "vmess.msg.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_count,
            {"Message fragment count", "vmess.msg.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_in,
            {"Reassembled in", "vmess.msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_length,
            {"Reassembled length", "vmess.msg.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_body_segment,
            {"VMess body segment", "vmess.msg.body.segment",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_vmess,
        &ett_msg_fragment,
        &ett_msg_fragments,
        &ett_vmess_opt
    };

    proto_vmess = proto_register_protocol(
        "VMESS Protocol", /* name        */
        "VMESS",          /* short name  */
        "vmess"           /* filter_name */
    );

    proto_register_field_array(proto_vmess, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&proto_vmess_streaming_reassembly_table,
        &addresses_ports_reassembly_table_functions);

    vmess_handle = register_dissector("vmess", dissect_vmess, proto_vmess);

#ifdef VMESS_DECRYPT_DEBUG
    vmess_module = prefs_register_protocol(proto_vmess, vmess_prefs_apply_cb);
#else
    vmess_module = prefs_register_protocol(proto_vmess, NULL);
#endif // VMESS_DECRYPT_DEBUG

    prefs_register_filename_preference(vmess_module, "keylog_file", "Key log filename",
        "The path to the file which contains a list of secrets in the following format:\n"
        "\"<key-type> = <base64-encoded-key>\" (without quotes, leading spaces and spaces around '=' are ignored).\n"
        "<key-type> is one of: AUTH, REMOTE_STATIC_PUBLIC_KEY, "
        "LOCAL_EPHEMERAL_PRIVATE_KEY or PRESHARED_KEY.",
        &pref_keylog_file, FALSE);

    prefs_register_filename_preference(vmess_module, "debug_file", "VMess debug file",
        "Redirect VMess debug to the file specified. Leave empty to disable debugging "
        "or use \"" VMESS_DEBUG_USE_STDERR "\" to redirect output to stderr.",
        &vmess_debug_file_name, TRUE);


    register_init_routine(vmess_init);
    register_cleanup_routine(vmess_cleanup);

    vmess_decryption_supported = vmess_decrypt_init();
}

void
proto_reg_handoff_vmess(void)
{
    //vmess_handle = create_dissector_handle(dissect_vmess, proto_vmess);
    //vmess_request_handle = create_dissector_handle(dissect_vmess_request, proto_vmess);
#ifdef VMESS_DECRYPT_DEBUG
    vmess_set_debug(vmess_debug_file_name);
#endif
    tls_handle = find_dissector("tls");
    dissector_add_uint("tcp.port", VMESS_TCP_PORT, vmess_handle);
}

vmess_message_info_t* get_vmess_message(packet_info* pinfo, guint record_id)
{
    vmess_packet_info_t* packet = (vmess_packet_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_vmess, 0);
    if (packet == NULL)
        return NULL;

    for (vmess_message_info_t* msg = packet->messages; msg; msg = msg->next) {
        if (msg->id == record_id)
            return msg;
    }

    return NULL;
}

vmess_conv_t* get_vmess_conv(conversation_t* conversation, const int proto_vmess)
{
    vmess_conv_t* conv_data;

    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (conv_data != NULL)
        return conv_data;

    /* no previous VMess conversation info, initialize it. */
    conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
    conv_data->req_decrypted = FALSE;
    conv_data->data_decrypted = FALSE;
    conv_data->resp_decrypted = FALSE;
    conv_data->auth = NULL;
    conv_data->reassembly_info = streaming_reassembly_info_new();
    conv_data->count_reader = 0;
    conv_data->count_writer = 0;
    /* Defer the port and address initialization to dissect VMess Request */

    /* Add the conv_data to the conversation in this routine. */
    conversation_add_proto_data(conversation, proto_vmess, conv_data);
    return conv_data;
}

bool
gbytearray_eq(const GByteArray* arr_1, const GByteArray* arr_2) {
    if (arr_1 == NULL && arr_2 == NULL)
        return true;

    if (arr_1 == NULL || arr_2 == NULL)
        return false;

    if (arr_1->len != arr_2->len)
        return false;

    return memcmp(arr_1->data, arr_2->data, arr_1->len) == 0;
}

bool
char_array_eq(const char* arr_1, const char* arr_2, size_t len) {
    if (arr_1 == NULL && arr_2 == NULL)
        return true;

    if (arr_1 == NULL || arr_2 == NULL)
        return false;

    return memcmp(arr_1, arr_2, len) == 0;
}

gint
mem_search(const char* haystack, guint haystack_size, const char* needle, guint needle_size) {
    if (haystack == NULL || needle == NULL) {
        g_print("Warning: Either haystack or needle is NULL\n");
        return -1;
    }


    if (needle_size == 0) return 0; /* Empty needle matches the beginning of haystack */
    if (haystack_size < needle_size) return -1; /* Haystack is smaller than needle */

    guint limit = haystack_size - needle_size;

    for (guint i = 0; i <= limit; i++)
        if (memcmp(haystack + i, needle, needle_size) == 0)
            return (gint)i; /* Warning: Convert unsigned int to int */
    return -1;
}

gint
tvb_find_bytes(tvbuff_t* tvb, const gint offset, const gint max_length, const char* needle) {

    guint limit_bufsize = tvb_reported_length_remaining(tvb, offset);
    guint bufsize;
    if (max_length < 0)
        bufsize = limit_bufsize + 1; /* 1 for the terminating nul */
    else
        if ((guint)max_length < limit_bufsize)
            bufsize = (guint)max_length + 1;
        else {
            g_print("Warning: max_length is larger than the tvb remaining size, clip to the tvb remaining size.\n");
            bufsize = limit_bufsize + 1;
        }
    char* buffer = (char*)malloc(bufsize);
    tvb_get_raw_bytes_as_string(tvb, offset, buffer, bufsize);
    /* Strip the terminating nul for both buffer and needle */
    return mem_search(buffer, bufsize - 1, needle, 3);
}

gint
tvb_find_TLS_signiture(tvbuff_t* tvb) {
    gint min_pos = -1;

    for (gint i = 0; i < TLS_SIGNUM; i++) {
        gint pos = tvb_find_bytes(tvb, 0, -1, TLS_signiture[i]);
        if (pos >= 0)
            if (min_pos >= 0)
                min_pos = min_pos <= pos ? min_pos : pos;
            else
                min_pos = pos;
    }

    return min_pos;
}
