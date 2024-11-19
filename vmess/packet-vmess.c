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
static int hf_vmess_response_header;
static int hf_vmess_payload_length;

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


int dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Request");
    proto_item* ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    proto_tree* vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_request_auth, tvb, 0, 16, ENC_BIG_ENDIAN);

    vmess_conv_t* conv_data = (vmess_conv_t*)data;


    /* If the header packet is decrypted, try to perform decryption */
    if (!conv_data->req_decrypted) {

    }

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
    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conversation_add_proto_data(conversation, proto_vmess, conv_data);
        /* Comment: How a conv_data is initialized? */
        /* By using wmem_new0, all the memory allocated is set to 0. */
    }
    if (!conv_data->reassembly_info) {
        conv_data->reassembly_info = streaming_reassembly_info_new();
    }

    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Response");
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
    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conversation_add_proto_data(conversation, proto_vmess, conv_data);
    }
    if (!conv_data->reassembly_info) {
        conv_data->reassembly_info = streaming_reassembly_info_new();
    }

    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Data");
    ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_payload_length, tvb, 0, 2, ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_remaining(tvb, 2);

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
    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conv_data->auth = NULL;
        conversation_add_proto_data(conversation, proto_vmess, conv_data);
    }
    if (!conv_data->reassembly_info) {
        conv_data->reassembly_info = streaming_reassembly_info_new();
    }

    vmess_keylog_read();

    //const char* auth = "\xb0\xb2\x5c\xda\x68\x1c\x15\x53\x74\xb3\x5b\x5f\xcc\x3f\x81\xe7";
    //const char* auth = "\x43\xe7\xf4\x86\xc9\x36\xde\x80\xec\x3d\x0e\xbf\x82\x06\x5e\x8c";
    //const char* auth = "\xfc\xc1\x8b\x89\x42\xc6\x70\xfd\xcb\x17\xe3\xb0\x7f\x72\xf2\x7f";

    bool is_request = false;

    
    //if (tvb_reported_length(tvb) > 61) { /* Minimum VMess request length */
    //    gchar* tmp_auth = (gchar*)g_malloc((VMESS_AUTH_LENGTH + 1) * sizeof(gchar));
    //    tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, (VMESS_AUTH_LENGTH + 1));
    //    if (char_array_eq(auth, tmp_auth, VMESS_AUTH_LENGTH)) {
    //        if (!PINFO_FD_VISITED(pinfo) && !conv_data->auth) { 
    //            conv_data->auth = wmem_strndup(wmem_file_scope(), tmp_auth, VMESS_AUTH_LENGTH);
    //            g_free(tmp_auth);
    //        }
    //        is_request = true;
    //    }
    //}

    /* The request could be dissected only once, since it occupies exactly one packet. */
    if (tvb_reported_length(tvb) > 61) { /* Minimum VMess request length */
        gchar* tmp_auth = (gchar*)g_malloc((VMESS_AUTH_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, (VMESS_AUTH_LENGTH + 1));
        GByteArray* key = (GByteArray *)g_hash_table_lookup(vmess_key_map.header_key, tmp_auth);
        if (key) {
            if (!PINFO_FD_VISITED(pinfo) && !conv_data->auth) { 
                conv_data->auth = wmem_strndup(wmem_file_scope(), tmp_auth, VMESS_AUTH_LENGTH);
                g_free(tmp_auth);
            }
            is_request = true;
        }
    }

    if (is_request) {

        dissect_vmess_request(tvb, pinfo, tree, conv_data);

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

        /* Strip '\n' and '\r' chars from lines. */
        /*size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) { len -= 1; buf[len] = 0; }*/

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
        {"header_key", km->header_key},
        {"header_iv", km->header_iv},
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
        gchar* auth = wmem_alloc(wmem_file_scope(), VMESS_AUTH_LENGTH + 1);
        GByteArray* secret = wmem_new(wmem_file_scope(), GByteArray); /* We use byte array to store the hex-formed secrets. */
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
                from_hex_raw(hex_auth, auth, strlen(hex_auth));
                from_hex(hex_secret, secret, strlen(hex_secret));
                g_free(hex_auth);
                g_free(hex_secret);
                break;
            }
        }
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
    g_hash_table_remove_all(mk->header_iv);
    g_hash_table_remove_all(mk->header_key);
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

void vmess_common_init(vmess_key_map_t* km)
{
    // Use wmem to manage memory, instead of using g_free.
    km->data_iv = g_hash_table_new(g_str_hash, g_str_equal);
    km->data_key = g_hash_table_new(g_str_hash, g_str_equal);
    km->header_iv = g_hash_table_new(g_str_hash, g_str_equal);
    km->header_key = g_hash_table_new(g_str_hash, g_str_equal);
    km->response_token = g_hash_table_new(g_str_hash, g_str_equal);
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
    g_hash_table_destroy(km->header_iv);
    g_hash_table_destroy(km->header_key);
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

gboolean from_hex(const char* in, GByteArray* out, guint datalen) {
    if (datalen & 1) /* The datalen should never be odd */
        return FALSE;
    out->len = datalen / 2;
    out->data = (guchar*)wmem_alloc(wmem_file_scope(), datalen / 2);
    gsize i;

    for (i = 0; i < datalen; i += 2) {
        char a, b;
        a = ws_xton(in[i]), b = ws_xton(in[i + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        out->data[i / 2] = (guint8)(a << 4 | b);
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
    out[datalen / 2 + 1] = '\0';
    return TRUE;
}

void
proto_register_vmess(void)
{
    module_t* vmess_module;

    static hf_register_info hf[] = {
        { &hf_vmess_request_auth,
            {"VMess Request Auth", "vmess.request.auth",
            FT_BYTES, BASE_NONE,
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
        &ett_msg_fragments
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
