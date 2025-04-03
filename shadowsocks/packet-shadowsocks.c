/* packet-shadowsocks.c
 * Routines for Shadowsocks dissection
 * Copyright 2024, Guangwei Li <gol3vka@163.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LICENSE
 */

/*
 * Shadowsocks is a secure split proxy loosely based on SOCKS5.
 * <http://shadowsocks.org>
 */

/********** Logging Domain **********/
#define WS_LOG_DOMAIN "packet-shadowsocks"

#include "config.h"

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/wmem_scopes.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>

#ifdef _WIN32
    // Windows-specific headers and definitions
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #ifndef __MINGW32__
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #endif
#endif

#include "packet-shadowsocks.h"

/********** Protocol Handles **********/
static int proto_ss;

/********** Dissector Handles **********/
static dissector_handle_t ss_handle;

/********** Header Fields **********/
/* Shadowsocks */
/* Cipher Context */
static int hf_cipher_ctx;
static int hf_cipher_ctx_salt;
static int hf_cipher_ctx_skey;
static int hf_cipher_ctx_nonce;
static int hf_cipher_ctx_cipher;
static int hf_cipher_ctx_cipher_method;
static int hf_cipher_ctx_cipher_password;
static int hf_cipher_ctx_cipher_key;
static int hf_cipher_ctx_cipher_nonce_len;
static int hf_cipher_ctx_cipher_key_len;
static int hf_cipher_ctx_cipher_tag_len;
/* Salt */
static int hf_salt;
/* Relay Header */
static int hf_atyp;
static int hf_dst_addr_ipv4;
static int hf_dst_addr_domainname_len;
static int hf_dst_addr_domainname;
static int hf_dst_addr_ipv6;
static int hf_dst_port;
/* Reassembly Info */
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
static int hf_msg_reassembled_data;
static int hf_msg_body_segment;

static const value_string hf_cipher_ctx_cipher_method_vals[] = {
    {AEAD_CIPHER_AES128GCM, "aes-128-gcm"},
    {AEAD_CIPHER_AES192GCM, "aes-192-gcm"},
    {AEAD_CIPHER_AES256GCM, "aes-256-gcm"},
    {AEAD_CIPHER_CHACHA20POLY1305IETF, "chacha20-ietf-poly1305"},
#ifdef FS_HAVE_XCHACHA20IETF
    {AEAD_CIPHER_XCHACHA20POLY1305IETF, "xchacha20-ietf-poly1305"},
#endif
    {AEAD_CIPHER_NONE, NULL},
};
static const value_string hf_atyp_vals[] = {
    {RELAY_HEADER_ATYP_IPV4, "IPv4"},
    {RELAY_HEADER_ATYP_DOMAINNAME, "Domain Name"},
    {RELAY_HEADER_ATYP_IPV6, "IPv6"},
    {0, NULL},
};

/********** Subtree Pointers **********/
/* Shadowsocks */
static int ett_ss;
static int ett_cipher_ctx;
static int ett_cipher_ctx_cipher;
/* Reassembly Info */
static int ett_msg_fragment;
static int ett_msg_fragments;

/********** Fragment Items **********/
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
    &hf_msg_reassembled_data,
    "Shadowsocks Message fragments",
};

/********** Preferences **********/
static const char *pref_password = "";
static int pref_cipher = AEAD_CIPHER_AES256GCM;
static const enum_val_t pref_cipher_vals[] = {
    {"aes-128-gcm", "AEAD_AES_128_GCM", AEAD_CIPHER_AES128GCM},
    {"aes-192-gcm", "AEAD_AES_192_GCM", AEAD_CIPHER_AES192GCM},
    {"aes-256-gcm", "AEAD_AES_256_GCM", AEAD_CIPHER_AES256GCM},
    {"chacha20-ietf-poly1305", "AEAD_CHACHA20_POLY1305", AEAD_CIPHER_CHACHA20POLY1305IETF},
#ifdef FS_HAVE_XCHACHA20IETF
    {"xchacha20-ietf-poly1305", "AEAD_XCHACHA20_POLY1305", AEAD_CIPHER_XCHACHA20POLY1305IETF},
#endif
    {NULL, NULL, AEAD_CIPHER_NONE},
};

/********** Global Variables **********/
/* Crypto */
static const char *supported_aead_ciphers[AEAD_CIPHER_NUM] = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
#ifdef FS_HAVE_XCHACHA20IETF
    "xchacha20-ietf-poly1305"
#endif
};
static const int supported_aead_ciphers_nonce_size[AEAD_CIPHER_NUM] = {
    12, 12, 12, 12,
#ifdef FS_HAVE_XCHACHA20IETF
    24
#endif
};
static const int supported_aead_ciphers_key_size[AEAD_CIPHER_NUM] = {
    16, 24, 32, 32,
#ifdef FS_HAVE_XCHACHA20IETF
    32
#endif
};
static const int supported_aead_ciphers_tag_size[AEAD_CIPHER_NUM] = {
    16, 16, 16, 16,
#ifdef FS_HAVE_XCHACHA20IETF
    16
#endif
};

static reassembly_table proto_ss_streaming_reassembly_table;
ss_crypto_t *ss_crypto;
// ss_buffer_t *ss_buf;

int dissect_ss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &(pinfo->num), sizeof(uint32_t));
    ss_pkt_type_t tmp_pkt_type;
    ss_pkt_type_t *cur_pkt_type;
    proto_item *ti, *cipher_ctx_ti, *cipher_ctx_cipher_ti;
    proto_tree *ss_tree, *cipher_ctx_tree, *cipher_ctx_cipher_tree;
    bool is_request = true;

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Request/Response Detection ***/
    if (conv_data->server_addr->data == NULL)
    { /* Look for salt (the first valid packet) to determine the server address */
        tmp_pkt_type = detect_ss_pkt_type(tvb, pinfo->num, conv_data, true);
        if (tmp_pkt_type == PKT_TYPE_SALT || tmp_pkt_type == PKT_TYPE_SALT_REASSEMBLY)
            copy_address(conv_data->server_addr, &pinfo->dst);
    }
    else
        is_request = (cmp_address(&pinfo->dst, conv_data->server_addr) == 0);

    /*** Type Detection ***/
    tmp_pkt_type = detect_ss_pkt_type(tvb, pinfo->num, conv_data, is_request);
    cur_pkt_type = (ss_pkt_type_t *)wmem_memdup(wmem_file_scope(), &tmp_pkt_type, sizeof(ss_pkt_type_t));
    wmem_map_insert(conv_data->pkt_type_map, pinfo_num_copy, cur_pkt_type);

    /*** Protocol Tree ***/
    ti = proto_tree_add_item(tree, proto_ss, tvb, 0, -1, ENC_NA);
    ss_tree = proto_item_add_subtree(ti, ett_ss);
    /* Cipher Context */
    cipher_ctx_ti = proto_tree_add_item(ss_tree, hf_cipher_ctx, tvb, 0, 0, ENC_NA);
    proto_item_set_text(cipher_ctx_ti, "Cipher Context");
    cipher_ctx_tree = proto_item_add_subtree(cipher_ctx_ti, ett_cipher_ctx);
    /* Cipher */
    cipher_ctx_cipher_ti = proto_tree_add_item(cipher_ctx_tree, hf_cipher_ctx_cipher, tvb, 0, 0, ENC_NA);
    proto_item_set_text(cipher_ctx_cipher_ti, "Cipher");
    cipher_ctx_cipher_tree = proto_item_add_subtree(cipher_ctx_cipher_ti, ett_cipher_ctx_cipher);
    proto_tree_add_int(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_method, tvb, 0, 0, ss_crypto->cipher->method);
    proto_tree_add_string(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_password, tvb, 0, 0, pref_password);
    proto_tree_add_bytes_with_length(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_key, tvb, 0, 0, ss_crypto->cipher->key, ss_crypto->cipher->key_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_nonce_len, tvb, 0, 0, ss_crypto->cipher->nonce_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_key_len, tvb, 0, 0, ss_crypto->cipher->key_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_tag_len, tvb, 0, 0, ss_crypto->cipher->tag_len);

    /*** Column Data & Dissection ***/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Shadowsocks");
    col_clear(pinfo->cinfo, COL_INFO);
    switch (*cur_pkt_type)
    {
    case PKT_TYPE_UNKNOWN:
        col_set_str(pinfo->cinfo, COL_INFO, "[Unknown]");
        break;
    case PKT_TYPE_ERROR:
        col_set_str(pinfo->cinfo, COL_INFO, "[Error]");
        break;
    case PKT_TYPE_UNSET:
        col_set_str(pinfo->cinfo, COL_INFO, "[Unset]");
        break;
    case PKT_TYPE_SALT:
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt]");
        dissect_ss_salt(tvb, pinfo, ss_tree, data);
        break;
    case PKT_TYPE_RELAY_HEADER:
        col_set_str(pinfo->cinfo, COL_INFO, "[Relay Header]");
        tvbuff_t *decrypted_tvb = dissect_ss_encrypted_data(tvb, pinfo, cipher_ctx_tree, data, conv_data, is_request, false);
        dissect_ss_relay_header(decrypted_tvb, pinfo, ss_tree, data);
        break;
    case PKT_TYPE_STREAM_DATA:
        col_set_str(pinfo->cinfo, COL_INFO, "[Stream Data]");
        decrypted_tvb = dissect_ss_encrypted_data(tvb, pinfo, cipher_ctx_tree, data, conv_data, is_request, false);
        dissect_ss_stream_data(decrypted_tvb, pinfo, tree, ss_tree, conv_data);
        break;
    case PKT_TYPE_SALT_WITH_STREAM_DATA:
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt & Stream Data]");
        tvb_memcpy(tvb, conv_data->response_cipher_ctx->salt, 0, ss_crypto->cipher->key_len);
        tvbuff_t *salt_tvb = tvb_new_subset_length(tvb, 0, ss_crypto->cipher->key_len);
        dissect_ss_salt(salt_tvb, pinfo, ss_tree, data);
        tvbuff_t *stream_data_tvb = tvb_new_subset_remaining(tvb, ss_crypto->cipher->key_len);
        decrypted_tvb = dissect_ss_encrypted_data(stream_data_tvb, pinfo, cipher_ctx_tree, data, conv_data, is_request, false);
        dissect_ss_stream_data(decrypted_tvb, pinfo, tree, ss_tree, conv_data);
        break;
    case PKT_TYPE_SALT_NEED_MORE:
        // NOTE: NO TEST CASE
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt (Need More)]");
        tcp_dissect_pdus(tvb, pinfo, ss_tree, true, 0,
                         get_ss_salt_pdu_len,
                         dissect_ss_pdu, NULL);
        break;
    case PKT_TYPE_RELAY_HEADER_NEED_MORE:
        // NOTE: NO TEST CASE
        col_set_str(pinfo->cinfo, COL_INFO, "[Relay Header (Need More)]");
        tcp_dissect_pdus(tvb, pinfo, ss_tree, true,
                         CHUNK_SIZE_LEN + ss_crypto->cipher->tag_len,
                         get_ss_stream_data_pdu_len,
                         dissect_ss_pdu, NULL);
        break;
    case PKT_TYPE_SALT_WITH_STREAM_DATA_NEED_MORE:
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt & Stream Data (Need More)]");
        tcp_dissect_pdus(tvb, pinfo, ss_tree, true,
                         ss_crypto->cipher->key_len + CHUNK_SIZE_LEN + ss_crypto->cipher->tag_len,
                         get_ss_salt_with_stream_data_pdu_len,
                         dissect_ss_pdu, NULL);
        break;
    case PKT_TYPE_STREAM_DATA_NEED_MORE:
        col_set_str(pinfo->cinfo, COL_INFO, "[Stream Data (Need More)]");
        tcp_dissect_pdus(tvb, pinfo, ss_tree, true,
                         CHUNK_SIZE_LEN + ss_crypto->cipher->tag_len,
                         get_ss_stream_data_pdu_len,
                         dissect_ss_pdu, NULL);
        break;
    case PKT_TYPE_SALT_REASSEMBLY:
        // NOTE: NO TEST CASE
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt (Reassembly)]");
        dissect_ss_salt(tvb, pinfo, ss_tree, data);
        break;
    case PKT_TYPE_RELAY_HEADER_REASSEMBLY:
        // NOTE: NO TEST CASE
        col_set_str(pinfo->cinfo, COL_INFO, "[Relay Header (Reassembly)]");
        decrypted_tvb = dissect_ss_encrypted_data(tvb, pinfo, cipher_ctx_tree, data, conv_data, is_request, true);
        dissect_ss_relay_header(decrypted_tvb, pinfo, ss_tree, data);
        break;
    case PKT_TYPE_SALT_WITH_STREAM_DATA_REASSEMBLY:
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt & Stream Data (Reassembly)]");
        tvb_memcpy(tvb, conv_data->response_cipher_ctx->salt, 0, ss_crypto->cipher->key_len);
        salt_tvb = tvb_new_subset_length(tvb, 0, ss_crypto->cipher->key_len);
        dissect_ss_salt(salt_tvb, pinfo, ss_tree, data);
        stream_data_tvb = tvb_new_subset_remaining(tvb, ss_crypto->cipher->key_len);
        decrypted_tvb = dissect_ss_encrypted_data(stream_data_tvb, pinfo, cipher_ctx_tree, data, conv_data, is_request, true);
        dissect_ss_stream_data(decrypted_tvb, pinfo, tree, ss_tree, conv_data);
        break;
    case PKT_TYPE_STREAM_DATA_REASSEMBLY:
        col_set_str(pinfo->cinfo, COL_INFO, "[Stream Data (Reassembly)]");
        decrypted_tvb = dissect_ss_encrypted_data(tvb, pinfo, cipher_ctx_tree, data, conv_data, is_request, true);
        dissect_ss_stream_data(decrypted_tvb, pinfo, tree, ss_tree, conv_data);
        break;
    default:
        ws_critical("[%u] Unknown packet type: %d", pinfo->num, *cur_pkt_type);
        break;
    }

    return tvb_captured_length(tvb);
}

/********** Dissectors **********/
ss_pkt_type_t detect_ss_pkt_type(tvbuff_t *tvb, uint32_t pinfo_num, ss_conv_data_t *conv_data, bool is_request)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &pinfo_num, sizeof(uint32_t));
    uint32_t tvb_len = tvb_captured_length(tvb);
    ss_pkt_type_t *cur_pkt_type, prev_pkt_type;
    uint8_t *cur_nonce = NULL;
    uint8_t *plaintext = NULL;
    size_t *plen = NULL;
    wmem_map_t *nonce_map = conv_data->nonce_map;
    wmem_map_t *pkt_type_map = conv_data->pkt_type_map;
    ss_cipher_ctx_t *cipher_ctx = is_request ? conv_data->request_cipher_ctx : conv_data->response_cipher_ctx;
    wmem_list_t *pkt_order_list = is_request ? conv_data->request_pkt_order_list : conv_data->response_pkt_order_list;
    size_t salt_len = cipher_ctx->cipher->key_len;

    /* Try to get the packet type from the hash table */
    cur_pkt_type = (ss_pkt_type_t *)wmem_map_lookup(pkt_type_map, pinfo_num_copy);
    if (cur_pkt_type != NULL)
        return *cur_pkt_type;

    /* Get previous packet type */
    // NOTE: Don't use `wmem_list_find` for value comparison
    wmem_list_frame_t *cur_list_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    if (cur_list_frame == NULL) // The first occurrence of the packet
        wmem_list_append(pkt_order_list, pinfo_num_copy);
    cur_list_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    prev_pkt_type = get_prev_pkt_type(cur_list_frame, pkt_type_map);

    if (is_request) /* Request */
        switch (prev_pkt_type)
        {
        case PKT_TYPE_UNKNOWN:
        case PKT_TYPE_ERROR:
        case PKT_TYPE_UNSET:
            /* Check if it is [SALT] */
            if (tvb_len > salt_len)
            { /* Unable to identify */
                // NOTE: This may happen when the capture is incomplete, i.e., the salt is not captured. The following packets will not be decrypted.
                ws_message("[%u] Unable to identify the packet type", pinfo_num);
                return PKT_TYPE_UNKNOWN;
            }
            if (tvb_len < salt_len)
            { /* Might be fragmented */
                // NOTE: Haven't seen this case yet
                ws_message("[%u] Fragmented salt", pinfo_num);
                return PKT_TYPE_SALT_NEED_MORE;
            }
            // NOTE: It cannot be distinguished from the case where the first packet is not salt, but happens to have the same length as the salt.
            tvb_memcpy(tvb, cipher_ctx->salt, 0, salt_len);
            err = ss_aead_cipher_ctx_set_key(cipher_ctx);
            if (err)
            {
                ws_critical("[%u] Failed to set cipher key: %s", pinfo_num, gcry_strerror(err));
                memset(cipher_ctx->salt, 0, salt_len);
                return PKT_TYPE_ERROR;
            }
            /* [SALT] */
            cipher_ctx->init = 1;
            return PKT_TYPE_SALT;
            break;
        case PKT_TYPE_SALT:
        case PKT_TYPE_SALT_REASSEMBLY:
            /* Check if it is [RELAY HEADER] */
            get_nonce(*pinfo_num_copy, &cur_nonce, pkt_order_list, nonce_map, false);
            /* Decryption */
            int ret = ss_aead_decrypt(cipher_ctx,
                                      &plaintext,
                                      (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                                      cur_nonce,
                                      &plen,
                                      (size_t)tvb_len);
            if (ret == RET_CRYPTO_ERROR)
                return PKT_TYPE_ERROR;
            if (ret == RET_CRYPTO_NEED_MORE)
                return PKT_TYPE_RELAY_HEADER_NEED_MORE;
            /* Check the plaintext to determine if it is [RELAY HEADER] */
            int offset = 0;
            char atyp = plaintext[offset++];
            char host[255];
            switch (atyp & ADDRTYPE_MASK)
            {
            case RELAY_HEADER_ATYP_IPV4:
                /* IPv4: 4 bytes */
                size_t in_addr_len = sizeof(struct in_addr);
                if (*plen > in_addr_len + 3)
                {
                    ws_critical("[%u] Invalid length for relay header with IPv4 address: %ln", pinfo_num, plen);
                    return PKT_TYPE_ERROR;
                }
                if (*plen < in_addr_len + 3)
                { /* Might be fragmented */
                    ws_message("[%u] Fragmented relay header with IPv4 address", pinfo_num);
                    return PKT_TYPE_RELAY_HEADER_NEED_MORE;
                }
                break;
            case RELAY_HEADER_ATYP_DOMAINNAME:
                /* Domain name: 1 byte length + domain name */
                uint8_t name_len = *(uint8_t *)(plaintext + offset);
                if (*plen > (size_t)(name_len + 4))
                {
                    ws_critical("[%u] Invalid length for relay header with domain name: %ln", pinfo_num, plen);
                    return PKT_TYPE_ERROR;
                }
                if (*plen < (size_t)(name_len + 4))
                { /* Might be fragmented */
                    ws_message("[%u] Fragmented relay header with domain name", pinfo_num);
                    return PKT_TYPE_RELAY_HEADER_NEED_MORE;
                }
                memcpy(host, plaintext + offset + 1, name_len);
                if (!validate_hostname(host, name_len))
                {
                    ws_critical("[%u] Invalid domain name: %s", pinfo_num, host);
                    return PKT_TYPE_ERROR;
                }
                break;
            case RELAY_HEADER_ATYP_IPV6:
                /* IPv6: 16 bytes */
                size_t in6_addr_len = sizeof(struct in6_addr);
                if (*plen > in6_addr_len + 3)
                {
                    ws_critical("[%u] Invalid length for relay header with IPv6 address: %ln", pinfo_num, plen);
                    return PKT_TYPE_ERROR;
                }
                if (*plen < in6_addr_len + 3)
                { /* Might be fragmented */
                    ws_message("[%u] Fragmented relay header with IPv6 address", pinfo_num);
                    return PKT_TYPE_RELAY_HEADER_NEED_MORE;
                }
                break;
            default:
                ws_critical("[%u] Invalid ATYP value: %d", pinfo_num, atyp);
                return PKT_TYPE_ERROR;
                break;
            }
            /* [RELAY HEADER] */
            return PKT_TYPE_RELAY_HEADER;
            break;
        case PKT_TYPE_RELAY_HEADER:
        case PKT_TYPE_RELAY_HEADER_REASSEMBLY:
        case PKT_TYPE_STREAM_DATA:
        case PKT_TYPE_STREAM_DATA_REASSEMBLY:
            /* Check if it is [STREAM DATA] */
            get_nonce(*pinfo_num_copy, &cur_nonce, pkt_order_list, nonce_map, false);
            /* Decryption */
            ret = ss_aead_decrypt(cipher_ctx,
                                  &plaintext,
                                  (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                                  cur_nonce,
                                  &plen,
                                  (size_t)tvb_len);
            if (ret == RET_CRYPTO_ERROR)
                return PKT_TYPE_ERROR;
            if (ret == RET_CRYPTO_NEED_MORE)
                return PKT_TYPE_STREAM_DATA_NEED_MORE;
            /* [STREAM DATA] */
            return PKT_TYPE_STREAM_DATA;
            break;
        case PKT_TYPE_SALT_NEED_MORE:
            return PKT_TYPE_SALT_REASSEMBLY;
            break;
        case PKT_TYPE_RELAY_HEADER_NEED_MORE:
            return PKT_TYPE_RELAY_HEADER_REASSEMBLY;
            break;
        case PKT_TYPE_STREAM_DATA_NEED_MORE:
            return PKT_TYPE_STREAM_DATA_REASSEMBLY;
            break;
        default:
            ws_critical("[%u] Unknown previous packet type for request: %d", pinfo_num, prev_pkt_type);
            return PKT_TYPE_UNKNOWN;
            break;
        }
    else /* Response */
        switch (prev_pkt_type)
        {
        case PKT_TYPE_UNKNOWN:
        case PKT_TYPE_ERROR:
        case PKT_TYPE_UNSET:
            /* Check if it is [SALT & STREAM DATA] */
            if (tvb_len < salt_len + 2 * cipher_ctx->cipher->tag_len + CHUNK_SIZE_LEN)
            { /* Might be fragmented */
                ws_message("[%u] Fragmented salt with stream data", pinfo_num);
                return PKT_TYPE_SALT_WITH_STREAM_DATA_NEED_MORE;
            }
            /* Check the salt part */
            tvb_memcpy(tvb, cipher_ctx->salt, 0, salt_len);
            err = ss_aead_cipher_ctx_set_key(cipher_ctx);
            if (err)
            {
                ws_critical("[%u] Failed to set cipher key: %s", pinfo_num, gcry_strerror(err));
                memset(cipher_ctx->salt, 0, salt_len);
                return PKT_TYPE_ERROR;
            }
            /* Check the stream data part */
            get_nonce(*pinfo_num_copy, &cur_nonce, pkt_order_list, nonce_map, false);
            /* Decryption */
            int ret = ss_aead_decrypt(cipher_ctx,
                                      &plaintext,
                                      (uint8_t *)tvb_get_ptr(tvb, salt_len, tvb_len - salt_len),
                                      cur_nonce,
                                      &plen,
                                      (size_t)(tvb_len - salt_len));
            if (ret == RET_CRYPTO_ERROR)
                return PKT_TYPE_ERROR;
            if (ret == RET_CRYPTO_NEED_MORE)
                return PKT_TYPE_SALT_WITH_STREAM_DATA_NEED_MORE;
            /* [SALT & STREAM DATA] */
            cipher_ctx->init = 1;
            return PKT_TYPE_SALT_WITH_STREAM_DATA;
            break;
        case PKT_TYPE_SALT_WITH_STREAM_DATA:
        case PKT_TYPE_SALT_WITH_STREAM_DATA_REASSEMBLY:
        case PKT_TYPE_STREAM_DATA:
        case PKT_TYPE_STREAM_DATA_REASSEMBLY:
            /* Check if it is [STREAM DATA] */
            get_nonce(*pinfo_num_copy, &cur_nonce, pkt_order_list, nonce_map, false);
            /* Decryption */
            ret = ss_aead_decrypt(cipher_ctx,
                                  &plaintext,
                                  (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                                  cur_nonce,
                                  &plen,
                                  (size_t)tvb_len);
            if (ret == RET_CRYPTO_ERROR)
                return PKT_TYPE_ERROR;
            if (ret == RET_CRYPTO_NEED_MORE)
                return PKT_TYPE_STREAM_DATA_NEED_MORE;
            /* [STREAM DATA] */
            return PKT_TYPE_STREAM_DATA;
            break;
        case PKT_TYPE_SALT_WITH_STREAM_DATA_NEED_MORE:
            return PKT_TYPE_SALT_WITH_STREAM_DATA_REASSEMBLY;
            break;
        case PKT_TYPE_STREAM_DATA_NEED_MORE:
            return PKT_TYPE_STREAM_DATA_REASSEMBLY;
            break;
        default:
            ws_critical("[%u] Unknown previous packet type for response: %d", pinfo_num, prev_pkt_type);
            return PKT_TYPE_UNKNOWN;
            break;
        }
}

/**
 * @brief An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey (client -> server).
 *  Structure:
 *  +----------+
 *  |   Salt   |
 *  +----------+
 *  | 16/24/32 |
 *  +----------+
 */
int dissect_ss_salt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /*** Protocol Tree ***/
    proto_tree_add_item(tree, hf_salt, tvb, 0, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

/**
 * @brief A relay header is typically sent after the salt by the client to the server.
 *  It contains the destination address and port that the client wants to connect to.
 *  Structure (decrypted):
 *  +------+----------+----------+
 *  | ATYP | DST.ADDR | DST.PORT |
 *  +------+----------+----------+
 *  |  1   | Variable |    2     |
 *  +------+----------+----------+
 *  ATYP: address type of following address
 *      - 0x01: IP V4 address. The DST.ADDR is a version-4 IP address, with a length of 4 octets
 *      - 0x03: DOMAINNAME. The address field contains a fully-qualified domain name.
 *          The first octet of the address field contains the number of octets of name that follow,
 *          there is no terminating NUL octet.
 *      - 0x04: IP V6 address. The DST.ADDR is a version-6 IP address, with a length of 16 octets
 *  DST.ADDR: desired destination address
 *  DST.PORT: desired destination port in network octet order
 */
int dissect_ss_relay_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    uint8_t atyp;
    int host_len;

    /*** Protocol Tree ***/
    atyp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_atyp, tvb, offset++, 1, ENC_BIG_ENDIAN);
    switch (atyp & ADDRTYPE_MASK)
    {
    case RELAY_HEADER_ATYP_IPV4:
        ws_in4_addr in4_addr = tvb_get_ipv4(tvb, offset);
        host_len = sizeof(struct in_addr);
        proto_tree_add_ipv4(tree, hf_dst_addr_ipv4, tvb, offset, host_len, in4_addr);
        break;
    case RELAY_HEADER_ATYP_DOMAINNAME:
        host_len = (int)tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_dst_addr_domainname_len, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_dst_addr_domainname, tvb, offset, host_len, ENC_ASCII);
        break;
    case RELAY_HEADER_ATYP_IPV6:
        ws_in6_addr *in6_addr = wmem_new0(wmem_file_scope(), ws_in6_addr);
        tvb_get_ipv6(tvb, offset, in6_addr);
        host_len = sizeof(struct in6_addr);
        proto_tree_add_ipv6(tree, hf_dst_addr_ipv6, tvb, offset, host_len, in6_addr);
        break;
    default:
        // TODO: expert item
        ws_critical("[%u] Invalid ATYP value: %d", pinfo->num, atyp);
        return -1;
    }
    offset += host_len;
    proto_tree_add_item(tree, hf_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

int dissect_ss_stream_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ss_tree, ss_conv_data_t *conv_data)
{
    /* Call upper dissectors */
    dissector_handle_t tls_handle = find_dissector("tls");
    reassemble_streaming_data_and_call_subdissector(tvb, pinfo, 0,
                                                    tvb_captured_length_remaining(tvb, 0),
                                                    ss_tree, tree,
                                                    proto_ss_streaming_reassembly_table,
                                                    conv_data->reassembly_info,
                                                    get_virtual_frame_num64(tvb, pinfo, 0),
                                                    tls_handle,
                                                    proto_tree_get_parent_tree(tree),
                                                    NULL,
                                                    "Shadowsocks",
                                                    &msg_frag_items, hf_msg_body_segment);
    dissector_handle_t http_handle = find_dissector("http");
    call_dissector(http_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/**
 * @brief Decrypt the shadowsocks data and return the decrypted tvb for further dissection
 * @param reassembly_flag `ture` if the packet is reassembled, `false` otherwise
 * @return The decrypted tvb
 */
tvbuff_t *dissect_ss_encrypted_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, ss_conv_data_t *conv_data, bool is_request, bool reassembly_flag)
{
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &(pinfo->num), sizeof(uint32_t));
    uint32_t tvb_len = tvb_captured_length(tvb);
    ss_cipher_ctx_t *cipher_ctx = is_request ? conv_data->request_cipher_ctx : conv_data->response_cipher_ctx;
    uint8_t *cur_nonce = NULL;
    uint8_t *plaintext = NULL;
    size_t *plen = NULL;
    tvbuff_t *decrypted_tvb;

    /*** Nonce ***/
    if (is_request)
        get_nonce(*pinfo_num_copy, &cur_nonce, conv_data->request_pkt_order_list, conv_data->nonce_map, reassembly_flag);
    else
        get_nonce(*pinfo_num_copy, &cur_nonce, conv_data->response_pkt_order_list, conv_data->nonce_map, reassembly_flag);

    /*** Protocol Tree ***/
    proto_tree_add_bytes_with_length(tree, hf_cipher_ctx_salt, tvb, 0, 0, cipher_ctx->salt, cipher_ctx->cipher->key_len);
    proto_tree_add_bytes_with_length(tree, hf_cipher_ctx_skey, tvb, 0, 0, cipher_ctx->skey, cipher_ctx->cipher->key_len);
    proto_tree_add_bytes_with_length(tree, hf_cipher_ctx_nonce, tvb, 0, 0, cur_nonce, cipher_ctx->cipher->nonce_len);

    /*** Decryption ***/
    int ret = ss_aead_decrypt(cipher_ctx,
                              &plaintext,
                              (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                              cur_nonce,
                              &plen,
                              (size_t)tvb_len);
    if (ret != RET_OK)
    { /* Set the packet type to [ERROR] */
        ws_critical("[%u] Failed to decrypt", pinfo->num);
        ss_pkt_type_t *tmp_pkt_type = wmem_map_lookup(conv_data->pkt_type_map, pinfo_num_copy);
        *tmp_pkt_type = PKT_TYPE_ERROR;
        return tvb_new_child_real_data(tvb, NULL, 0, 0);
    }

    /*** New Tab ***/
    decrypted_tvb = tvb_new_child_real_data(tvb, plaintext, *plen, *plen);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Shadowsocks Data");
    return decrypted_tvb;
}

int dissect_ss_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    return tvb_captured_length(tvb);
}

unsigned get_ss_salt_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb _U_, int offset _U_, void *data _U_)
{
    /* Cast to unsigned */
    // NOTE: The salt length is fixed
    return (unsigned)ss_crypto->cipher->key_len;
}

unsigned get_ss_stream_data_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *cur_nonce = NULL;
    size_t nlen = ss_crypto->cipher->nonce_len;
    size_t tlen = ss_crypto->cipher->tag_len;
    uint8_t *len_buf = (uint8_t *)wmem_alloc0(wmem_file_scope(), CHUNK_SIZE_LEN + tlen);
    uint16_t plen;

    /*** Conversation & Request/Response Detection ***/
    conversation_t *conversation = find_or_create_conversation(pinfo);
    ss_conv_data_t *conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);
    if (conv_data->server_addr->data == NULL)
    { /* Should not happen */
        ws_critical("[%u] Server address is NULL", pinfo->num);
        return -1;
    }
    bool is_request = (cmp_address(&pinfo->dst, conv_data->server_addr) == 0);
    ss_cipher_ctx_t *cipher_ctx = is_request ? conv_data->request_cipher_ctx : conv_data->response_cipher_ctx;
    wmem_list_t *pkt_order_list = is_request ? conv_data->request_pkt_order_list : conv_data->response_pkt_order_list;
    wmem_map_t *nonce_map = conv_data->nonce_map;

    /*** Nonce ***/
    get_nonce(pinfo->num, &cur_nonce, pkt_order_list, nonce_map, false);

    /* Decrypt Length */
    if (tvb_captured_length(tvb) <= 2 * tlen + CHUNK_SIZE_LEN)
    {
        ws_critical("[%u] Not enough data to decrypt `plen`", pinfo->num);
        return 0;
    }
    err = gcry_cipher_setiv(cipher_ctx->cipher->hd, cur_nonce, nlen);
    if (err)
    {
        ws_critical("[%u] Failed to set IV: %s", pinfo->num, gcry_strerror(err));
        return -1;
    }
    // NOTE: The `outsize` should always be expected length + tag length
    err = gcry_cipher_decrypt(cipher_ctx->cipher->hd, len_buf, CHUNK_SIZE_LEN + tlen, tvb_get_ptr(tvb, 0, CHUNK_SIZE_LEN + tlen), CHUNK_SIZE_LEN + tlen);
    if (err)
    {
        ws_critical("[%u] Failed to decrypt length: %s", pinfo->num, gcry_strerror(err));
        return -1;
    }

    plen = load16_be(len_buf);
    wmem_free(wmem_file_scope(), len_buf);
    plen = plen & CHUNK_SIZE_MASK;

    if (plen == 0)
    {
        ws_critical("[%u] Invalid message length decoded: %d", pinfo->num, plen);
        return -1;
    }

    /* Cast to unsigned */
    // NOTE: encrypted payload length(2) | length tag(tlen) | encrypted payload(plen) | payload tag(tlen)
    return (unsigned)(CHUNK_SIZE_LEN + tlen + plen + tlen);
}

unsigned get_ss_salt_with_stream_data_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *cur_nonce = NULL;
    size_t slen = ss_crypto->cipher->key_len;
    size_t nlen = ss_crypto->cipher->nonce_len;
    size_t tlen = ss_crypto->cipher->tag_len;
    uint8_t *len_buf = (uint8_t *)wmem_alloc0(wmem_file_scope(), CHUNK_SIZE_LEN + tlen);
    uint16_t plen;

    /*** Conversation & Request/Response Detection ***/
    conversation_t *conversation = find_or_create_conversation(pinfo);
    ss_conv_data_t *conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);
    if (conv_data->server_addr->data == NULL)
    { /* Should not happen */
        ws_critical("[%u] Server address is NULL", pinfo->num);
        return -1;
    }
    bool is_request = (cmp_address(&pinfo->dst, conv_data->server_addr) == 0);
    ss_cipher_ctx_t *cipher_ctx = is_request ? conv_data->request_cipher_ctx : conv_data->response_cipher_ctx;
    wmem_list_t *pkt_order_list = is_request ? conv_data->request_pkt_order_list : conv_data->response_pkt_order_list;
    wmem_map_t *nonce_map = conv_data->nonce_map;

    /*** Nonce ***/
    get_nonce(pinfo->num, &cur_nonce, pkt_order_list, nonce_map, false);

    /* Decrypt Length */
    if (tvb_captured_length(tvb) <= slen + 2 * tlen + CHUNK_SIZE_LEN)
    {
        ws_critical("[%u] Not enough data to decrypt `plen`", pinfo->num);
        return 0;
    }
    err = gcry_cipher_setiv(cipher_ctx->cipher->hd, cur_nonce, nlen);
    if (err)
    {
        ws_critical("[%u] Failed to set IV: %s", pinfo->num, gcry_strerror(err));
        return -1;
    }
    // NOTE: The `outsize` should always be expected length + tag length
    err = gcry_cipher_decrypt(cipher_ctx->cipher->hd, len_buf, CHUNK_SIZE_LEN + tlen, tvb_get_ptr(tvb, slen, CHUNK_SIZE_LEN + tlen), CHUNK_SIZE_LEN + tlen);
    if (err)
    {
        ws_critical("[%u] Failed to decrypt length: %s", pinfo->num, gcry_strerror(err));
        return -1;
    }

    plen = load16_be(len_buf);
    wmem_free(wmem_file_scope(), len_buf);
    plen = plen & CHUNK_SIZE_MASK;

    if (plen == 0)
    {
        ws_critical("[%u] Invalid message length decoded: %d", pinfo->num, plen);
        return -1;
    }

    /* Cast to unsigned */
    // NOTE: salt(slen) | encrypted payload length(2) | length tag(tlen) | encrypted payload(plen) | payload tag(tlen)
    return (unsigned)(slen + CHUNK_SIZE_LEN + tlen + plen + tlen);
}

/********** Registers **********/
void proto_register_ss(void)
{
    module_t *ss_module;

    proto_ss = proto_register_protocol(
        "Shadowsocks", // name
        "Shadowsocks", // short_name
        "shadowsocks"  // filter_name
    );
    ss_handle = register_dissector("shadowsocks", dissect_ss, proto_ss);

    /*** Header Fields ***/
    static hf_register_info hf[] = {
        /* Cipher Context */
        {&hf_cipher_ctx,
         {"Cipher Context",
          "shadowsocks.cipher_ctx",
          FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_salt,
         {"Salt",
          "shadowsocks.cipher_ctx.salt",
          FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_skey,
         {"Subkey",
          "shadowsocks.cipher_ctx.skey",
          FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_nonce,
         {"Nonce",
          "shadowsocks.cipher_ctx.nonce",
          FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher,
         {"Cipher",
          "shadowsocks.cipher_ctx.cipher",
          FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_method,
         {"Method",
          "shadowsocks.cipher_ctx.cipher.method",
          FT_INT8, BASE_DEC,
          VALS(hf_cipher_ctx_cipher_method_vals), 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_password,
         {"Password",
          "shadowsocks.cipher_ctx.cipher.password",
          FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_key,
         {"Key",
          "shadowsocks.cipher_ctx.cipher.key",
          FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_nonce_len,
         {"Nonce Length",
          "shadowsocks.cipher_ctx.cipher.nonce_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_key_len,
         {"Key Length",
          "shadowsocks.cipher_ctx.cipher.key_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_tag_len,
         {"Tag Length",
          "shadowsocks.cipher_ctx.cipher.tag_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        /* Salt */
        {&hf_salt,
         {"Salt",
          "shadowsocks.salt",
          FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        /* Relay Header */
        {&hf_atyp,
         {"Address Type",
          "shadowsocks.atyp",
          FT_UINT8, BASE_DEC,
          VALS(hf_atyp_vals), 0x0, NULL, HFILL}},
        {&hf_dst_addr_ipv4,
         {"IPv4 Address",
          "shadowsocks.dst_addr.ipv4",
          FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_addr_domainname_len,
         {"Domain Name Length",
          "shadowsocks.dst_addr.domainname_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_addr_domainname,
         {"Domain Name",
          "shadowsocks.dst_addr.domainname",
          FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_addr_ipv6,
         {"IPv6 Address",
          "shadowsocks.dst_addr.ipv6",
          FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_port,
         {"Destination Port",
          "shadowsocks.dst_port",
          FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        /* Reassembly Info */
        {&hf_msg_fragments,
         {"Reassembled Shadowsocks Message fragments",
          "shadowsocks.msg.fragments",
          FT_NONE, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment,
         {"Message fragment",
          "shadowsocks.msg.fragment",
          FT_FRAMENUM, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment_overlap,
         {"Message fragment overlap",
          "shadowsocks.msg.fragment.overlap",
          FT_BOOLEAN, 0,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "shadowsocks.msg.fragment.overlap.conflicts",
          FT_BOOLEAN, 0,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment_multiple_tails,
         {"Message has multiple tail fragments",
          "shadowsocks.msg.fragment.multiple_tails",
          FT_BOOLEAN, 0,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment_too_long_fragment,
         {"Message fragment too long",
          "shadowsocks.msg.fragment.too_long_fragment",
          FT_BOOLEAN, 0,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment_error,
         {"Message defragmentation error",
          "shadowsocks.msg.fragment.error",
          FT_FRAMENUM, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_fragment_count,
         {"Message fragment count",
          "shadowsocks.msg.fragment.count",
          FT_UINT32, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_reassembled_in,
         {"Reassembled in",
          "shadowsocks.msg.reassembled.in",
          FT_FRAMENUM, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_reassembled_length,
         {"Reassembled length",
          "shadowsocks.msg.reassembled.length",
          FT_UINT32, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_reassembled_data,
         {"Reassembled data",
          "shadowsocks.msg.reassembled.data",
          FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_msg_body_segment,
         {"Shadowsocks body segment",
          "shadowsocks.msg.body.segment",
          FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
    };
    /* Subtree Arrays */
    static int *ett[] = {
        &ett_ss,
        &ett_cipher_ctx,
        &ett_cipher_ctx_cipher,
        &ett_msg_fragment,
        &ett_msg_fragments,
    };
    /* Register */
    proto_register_field_array(proto_ss, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    reassembly_table_register(&proto_ss_streaming_reassembly_table,
                              &addresses_ports_reassembly_table_functions);

    /*** Preferences ***/
    ss_module = prefs_register_protocol(proto_ss, proto_reg_handoff_ss);
    prefs_register_enum_preference(ss_module,
                                   "cipher",
                                   "Cipher",
                                   "The cipher used by the Shadowsocks server",
                                   (int *)&pref_cipher,
                                   pref_cipher_vals,
                                   false);
    prefs_register_string_preference(ss_module,
                                     "password",
                                     "Password",
                                     "The password set by Shadowsocks server",
                                     &pref_password);

    /*** Routines ***/
    register_init_routine(ss_init_routine);
    register_cleanup_routine(ss_cleanup_routine);
}

void proto_reg_handoff_ss(void)
{
    dissector_add_uint_with_preference("tcp.port", SHADOWSOCKS_TCP_PORT, ss_handle);
}

/********** Routines **********/
void ss_init_routine(void)
{
    ss_crypto = ss_crypto_init(pref_password, NULL, supported_aead_ciphers[pref_cipher]);
    if (ss_crypto == NULL)
        ws_critical("Failed to initialize ciphers");

    // ss_buf = wmem_new0(wmem_file_scope(), ss_buffer_t);
    // ss_balloc(ss_buf, BUF_SIZE);
}

void ss_cleanup_routine(void)
{
    // if (ss_buf != NULL)
    // {
    //     ss_bfree(ss_buf);
    //     wmem_free(wmem_file_scope(), ss_buf);
    // }
}

/********** Conversation **********/
/**
 * @brief Return the Shadowsocks conversation data if it exists, or create a new one
 */
ss_conv_data_t *get_ss_conv_data(conversation_t *conversation, const int proto)
{
    ss_conv_data_t *conv_data;

    conv_data = (ss_conv_data_t *)conversation_get_proto_data(conversation, proto);
    if (conv_data != NULL)
        return conv_data;

    /*** Initialization ***/
    conv_data = wmem_new0(wmem_file_scope(), ss_conv_data_t);

    conv_data->server_addr = wmem_new0(wmem_file_scope(), address);
    clear_address(conv_data->server_addr);

    conv_data->request_cipher_ctx = wmem_new0(wmem_file_scope(), ss_cipher_ctx_t);
    conv_data->response_cipher_ctx = wmem_new0(wmem_file_scope(), ss_cipher_ctx_t);
    ss_crypto->ctx_init(ss_crypto->cipher, conv_data->request_cipher_ctx);
    ss_crypto->ctx_init(ss_crypto->cipher, conv_data->response_cipher_ctx);

    conv_data->request_pkt_order_list = wmem_list_new(wmem_file_scope());
    conv_data->response_pkt_order_list = wmem_list_new(wmem_file_scope());

    conv_data->pkt_type_map = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    conv_data->nonce_map = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    conv_data->salts = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);

    conv_data->reassembly_info = streaming_reassembly_info_new();

    conversation_add_proto_data(conversation, proto, conv_data);
    return conv_data;
}

/********** Crypto **********/
/**
 * @brief Decrypt the content of the packet.
 *  Each encrypted chunk has the following structure:
 *  [encrypted payload length][length tag][encrypted payload][payload tag]
 *  Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF.
 *  The higher two bits are reserved and must be set to zero.
 *  Payload is therefore limited to 16*1024 - 1 bytes.
 *  The first AEAD encrypt/decrypt operation uses a counting nonce starting from 0.
 *  After each encrypt/decrypt operation, the nonce is incremented by one as if it were an unsigned little-endian integer.
 *  Note that each TCP chunk involves two AEAD encrypt/decrypt operation: one for the payload length, and one for the payload.
 *  Therefore each chunk increases the nonce twice.
 * @param cipher_ctx Cipher context
 * @param p Pointer to plaintext (output)
 * @param c Ciphertext
 * @param n Nonce
 * @param plen Pointer to plaintext length (output)
 * @param clen Ciphertext length
 * @return 0 on success and an error code otherwise
 */
int ss_aead_decrypt(ss_cipher_ctx_t *cipher_ctx, uint8_t **p, uint8_t *c, uint8_t *n, size_t **plen, size_t clen)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t hd = cipher_ctx->cipher->hd;
    size_t nlen = cipher_ctx->cipher->nonce_len;
    size_t tlen = cipher_ctx->cipher->tag_len;
    uint8_t *len_buf = (uint8_t *)wmem_alloc0(wmem_file_scope(), CHUNK_SIZE_LEN + tlen);
    size_t chunk_len;
    uint8_t *n_copy = (uint8_t *)wmem_memdup(wmem_file_scope(), n, nlen);
    uint8_t *tmp_p;
    size_t tmp_plen;

    err = ss_aead_cipher_ctx_set_key(cipher_ctx);
    if (err)
    {
        ws_critical("Failed to set cipher key: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }

    if (*plen == NULL)
        *plen = wmem_new0(wmem_file_scope(), size_t);

    if (clen <= 2 * tlen + CHUNK_SIZE_LEN)
    {
        ws_message("clen(%lu) <= 2 * tlen(%lu) + CHUNK_SIZE_LEN(%d)", clen, 2 * tlen, CHUNK_SIZE_LEN);
        return RET_CRYPTO_NEED_MORE;
    }

    /* Decrypt Length */
    err = gcry_cipher_setiv(hd, n_copy, nlen);
    if (err)
    {
        ws_critical("Failed to set IV: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    // NOTE: The `outsize` should always be expected length + tag length
    err = gcry_cipher_decrypt(hd, len_buf, CHUNK_SIZE_LEN + tlen, c, CHUNK_SIZE_LEN + tlen);
    if (err)
    {
        ws_critical("Failed to decrypt length: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }

    /* Decode the length and pass it to `plen` */
    tmp_plen = load16_be(len_buf);
    wmem_free(wmem_file_scope(), len_buf);
    tmp_plen = tmp_plen & CHUNK_SIZE_MASK;
    **plen = tmp_plen;

    if (tmp_plen == 0)
    {
        ws_critical("Invalid message length decoded: %lu", tmp_plen);
        return RET_CRYPTO_ERROR;
    }

    chunk_len = 2 * tlen + CHUNK_SIZE_LEN + tmp_plen;

    if (clen < chunk_len)
    {
        ws_message("clen(%lu) < 2 * tlen(%lu) + CHUNK_SIZE_LEN(%d) + tmp_plen(%lu)", clen, 2 * tlen, CHUNK_SIZE_LEN, tmp_plen);
        return RET_CRYPTO_NEED_MORE;
    }

    sodium_increment(n_copy, nlen);

    /* Decrypt Content */
    err = gcry_cipher_setiv(hd, n_copy, nlen);
    wmem_free(wmem_file_scope(), n_copy);
    if (err)
    {
        ws_critical("Failed to set IV: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    tmp_p = (uint8_t *)wmem_alloc0(wmem_file_scope(), tmp_plen + tlen);
    err = gcry_cipher_decrypt(hd, tmp_p, tmp_plen + tlen, c + CHUNK_SIZE_LEN + tlen, tmp_plen + tlen);
    if (err)
    {
        ws_critical("Failed to decrypt content: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }

    /* Pass the plaintext to `p` */
    *p = (uint8_t *)wmem_memdup(wmem_file_scope(), tmp_p, tmp_plen);
    wmem_free(wmem_file_scope(), tmp_p);

    return RET_OK;
}

/**
 * @brief Extract a pseudorandom key from `salt` and `ikm` arguments.
 *  And generate output key material based on an `info` value.
 *  Called by `ss_aead_cipher_ctx_set_key`.
 * @param md_algo Hash algorithm (defined in gcrypt.h)
 * @param salt Salt
 * @param salt_len Length of salt
 * @param ikm Input keying material (derived from password)
 * @param ikm_len Length of ikm
 * @param info Optional context ("ss-subkey" in this case)
 * @param info_len Length of info
 * @param okm Output keying material (subkey)
 * @param okm_len Length of okm
 * @return 0 on success and an error code otherwise
 */
gcry_error_t ss_crypto_hkdf(int md_algo,
                            const unsigned char *salt, int salt_len,
                            const unsigned char *ikm, int ikm_len,
                            const unsigned char *info, int info_len,
                            unsigned char *okm, int okm_len)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    unsigned char prk[MAX_MD_SIZE];

    err = hkdf_extract(md_algo, salt, salt_len, ikm, ikm_len, prk);
    if (err)
    {
        return err;
    }
    err = hkdf_expand(md_algo, prk, HASH_SHA1_LENGTH, info, info_len, okm, okm_len);
    if (err)
    {
        return err;
    }

    return err;
}

/**
 * @brief Set the key and nonce for `cipher_ctx`.
 *  Called after the salt is received.
 *  HKDF_SHA1 is a function that takes a secret key, a non-secret salt, an info string,
 *   and produces a subkey that is cryptographically strong even if the input secret key is weak.
 *  HKDF_SHA1(key, salt, info) => subkey
 *  The info string binds the generated subkey to a specific application context.
 *  In our case, it must be the string "ss-subkey" without quotes.
 *  We derive a per-session subkey from a pre-shared master key using HKDF_SHA1.
 *  Salt must be unique through the entire life of the pre-shared master key.
 * @param cipher_ctx Cipher context
 * @return 0 on success and an error code otherwise
 */
gcry_error_t ss_aead_cipher_ctx_set_key(ss_cipher_ctx_t *cipher_ctx)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;

    err = ss_crypto_hkdf(GCRY_MD_SHA1,
                         cipher_ctx->salt, cipher_ctx->cipher->key_len,
                         cipher_ctx->cipher->key, cipher_ctx->cipher->key_len,
                         (uint8_t *)SUBKEY_INFO, strlen(SUBKEY_INFO),
                         cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err)
    {
        ws_critical("Failed to generate subkey: %s", gcry_strerror(err));
        return err;
    }

    // memset(cipher_ctx->nonce, 0, cipher_ctx->cipher->nonce_len);

    err = gcry_cipher_setkey(cipher_ctx->cipher->hd, cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err)
    {
        ws_critical("Failed to set cipher key: %s", gcry_strerror(err));
        return err;
    }

    return err;
}

int ss_crypto_parse_key(const char *base64 _U_, uint8_t *key _U_, size_t key_len)
{
    // TODO
    return key_len;
}

/**
 * @brief Derive a key from the `pass` argument.
 *  Called by `ss_aead_key_init`.
 * @param pass Password
 * @param key Output key
 * @param key_len Length of key
 * @return Length of the key, or 0 on failure
 */
int ss_crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    unsigned int i, j;
    int addmd;
    gcry_md_hd_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    unsigned int mds = gcry_md_get_algo_dlen(GCRY_MD_MD5);
    size_t datal = strlen((const char *)pass);

    if (pass == NULL)
        return key_len;

    err = gcry_md_open(&c, GCRY_MD_MD5, 0);
    if (err)
    {
        ws_critical("Failed to initialize the MD5 context: %s", gcry_strerror(err));
        return 0;
    }

    for (j = 0, addmd = 0; j < key_len; addmd++)
    {
        gcry_md_reset(c);
        if (addmd)
        {
            gcry_md_write(c, md_buf, mds);
        }
        gcry_md_write(c, (uint8_t *)pass, datal);
        memcpy(md_buf, gcry_md_read(c, GCRY_MD_MD5), mds);

        for (i = 0; i < mds; i++, j++)
        {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    gcry_md_close(c);

    return key_len;
}

ss_cipher_t *ss_aead_key_init(int method, const char *pass, const char *key)
{
    ss_cipher_t *cipher;
    gcry_error_t err = GPG_ERR_NO_ERROR;

    if (method < AEAD_CIPHER_AES128GCM || method >= AEAD_CIPHER_NUM)
    {
        ws_critical("Illegal method: %d", method);
        return NULL;
    }

    cipher = wmem_new0(wmem_file_scope(), ss_cipher_t);

    if (key != NULL)
    {
        // TODO: Implement the key parsing function
        // cipher->key_len = crypto_parse_key(key, cipher->key,
        //                                    supported_aead_ciphers_key_size[method]);
        return NULL;
    }
    else
        cipher->key_len = ss_crypto_derive_key(pass, cipher->key, supported_aead_ciphers_key_size[method]);

    if (cipher->key_len == 0)
    {
        ws_critical("Failed to derive key");
        return NULL;
    }

    cipher->nonce_len = supported_aead_ciphers_nonce_size[method];
    cipher->tag_len = supported_aead_ciphers_tag_size[method];
    cipher->method = method;

    switch (method)
    {
    case AEAD_CIPHER_AES128GCM:
        err = gcry_cipher_open(&cipher->hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case AEAD_CIPHER_AES192GCM:
        err = gcry_cipher_open(&cipher->hd, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case AEAD_CIPHER_AES256GCM:
        err = gcry_cipher_open(&cipher->hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case AEAD_CIPHER_CHACHA20POLY1305IETF:
        err = gcry_cipher_open(&cipher->hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case AEAD_CIPHER_XCHACHA20POLY1305IETF:
        // NOTE: xchacha20-ietf-poly1305 is not supported by libgcrypt
        //  err = gcry_cipher_open(&cipher->hd, GCRY_CIPHER_XCHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
        err = GPG_ERR_UNKNOWN_ALGORITHM;
        ws_critical("Unsupported cipher: xchacha20-ietf-poly1305");
        break;
#endif
    default:
        err = GPG_ERR_UNKNOWN_ALGORITHM;
        break;
    }
    if (err)
    {
        ws_critical("Failed to initialize the cipher: %s", gcry_strerror(err));
        return NULL;
    }

    return cipher;
}

ss_cipher_t *ss_aead_init(const char *pass, const char *key, const char *method)
{
    int m = AEAD_CIPHER_AES128GCM;
    if (method != NULL)
    {
        /* check method validity */
        for (m = AEAD_CIPHER_AES128GCM; m < AEAD_CIPHER_NUM; m++)
        {
            if (strcmp(method, supported_aead_ciphers[m]) == 0)
            {
                break;
            }
        }
        if (m >= AEAD_CIPHER_NUM)
        {
            ws_critical("Invalid cipher name: %s, use chacha20-ietf-poly1305 instead", method);
            m = AEAD_CIPHER_CHACHA20POLY1305IETF;
        }
    }
    return ss_aead_key_init(m, pass, key);
}

ss_crypto_t *ss_crypto_init(const char *password, const char *key, const char *method)
{
    int m = -1;

    if (method != NULL)
    {
        // NOTE: Stream ciphers are deprecated
        for (int i = 0; i < AEAD_CIPHER_NUM; i++)
            if (strcmp(method, supported_aead_ciphers[i]) == 0)
            {
                m = i;
                break;
            }
        if (m != -1)
        {
            ss_cipher_t *cipher = ss_aead_init(password, key, method);
            if (cipher == NULL)
            {
                return NULL;
            }
            ss_crypto_t *crypto = wmem_new0(wmem_file_scope(), ss_crypto_t);
            ss_crypto_t tmp = {
                .cipher = cipher,
                // .decrypt_all = &aead_decrypt_all,
                // .decrypt = &aead_decrypt,
                .ctx_init = &ss_aead_ctx_init,
                .ctx_release = &ss_aead_ctx_release,
            };
            memcpy(crypto, &tmp, sizeof(ss_crypto_t));
            return crypto;
        }
    }

    ws_critical("Invalid cipher name: %s", method);
    return NULL;
}

void ss_aead_ctx_init(ss_cipher_t *cipher, ss_cipher_ctx_t *cipher_ctx)
{
    memset(cipher_ctx, 0, sizeof(ss_cipher_ctx_t));
    cipher_ctx->cipher = cipher;
}

void ss_aead_ctx_release(ss_cipher_ctx_t *cipher_ctx)
{
    if (cipher_ctx->chunk != NULL)
    {
        ss_bfree(cipher_ctx->chunk);
        wmem_free(wmem_file_scope(), cipher_ctx->chunk);
        cipher_ctx->chunk = NULL;
    }

    if (cipher_ctx->cipher->method >= AEAD_CIPHER_CHACHA20POLY1305IETF)
        return;
}

/********** Buffer Operations **********/
int ss_balloc(ss_buffer_t *ptr, size_t capacity)
{
    memset(ptr, 0, sizeof(ss_buffer_t));
    ptr->data = (char *)wmem_alloc0(wmem_file_scope(), capacity);
    ptr->capacity = capacity;
    return capacity;
}

int ss_brealloc(ss_buffer_t *ptr, size_t len, size_t capacity)
{
    if (ptr == NULL)
        return -1;
    size_t real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity)
    {
        ptr->data = (char *)wmem_realloc(wmem_file_scope(), ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void ss_bfree(ss_buffer_t *ptr)
{
    if (ptr == NULL)
        return;
    ptr->idx = 0;
    ptr->len = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL)
    {
        wmem_free(wmem_file_scope(), ptr->data);
        ptr->data = NULL;
    }
}

int ss_bprepend(ss_buffer_t *dst, ss_buffer_t *src, size_t capacity)
{
    ss_brealloc(dst, dst->len + src->len, capacity);
    memmove(dst->data + src->len, dst->data, dst->len);
    memcpy(dst->data, src->data, src->len);
    dst->len = dst->len + src->len;
    return dst->len;
}

/********** Utils **********/
uint16_t load16_be(const void *s)
{
    const uint8_t *in = (const uint8_t *)s;
    return ((uint16_t)in[0] << 8) | ((uint16_t)in[1]);
}

void sodium_increment(unsigned char *n, const size_t nlen)
{
    size_t i = 0U;
    uint_fast16_t c = 1U;

#ifdef HAVE_AMD64_ASM
    uint64_t t64, t64_2;
    uint32_t t32;

    if (nlen == 12U)
    {
        __asm__ __volatile__(
            "xorq %[t64], %[t64] \n"
            "xorl %[t32], %[t32] \n"
            "stc \n"
            "adcq %[t64], (%[out]) \n"
            "adcl %[t32], 8(%[out]) \n"
            : [t64] "=&r"(t64), [t32] "=&r"(t32)
            : [out] "D"(n)
            : "memory", "flags", "cc");
        return;
    }
    else if (nlen == 24U)
    {
        __asm__ __volatile__(
            "movq $1, %[t64] \n"
            "xorq %[t64_2], %[t64_2] \n"
            "addq %[t64], (%[out]) \n"
            "adcq %[t64_2], 8(%[out]) \n"
            "adcq %[t64_2], 16(%[out]) \n"
            : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2)
            : [out] "D"(n)
            : "memory", "flags", "cc");
        return;
    }
    else if (nlen == 8U)
    {
        __asm__ __volatile__("incq (%[out]) \n"
                             :
                             : [out] "D"(n)
                             : "memory", "flags", "cc");
        return;
    }
#endif
    for (; i < nlen; i++)
    {
        c += (uint_fast16_t)n[i];
        n[i] = (unsigned char)c;
        c >>= 8;
    }
}

int validate_hostname(const char *hostname, const int hostname_len)
{
    if (hostname == NULL)
        return 0;

    if (hostname_len < 1 || hostname_len > 255)
        return 0;

    if (hostname[0] == '.')
        return 0;

    const char *label = hostname;
    while (label < hostname + hostname_len)
    {
        size_t label_len = hostname_len - (label - hostname);
        char *next_dot = strchr(label, '.');
        if (next_dot != NULL)
            label_len = next_dot - label;

        if (label + label_len > hostname + hostname_len)
            return 0;

        if (label_len > 63 || label_len < 1)
            return 0;

        if (label[0] == '-' || label[label_len - 1] == '-')
            return 0;

        if (strspn(label, "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz") < label_len)
            return 0;

        label += label_len + 1;
    }

    return 1;
}

/**
 * @brief `wmem_map_find` compares the MEMORY ADDRESS of the frame data but not the VALUE.
 *  Therefore, `wmem_map_find_custom` is used instead.
 */
int cmp_list_frame_uint_data(const void *a, const void *b)
{
    return *(uint32_t *)a - *(uint32_t *)b;
}
ss_pkt_type_t get_prev_pkt_type(wmem_list_frame_t *frame, wmem_map_t *pkt_type_map)
{
    wmem_list_frame_t *prev_frame;
    uint32_t *prev_pinfo_num;
    ss_pkt_type_t *prev_pkt_type;

    prev_frame = wmem_list_frame_prev(frame);
    if (prev_frame == NULL)
    { /* Head */
        // NOTE: Return PKT_TYPE_UNSET to indicate no previous packet.
        ws_message("No previous packet");
        return PKT_TYPE_UNSET;
    }
    prev_pinfo_num = (uint32_t *)wmem_list_frame_data(prev_frame);
    if (prev_pinfo_num == NULL)
    {
        ws_critical("Failed to get previous packet index");
        return PKT_TYPE_UNKNOWN;
    }
    prev_pkt_type = (ss_pkt_type_t *)wmem_map_lookup(pkt_type_map, prev_pinfo_num);
    if (prev_pkt_type == NULL)
    {
        ws_critical("Failed to get previous packet type");
        return PKT_TYPE_UNKNOWN;
    }

    return *prev_pkt_type;
}

/**
 * @brief Look up the nonce of the previous packet.
 *  If no previous nonce is found, return all-zero nonce.
 *  If a previous nonce is found and the packet is reassembled, return the same nonce (because they are literally the same packet).
 *  If a previous nonce is found and the packet is not reassembled, return the incremented nonce.
 * @param pinfo_num Packet number
 * @param nonce Pointer to the nonce (output)
 * @param reassembly_flag Flag indicating whether the packet is reassembled
 */
void get_nonce(uint32_t pinfo_num, uint8_t **nonce, wmem_list_t *pkt_order_list, wmem_map_t *nonce_map, bool reassembly_flag)
{
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &pinfo_num, sizeof(uint32_t));
    size_t nonce_len = ss_crypto->cipher->nonce_len;
    wmem_list_frame_t *cur_frame = NULL;
    wmem_list_frame_t *prev_frame = NULL;
    uint32_t *prev_pinfo_num = NULL;
    uint8_t *prev_nonce = NULL;
    uint8_t *nonce_copy = NULL;

    nonce_copy = (uint8_t *)wmem_map_lookup(nonce_map, pinfo_num_copy);
    if (nonce_copy != NULL)
    {
        *nonce = (uint8_t *)wmem_memdup(wmem_file_scope(), nonce_copy, nonce_len);
        return;
    }

    /* Search backward until a nonce is found or reach the head of the list */
    cur_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    if (cur_frame == NULL)
        wmem_list_append(pkt_order_list, pinfo_num_copy);
    cur_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    prev_frame = wmem_list_frame_prev(cur_frame);
    while (prev_frame != NULL)
    {
        prev_pinfo_num = (uint32_t *)wmem_list_frame_data(prev_frame);
        if (prev_pinfo_num == NULL)
        {
            ws_critical("Failed to get previous packet index");
            break;
        }
        prev_nonce = (uint8_t *)wmem_map_lookup(nonce_map, prev_pinfo_num);
        /* If last nonce is found,
         return the incremented value(for normal packets)
         or the same value(for reassembled packets) */
        if (prev_nonce != NULL)
        {
            nonce_copy = wmem_memdup(wmem_file_scope(), prev_nonce, nonce_len);
            if (reassembly_flag)
                break;
            sodium_increment(nonce_copy, nonce_len);
            sodium_increment(nonce_copy, nonce_len);
            break;
        }
        prev_frame = wmem_list_frame_prev(prev_frame);
    }

    /* If no nonce is found, set the nonce to zero */
    if (prev_nonce == NULL)
    {
        nonce_copy = wmem_alloc0(wmem_file_scope(), nonce_len);
        memset(nonce_copy, 0, nonce_len);
    }

    /* Save the nonce for the current packet */
    *nonce = (uint8_t *)wmem_memdup(wmem_file_scope(), nonce_copy, nonce_len);
    wmem_map_insert(nonce_map, pinfo_num_copy, nonce_copy);
}

/********** Debugging **********/
void debug_print_uint_key_int_value(const void *key, const void *value, void *user_data)
{
    char *buf = (char *)user_data;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "  - %u: %d\n", *(uint32_t *)key, *(int *)value);
    strcat(buf, tmp);
}

void debug_print_uint_key_uint_value(const void *key, const void *value, void *user_data)
{
    char *buf = (char *)user_data;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "  - %u: %u\n", *(uint32_t *)key, *(uint32_t *)value);
    strcat(buf, tmp);
}

void debug_print_uint_key_uint8_array_value(const void *key, const void *value, void *user_data)
{
    char *buf = (char *)user_data;
    char tmp[128];
    int offset = snprintf(tmp, sizeof(tmp), "  - %u: ", *(uint32_t *)key);

    for (size_t i = 0; i < 16; i++)
    {
        offset += snprintf(tmp + offset, sizeof(tmp) - offset, "%02x", ((uint8_t *)value)[i]);
    }

    snprintf(tmp + offset, sizeof(tmp) - offset, "\n");
    strcat(buf, tmp);
}

void debug_print_hash_map(wmem_map_t *hash_map, const char *var_name, PrintFunc print_func)
{
    char buf[4096] = {0};
    char header[128];

    snprintf(header, sizeof(header), "[DEBUG] %s:\n", var_name);
    strcat(buf, header);

    wmem_map_foreach(hash_map, (GHFunc)print_func, buf);

    ws_message("%s", buf);
}

void debug_print_list(wmem_list_t *list, const char *var_name)
{
    char buf[4096] = {0};
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "[DEBUG] %s: HEAD - ", var_name);
    strcat(buf, tmp);

    wmem_list_frame_t *frame;
    for (frame = wmem_list_head(list); frame != NULL; frame = wmem_list_frame_next(frame))
    {
        snprintf(tmp, sizeof(tmp), "%u - ", *(uint32_t *)wmem_list_frame_data(frame));
        strcat(buf, tmp);
    }

    strcat(buf, "TAIL\n");
    ws_message("%s", buf);
}

void debug_print_uint8_array(const uint8_t *array, size_t len, const char *var_name)
{
    char buf[4096] = {0};
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "[DEBUG] %s: ", var_name);
    strcat(buf, tmp);

    for (size_t i = 0; i < len; i++)
    {
        snprintf(tmp, sizeof(tmp), "%02x", array[i]);
        strcat(buf, tmp);
    }

    strcat(buf, "\n");
    ws_message("%s", buf);
}

void debug_print_tvb(tvbuff_t *tvb, const char *var_name)
{
    char buf[4096] = {0};
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "[DEBUG] %s: ", var_name);
    strcat(buf, tmp);

    for (size_t i = 0; i < tvb_captured_length(tvb); i++)
    {
        snprintf(tmp, sizeof(tmp), "%02x", tvb_get_guint8(tvb, i));
        strcat(buf, tmp);
    }

    strcat(buf, "\n");
    ws_message("%s", buf);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
