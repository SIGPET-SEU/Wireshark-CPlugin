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

#include "config.h"

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/wmem_scopes.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>

#ifndef __MINGW32__
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "packet-shadowsocks.h"

/********** Protocol Handles **********/
static int proto_ss;

/********** Dissector Handles **********/
static dissector_handle_t ss_handle;

/********** Header Fields **********/
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
static int hf_salt;
static int hf_atyp;
static int hf_dst_addr_ipv4;
static int hf_dst_addr_domainname_len;
static int hf_dst_addr_domainname;
static int hf_dst_addr_ipv6;
static int hf_dst_port;

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
static int ett_ss;
static int ett_cipher_ctx;
static int ett_cipher_ctx_cipher;

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
/* Hash Tables (use pinfo->num as key) */
static wmem_map_t *pkt_type_map;
static wmem_map_t *nonce_map;
// NOTE: `shadowsocks-libev` uses a bloom filter to store and check salts. Here a hash table is used instead.
// NOTE AGAIN: Seems that it is used to avoid replay attacks only, so not necessary here?
// static wmem_map_t *salts;
/* Doubly Linked List */
static wmem_list_t *pkt_order_list;

// These vars will be initialized in `ss_init_routine`
// TODO: Gather the following vars into conv_data?
ss_cipher_ctx_t *ss_cipher_ctx;
ss_crypto_t *ss_crypto;
ss_buffer_t *ss_buf;
int ss_frag = 0;

int dissect_ss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    ss_conv_data_t *conv_data _U_;
    uint32_t *pinfo_num_copy _U_ = (uint32_t *)wmem_memdup(wmem_file_scope(), &(pinfo->num), sizeof(uint32_t));
    int prev_pkt_type _U_, *cur_pkt_type = wmem_new0(wmem_file_scope(), int);
    // ss_buffer_t *buf = ss_buf;
    proto_item *ti, *cipher_ctx_ti, *cipher_ctx_cipher_ti;
    proto_tree *ss_tree, *cipher_ctx_tree, *cipher_ctx_cipher_tree;

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Type Detection ***/
    int tmp_pkt_type = detect_ss_pkt_type(tvb, pinfo->num);
    memcpy(cur_pkt_type, &tmp_pkt_type, sizeof(int));
    wmem_map_insert(pkt_type_map, pinfo_num_copy, cur_pkt_type);

    /*** Protocol Tree ***/
    ti = proto_tree_add_item(tree, proto_ss, tvb, 0, -1, ENC_NA);
    ss_tree = proto_item_add_subtree(ti, ett_ss);
    /* Cipher Context */
    cipher_ctx_ti = proto_tree_add_item(ss_tree, hf_cipher_ctx, tvb, 0, 0, ENC_NA);
    proto_item_set_text(cipher_ctx_ti, "Cipher Context");
    cipher_ctx_tree = proto_item_add_subtree(cipher_ctx_ti, ett_cipher_ctx);
    if (ss_cipher_ctx->init)
    {
        proto_tree_add_bytes_with_length(cipher_ctx_tree, hf_cipher_ctx_salt, tvb, 0, 0, ss_cipher_ctx->salt, ss_cipher_ctx->cipher->key_len);
        proto_tree_add_bytes_with_length(cipher_ctx_tree, hf_cipher_ctx_skey, tvb, 0, 0, ss_cipher_ctx->skey, ss_cipher_ctx->cipher->key_len);
        // proto_tree_add_bytes_with_length(cipher_ctx_tree, hf_cipher_ctx_nonce, tvb, 0, 0, ss_cipher_ctx->nonce, ss_cipher_ctx->cipher->nonce_len);
    }
    /* Cipher */
    cipher_ctx_cipher_ti = proto_tree_add_item(cipher_ctx_tree, hf_cipher_ctx_cipher, tvb, 0, 0, ENC_NA);
    proto_item_set_text(cipher_ctx_cipher_ti, "Cipher");
    cipher_ctx_cipher_tree = proto_item_add_subtree(cipher_ctx_cipher_ti, ett_cipher_ctx_cipher);
    proto_tree_add_int(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_method, tvb, 0, 0, ss_cipher_ctx->cipher->method);
    proto_tree_add_string(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_password, tvb, 0, 0, pref_password);
    proto_tree_add_bytes_with_length(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_key, tvb, 0, 0, ss_cipher_ctx->cipher->key, ss_cipher_ctx->cipher->key_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_nonce_len, tvb, 0, 0, ss_cipher_ctx->cipher->nonce_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_key_len, tvb, 0, 0, ss_cipher_ctx->cipher->key_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_tag_len, tvb, 0, 0, ss_cipher_ctx->cipher->tag_len);

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
        dissect_ss_relay_header(tvb, pinfo, ss_tree, data);
        break;
    case PKT_TYPE_STREAM_DATA:
        col_set_str(pinfo->cinfo, COL_INFO, "[Data]");
        break;
    case PKT_TYPE_SALT_NEED_MORE:
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt (Need More)]");
        break;
    case PKT_TYPE_RELAY_HEADER_NEED_MORE:
        col_set_str(pinfo->cinfo, COL_INFO, "[Relay Header (Need More)]");
        break;
    case PKT_TYPE_STREAM_DATA_NEED_MORE:
        col_set_str(pinfo->cinfo, COL_INFO, "[Data (Need More)]");
        break;
    default:
        ws_critical("[%u] Unknown packet type: %d", pinfo->num, *cur_pkt_type);
        break;
    }
    // ss_buf->len = tvb_captured_length(tvb);
    // ss_crypto->decrypt(ss_buf, ss_cipher_ctx, BUF_SIZE);

    return tvb_captured_length(tvb);
}

/********** Dissectors **********/
int detect_ss_pkt_type(tvbuff_t *tvb, uint32_t pinfo_num)
{
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &pinfo_num, sizeof(uint32_t));
    uint32_t tvb_len = tvb_captured_length(tvb);
    int *cur_pkt_type, prev_pkt_type;
    uint8_t *cur_nonce = wmem_alloc0(wmem_file_scope(), ss_crypto->cipher->nonce_len);
    uint8_t *plaintext = wmem_alloc0(wmem_file_scope(), BUF_SIZE);
    size_t *plen = wmem_new0(wmem_file_scope(), size_t);
    size_t salt_len = ss_crypto->cipher->key_len;

    /* Try to get the packet type from the hash table */
    cur_pkt_type = (int *)wmem_map_lookup(pkt_type_map, pinfo_num_copy);
    if (cur_pkt_type != NULL)
        return *cur_pkt_type;

    /* Get previous packet type */
    wmem_list_frame_t *cur_list_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data); // NOTE: Don't use `wmem_list_find` for value comparison
    if (cur_list_frame == NULL)
    { /* The first occurrence of the packet */
        wmem_list_append(pkt_order_list, pinfo_num_copy);
    }
    cur_list_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    prev_pkt_type = get_prev_pkt_type(cur_list_frame);

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
        /* [SALT] */
        // NOTE: It cannot be distinguished from the case where the first packet is not salt, but happens to have the same length as the salt.
        memcpy(ss_cipher_ctx->salt, tvb_get_ptr(tvb, 0, salt_len), salt_len);
        gcry_error_t err = ss_aead_cipher_ctx_set_key(ss_cipher_ctx);
        if (err)
        {
            ws_critical("[%u] Failed to set cipher key: %s", pinfo_num, gcry_strerror(err));
            return PKT_TYPE_ERROR;
        }
        return PKT_TYPE_SALT;
        break;
    case PKT_TYPE_SALT:
        /* Check if it is [RELAY HEADER] */
        get_nonce(*pinfo_num_copy, cur_nonce);
        /* Decryption */
        int ret = ss_aead_decrypt(ss_cipher_ctx,
                                  plaintext,
                                  (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                                  cur_nonce,
                                  plen,
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
    case PKT_TYPE_STREAM_DATA:
        /* Check if it is [STREAM DATA] */
        get_nonce(*pinfo_num_copy, cur_nonce);
        /* Decryption */
        ret = ss_aead_decrypt(ss_cipher_ctx,
                              plaintext,
                              (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                              cur_nonce,
                              plen,
                              (size_t)tvb_len);
        if (ret == RET_CRYPTO_ERROR)
            return PKT_TYPE_ERROR;
        if (ret == RET_CRYPTO_NEED_MORE)
            return PKT_TYPE_STREAM_DATA_NEED_MORE;
        /* [STREAM DATA] */
        return PKT_TYPE_STREAM_DATA;
        break;
    case PKT_TYPE_SALT_NEED_MORE:
    case PKT_TYPE_RELAY_HEADER_NEED_MORE:
    case PKT_TYPE_STREAM_DATA_NEED_MORE:
        // TODO
        return PKT_TYPE_UNKNOWN;
        break;
    default:
        ws_error("[%u] Unknown previous packet type: %d", pinfo_num, prev_pkt_type);
        exit(-1);
        break;
    }
}

/**
 * @brief An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey (server -> client).
 *  Structure:
 *  +----------+
 *  |   Salt   |
 *  +----------+
 *  | 16/24/32 |
 *  +----------+
 * @return packet type
 */
void dissect_ss_salt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /*** Protocol Tree ***/
    proto_tree_add_item(tree, hf_salt, tvb, 0, -1, ENC_NA);
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
 * @return packet type
 */
void dissect_ss_relay_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &(pinfo->num), sizeof(uint32_t));
    uint32_t tvb_len = tvb_captured_length(tvb);
    uint8_t *cur_nonce = wmem_alloc0(wmem_file_scope(), ss_crypto->cipher->nonce_len);
    uint8_t *plaintext = wmem_alloc0(wmem_file_scope(), BUF_SIZE);
    size_t *plen = wmem_new0(wmem_file_scope(), size_t);
    tvbuff_t *next_tvb;
    int offset = 0;
    uint8_t atyp;
    int host_len;

    /*** Nonce ***/
    get_nonce(*pinfo_num_copy, cur_nonce);

    /*** Decryption ***/
    int ret = ss_aead_decrypt(ss_cipher_ctx,
                              plaintext,
                              (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                              cur_nonce,
                              plen,
                              (size_t)tvb_len);
    if (ret != RET_OK)
    {
        ws_error("[%u] Failed to decrypt relay header", pinfo->num);
        exit(-1);
    }

    /*** New Tab ***/
    next_tvb = tvb_new_child_real_data(tvb, plaintext, *plen, *plen);
    add_new_data_source(pinfo, next_tvb, "Decrypted Shadowsocks Relay Header");

    /*** Protocol Tree ***/
    atyp = tvb_get_uint8(next_tvb, offset);
    proto_tree_add_item(tree, hf_atyp, next_tvb, offset++, 1, ENC_BIG_ENDIAN);
    switch (atyp & ADDRTYPE_MASK)
    {
    case RELAY_HEADER_ATYP_IPV4:
        ws_in4_addr in4_addr = tvb_get_ipv4(next_tvb, offset);
        host_len = sizeof(struct in_addr);
        proto_tree_add_ipv4(tree, hf_dst_addr_ipv4, next_tvb, offset, host_len, in4_addr);
        break;
    case RELAY_HEADER_ATYP_DOMAINNAME:
        host_len = (int)tvb_get_uint8(next_tvb, offset);
        proto_tree_add_item(tree, hf_dst_addr_domainname_len, next_tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_dst_addr_domainname, next_tvb, offset, host_len, ENC_ASCII);
        break;
    case RELAY_HEADER_ATYP_IPV6:
        ws_in6_addr *in6_addr = wmem_new0(wmem_file_scope(), ws_in6_addr);
        tvb_get_ipv6(next_tvb, offset, in6_addr);
        host_len = sizeof(struct in6_addr);
        proto_tree_add_ipv6(tree, hf_dst_addr_ipv6, next_tvb, offset, host_len, in6_addr);
        break;
    default:
        ws_error("[%u] Invalid ATYP value: %d", pinfo->num, atyp);
        exit(-1);
        break;
    }
    offset += host_len;
    proto_tree_add_item(tree, hf_dst_port, next_tvb, offset, 2, ENC_BIG_ENDIAN);
}

void dissect_ss_stream_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &(pinfo->num), sizeof(uint32_t));
    uint32_t tvb_len = tvb_captured_length(tvb);
    uint8_t *cur_nonce = wmem_alloc0(wmem_file_scope(), ss_crypto->cipher->nonce_len);
    uint8_t *plaintext = wmem_alloc0(wmem_file_scope(), BUF_SIZE);
    size_t *plen = wmem_new0(wmem_file_scope(), size_t);
    tvbuff_t *next_tvb;

    /*** Nonce ***/
    get_nonce(*pinfo_num_copy, cur_nonce);

    /*** Decryption ***/
    int ret = ss_aead_decrypt(ss_cipher_ctx,
                              plaintext,
                              (uint8_t *)tvb_get_ptr(tvb, 0, tvb_len),
                              cur_nonce,
                              plen,
                              (size_t)tvb_len);
    if (ret != RET_OK)
    {
        ws_error("[%u] Failed to decrypt relay header", pinfo->num);
        exit(-1);
    }

    /*** New Tab ***/
    next_tvb = tvb_new_child_real_data(tvb, plaintext, *plen, *plen);
    add_new_data_source(pinfo, next_tvb, "Decrypted Shadowsocks Stream Data");
}

/**
 * @brief Dissect fully reassembled messages.
 */
int dissect_ss_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    // TODO: Implement
    return tvb_captured_length(tvb);
}

/**
 * @brief Determine PDU length of protocol Shadowsocks
 */
unsigned get_ss_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    uint8_t *cur_nonce = wmem_alloc0(wmem_file_scope(), ss_crypto->cipher->nonce_len);
    size_t tlen = ss_cipher_ctx->cipher->tag_len;
    size_t nlen = ss_cipher_ctx->cipher->nonce_len;
    size_t plen;
    uint8_t *len_buf = wmem_alloc0(wmem_file_scope(), 2 + tlen);

    /*** Decryption ***/
    if (tvb_captured_length(tvb) <= 2 * tlen + CHUNK_SIZE_LEN)
        ws_error("Not enough data to decrypt `plen`");
    gcry_error_t err = gcry_cipher_setiv(ss_cipher_ctx->cipher->hd, cur_nonce, nlen);
    if (err)
        ws_error("Failed to set IV: %s", gcry_strerror(err));
    // NOTE: The `outsize` should always be expected length + tag length
    err = gcry_cipher_decrypt(ss_cipher_ctx->cipher->hd, len_buf, 2 + tlen, tvb_get_ptr(tvb, 0, CHUNK_SIZE_LEN + tlen), CHUNK_SIZE_LEN + tlen);
    if (err)
        ws_error("Failed to decrypt length: %s", gcry_strerror(err));

    plen = load16_be(len_buf);
    plen = plen & CHUNK_SIZE_MASK;

    if (plen == 0)
        ws_error("Invalid message length decoded: %lu", plen);

    /* Cast to unsigned */
    ws_message("Fully reassembled message length: %lu", plen);
    return (unsigned)plen;
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
        {&hf_cipher_ctx,
         {"Cipher Context",
          "shadowsocks.cipher_ctx",
          FT_NONE,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_salt,
         {"Salt",
          "shadowsocks.cipher_ctx.salt",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_skey,
         {"Subkey",
          "shadowsocks.cipher_ctx.skey",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_nonce,
         {"Nonce",
          "shadowsocks.cipher_ctx.nonce",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher,
         {"Cipher",
          "shadowsocks.cipher_ctx.cipher",
          FT_NONE,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_method,
         {"Method",
          "shadowsocks.cipher_ctx.cipher.method",
          FT_INT8,
          BASE_DEC,
          VALS(hf_cipher_ctx_cipher_method_vals), 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_password,
         {"Password",
          "shadowsocks.cipher_ctx.cipher.password",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_key,
         {"Key",
          "shadowsocks.cipher_ctx.cipher.key",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_nonce_len,
         {"Nonce Length",
          "shadowsocks.cipher_ctx.cipher.nonce_len",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_key_len,
         {"Key Length",
          "shadowsocks.cipher_ctx.cipher.key_len",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_cipher_ctx_cipher_tag_len,
         {"Tag Length",
          "shadowsocks.cipher_ctx.cipher.tag_len",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_salt,
         {"Salt",
          "shadowsocks.salt",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_atyp,
         {"Address Type",
          "shadowsocks.atyp",
          FT_UINT8,
          BASE_DEC,
          VALS(hf_atyp_vals), 0x0, NULL, HFILL}},
        {&hf_dst_addr_ipv4,
         {"IPv4 Address",
          "shadowsocks.dst_addr.ipv4",
          FT_IPv4,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_addr_domainname_len,
         {"Domain Name Length",
          "shadowsocks.dst_addr.domainname_len",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_addr_domainname,
         {"Domain Name",
          "shadowsocks.dst_addr.domainname",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_addr_ipv6,
         {"IPv6 Address",
          "shadowsocks.dst_addr.ipv6",
          FT_IPv6,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_dst_port,
         {"Destination Port",
          "shadowsocks.dst_port",
          FT_UINT16,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
    };
    /* Subtree Arrays */
    static int *ett[] = {
        &ett_ss,
        &ett_cipher_ctx,
        &ett_cipher_ctx_cipher};
    /* Register */
    proto_register_field_array(proto_ss, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    {
        ws_error("Failed to initialize ciphers");
        exit(-1);
    }

    ss_cipher_ctx = wmem_new0(wmem_file_scope(), ss_cipher_ctx_t);
    ss_crypto->ctx_init(ss_crypto->cipher, ss_cipher_ctx);
    ss_buf = wmem_new0(wmem_file_scope(), ss_buffer_t);
    ss_balloc(ss_buf, BUF_SIZE);

    ss_frag = 0;

    pkt_type_map = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    nonce_map = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    // salts = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    pkt_order_list = wmem_list_new(wmem_file_scope());
}

void ss_cleanup_routine(void)
{
    if (ss_cipher_ctx != NULL)
    {
        ss_crypto->ctx_release(ss_cipher_ctx);
        wmem_free(wmem_file_scope(), ss_cipher_ctx);
    }

    if (ss_buf != NULL)
    {
        ss_bfree(ss_buf);
        wmem_free(wmem_file_scope(), ss_buf);
    }

    wmem_free(wmem_file_scope(), pkt_type_map);
    wmem_free(wmem_file_scope(), nonce_map);
    // wmem_free(wmem_file_scope(), salts);
    wmem_free(wmem_file_scope(), pkt_order_list);
}

/********** Conversation **********/
ss_conv_data_t *get_ss_conv_data(conversation_t *conversation, const int proto)
{
    ss_conv_data_t *conv_data;

    conv_data = (ss_conv_data_t *)conversation_get_proto_data(conversation, proto);
    if (conv_data != NULL)
        return conv_data;

    conv_data = wmem_new0(wmem_file_scope(), ss_conv_data_t);
    // TODO: Initialize the fields

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
 * @param ctx cipher context
 * @param p plaintext (output)
 * @param c ciphertext
 * @param n nonce
 * @param plen plaintext length (output)
 * @param clen ciphertext length
 * @return 0 on success and an error code otherwise
 */
int ss_aead_decrypt(ss_cipher_ctx_t *ctx, uint8_t *p, uint8_t *c, uint8_t *n, size_t *plen, size_t clen)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    size_t nlen = ctx->cipher->nonce_len;
    size_t tlen = ctx->cipher->tag_len;
    uint8_t *len_buf = wmem_alloc0(wmem_file_scope(), 2 + tlen);
    size_t chunk_len;
    uint8_t *n_copy = wmem_memdup(wmem_file_scope(), n, nlen);

    if (clen <= 2 * tlen + CHUNK_SIZE_LEN)
        return RET_CRYPTO_NEED_MORE;

    /* Decrypt Length */
    err = gcry_cipher_setiv(ctx->cipher->hd, n_copy, nlen);
    if (err)
    {
        ws_critical("Failed to set IV: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    // NOTE: The `outsize` should always be expected length + tag length
    err = gcry_cipher_decrypt(ctx->cipher->hd, len_buf, 2 + tlen, c, CHUNK_SIZE_LEN + tlen);
    if (err)
    {
        ws_critical("Failed to decrypt length: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }

    if (plen == NULL)
        plen = wmem_new0(wmem_file_scope(), size_t);
    *plen = load16_be(len_buf);
    *plen = *plen & CHUNK_SIZE_MASK;

    if (*plen == 0)
    {
        ws_critical("Invalid message length decoded: %lu", *plen);
        return RET_CRYPTO_ERROR;
    }

    chunk_len = 2 * tlen + CHUNK_SIZE_LEN + *plen;

    if (clen < chunk_len)
    {
        return RET_CRYPTO_NEED_MORE;
    }

    sodium_increment(n_copy, nlen);

    /* Decrypt Content */
    err = gcry_cipher_setiv(ctx->cipher->hd, n_copy, nlen);
    if (err)
    {
        ws_critical("Failed to set IV: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    err = gcry_cipher_decrypt(ctx->cipher->hd, p, *plen + tlen, c + CHUNK_SIZE_LEN + tlen, *plen + tlen);
    if (err)
    {
        ws_critical("Failed to decrypt content: %s", gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    sodium_increment(n_copy, nlen);

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

    memset(cipher_ctx->nonce, 0, cipher_ctx->cipher->nonce_len);

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
 * @return Length of the key
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
        ws_error("Failed to initialize the MD5 context: %s", gcry_strerror(err));
        exit(-1);
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
    {
        cipher->key_len = ss_crypto_derive_key(pass, cipher->key, supported_aead_ciphers_key_size[method]);
    }

    if (cipher->key_len == 0)
    {
        ws_error("Failed to generate key and nonce");
        exit(-1);
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

int get_prev_pkt_type(wmem_list_frame_t *frame)
{
    wmem_list_frame_t *prev_frame;
    uint32_t *prev_pinfo_num;
    int *prev_pkt_type;

    if (wmem_list_count(pkt_order_list) == 0)
    {
        ws_error("`pkt_order_list` is empty");
        exit(-1);
    }

    prev_frame = wmem_list_frame_prev(frame);
    if (prev_frame == NULL)
    { // Head
        // NOTE: Return PKT_TYPE_UNSET to indicate no previous packet.
        return PKT_TYPE_UNSET;
    }
    prev_pinfo_num = (uint32_t *)wmem_list_frame_data(prev_frame);
    if (prev_pinfo_num == NULL)
    {
        ws_error("`prev_pinfo_num` is NULL");
        exit(-1);
    }
    prev_pkt_type = (int *)wmem_map_lookup(pkt_type_map, prev_pinfo_num);
    if (prev_pkt_type == NULL)
    {
        ws_error("`prev_pkt_type` is NULL");
        exit(-1);
    }

    return *prev_pkt_type;
}

/**
 * @brief Look up the nonce of the previous packet.
 *  Consider the case where the previous packet is fragmented.
 */
void get_nonce(uint32_t pinfo_num, uint8_t *nonce)
{
    uint32_t *pinfo_num_copy = wmem_memdup(wmem_file_scope(), &pinfo_num, sizeof(uint32_t));
    size_t nonce_len = ss_cipher_ctx->cipher->nonce_len;
    wmem_list_frame_t *cur_frame, *prev_frame;
    uint32_t *prev_pinfo_num;
    uint8_t *prev_nonce, *nonce_copy;

    nonce = (uint8_t *)wmem_map_lookup(nonce_map, pinfo_num_copy);
    if (nonce != NULL)
        return;
    nonce = wmem_alloc0(wmem_file_scope(), nonce_len);

    cur_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    if (cur_frame == NULL)
        wmem_list_append(pkt_order_list, pinfo_num_copy);
    cur_frame = wmem_list_find_custom(pkt_order_list, pinfo_num_copy, (GCompareFunc)cmp_list_frame_uint_data);
    prev_frame = wmem_list_frame_prev(cur_frame);

    /* Search backward until a nonce is found or reach the head of the list */
    while (prev_frame != NULL)
    {
        prev_pinfo_num = (uint32_t *)wmem_list_frame_data(prev_frame);
        if (prev_pinfo_num == NULL)
        {
            ws_error("`prev_pinfo_num` is NULL");
            exit(-1);
        }
        prev_nonce = (uint8_t *)wmem_map_lookup(nonce_map, prev_pinfo_num);
        /* If last nonce is found, return the incremented value */
        if (prev_nonce != NULL)
        {
            memcpy(nonce, prev_nonce, ss_cipher_ctx->cipher->nonce_len);
            sodium_increment(nonce, ss_cipher_ctx->cipher->nonce_len);
            sodium_increment(nonce, ss_cipher_ctx->cipher->nonce_len);
            /* Save the nonce for the current packet */
            nonce_copy = wmem_memdup(wmem_file_scope(), nonce, nonce_len);
            wmem_map_insert(nonce_map, pinfo_num_copy, nonce_copy);
            return;
        }
        prev_frame = wmem_list_frame_prev(prev_frame);
    }

    /* If no nonce is found, return the initial value */
    memset(nonce, 0, ss_cipher_ctx->cipher->nonce_len);
    /* Save the nonce for the current packet */
    nonce_copy = wmem_memdup(wmem_file_scope(), nonce, nonce_len);
    wmem_map_insert(nonce_map, pinfo_num_copy, nonce_copy);
}

/********** Debugging **********/
void debug_print_uint_key_int_value(const void *key, const void *value, void *user_data _U_)
{
    printf("  - %u: %d\n", *(uint32_t *)key, *(int *)value);
}

void debug_print_uint_key_uint_value(const void *key, const void *value, void *user_data _U_)
{
    printf("  - %u: %u\n", *(uint32_t *)key, *(uint32_t *)value);
}

void debug_print_uint_key_uint8_array_value(const void *key, const void *value, void *user_data _U_)
{
    printf("  - %u: ", *(uint32_t *)key);
    for (size_t i = 0; i < 16; i++)
    {
        printf("%02x", ((uint8_t *)value)[i]);
    }
    printf("\n");
}

void debug_print_hash_map(wmem_map_t *hash_map, const char *var_name, PrintFunc print_func)
{
    printf("[DEBUG] %s:\n", var_name);
    wmem_map_foreach(hash_map, (GHFunc)print_func, NULL);
}

void debug_print_list(wmem_list_t *list, const char *var_name)
{
    printf("[DEBUG] %s: HEAD - ", var_name);
    wmem_list_frame_t *frame;
    for (frame = wmem_list_head(list); frame != NULL; frame = wmem_list_frame_next(frame))
    {
        printf("%u - ", *(uint32_t *)wmem_list_frame_data(frame));
    }
    printf("TAIL\n");
}

void debug_print_uint8_array(const uint8_t *array, size_t len, const char *var_name)
{
    printf("[DEBUG] %s: ", var_name);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", array[i]);
    }
}

void debug_print_tvb(tvbuff_t *tvb, const char *var_name)
{
    printf("[DEBUG] %s: ", var_name);
    for (size_t i = 0; i < tvb_captured_length(tvb); i++)
    {
        printf("%02x", tvb_get_uint8(tvb, i));
    }
    printf("\n");
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
