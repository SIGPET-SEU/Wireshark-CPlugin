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
#ifndef SS_DEBUG
#define SS_DEBUG 0
#endif

#include "config.h"

#include <wireshark.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/wmem_scopes.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>

#ifdef _WIN32
// Windows-specific headers and definitions
#include <winsock2.h>
#include <ws2tcpip.h>
#else
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

/********** Reassembly Info **********/
static reassembly_table proto_ss_streaming_reassembly_table;

/********** Preferences **********/
static const char *pref_password = "";
static int pref_cipher = AEAD_CIPHER_CHACHA20POLY1305IETF;
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

/********** Crypto **********/
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
ss_crypto_t *ss_crypto;

/**************************************************/
/*                   Dissectors                   */
/**************************************************/
int dissect_ss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *cipher_ctx_ti, *cipher_ctx_cipher_ti;
    proto_tree *ss_tree, *cipher_ctx_tree, *cipher_ctx_cipher_tree;
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    bool is_from_server;
    ss_cipher_ctx_t *cipher_ctx;

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Direction ***/
    /* NOTE: In a complete capture, the salt from the client should be the first packet.
     * But it is not possible to distinguish that the salt is from server or client.
     * The only method is to check whether there is a relay header after the salt later.
     * So now we just assume that the first packet is salt from the client.
     */
    if (conv_data->server_addr->data == NULL)
        copy_address(conv_data->server_addr, &pinfo->dst);
    is_from_server = addresses_equal(&pinfo->src, conv_data->server_addr);
    cipher_ctx = is_from_server ? conv_data->server_cipher_ctx : conv_data->client_cipher_ctx;

    /*** Column Info & Protocol Tree ***/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Shadowsocks");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_ss, tvb, 0, -1, ENC_NA);
    ss_tree = proto_item_add_subtree(ti, ett_ss);
    /* Cipher context */
    cipher_ctx_ti = proto_tree_add_item(ss_tree, hf_cipher_ctx, tvb, 0, 0, ENC_NA);
    proto_item_set_text(cipher_ctx_ti, "Cipher Context");
    cipher_ctx_tree = proto_item_add_subtree(cipher_ctx_ti, ett_cipher_ctx);
    /* Cipher */
    cipher_ctx_cipher_ti = proto_tree_add_item(cipher_ctx_tree, hf_cipher_ctx_cipher, tvb, 0, 0, ENC_NA);
    proto_item_set_text(cipher_ctx_cipher_ti, "Cipher");
    cipher_ctx_cipher_tree = proto_item_add_subtree(cipher_ctx_cipher_ti, ett_cipher_ctx_cipher);
    proto_tree_add_int(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_method, tvb, 0, 0, cipher_ctx->cipher->method);
    proto_tree_add_string(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_password, tvb, 0, 0, pref_password);
    proto_tree_add_bytes_with_length(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_key, tvb, 0, 0, cipher_ctx->cipher->key, cipher_ctx->cipher->key_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_nonce_len, tvb, 0, 0, cipher_ctx->cipher->nonce_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_key_len, tvb, 0, 0, cipher_ctx->cipher->key_len);
    proto_tree_add_uint(cipher_ctx_cipher_tree, hf_cipher_ctx_cipher_tag_len, tvb, 0, 0, cipher_ctx->cipher->tag_len);

    tcp_dissect_pdus(tvb, pinfo, ss_tree, true,
                     !cipher_ctx->init
                         ? cipher_ctx->cipher->key_len
                         : CHUNK_SIZE_LEN + cipher_ctx->cipher->tag_len,
                     get_ss_message_len, dissect_ss_message, NULL);

    return tvb_captured_length(tvb);
}

/**
 * @brief Get the length of a Shadowsocks message. There are several branches:
 *  1. The message is already dissected. Just return the length stored in the message info.
 *  2. The message is not dissected yet.
 *    - If it is a salt, return the length of the salt.
 *    - Otherwise, decrypt the payload length with fixed length.
 */
unsigned get_ss_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
    ss_packet_info_t *pkt;
    ss_message_info_t *msg;
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    bool is_from_server;
    ss_cipher_ctx_t *cipher_ctx;
    uint32_t nlen, tlen, mlen;
    gcry_error_t err;
    uint8_t *encrypted_data;
    uint8_t *len_buf;

    /*** Already Dissected Packets ***/
    if (PINFO_FD_VISITED(pinfo))
    {
        /*** Lookup Message Info ***/
        pkt = (ss_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ss, 0);
        msg = pkt ? pkt->messages : NULL;
        while (msg)
        {
            if (msg->id == offset + tvb_raw_offset(tvb))
                return msg->cipher_len;
            msg = msg->next;
        }
        /* Two cases:
         * 1. The message info is not stored properly when decrypting. (Should not happen)
         * 2. The message is incomplete and the dissection will be done later. (It's OK)
         */
        return 0;
    }

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Direction ***/
    if (conv_data->server_addr->data == NULL)
    { /* Should not happen */
        ws_critical("[%u] %s: Server address is NULL", pinfo->num, __func__);
        return 1;
    }
    is_from_server = addresses_equal(&pinfo->src, conv_data->server_addr);
    cipher_ctx = is_from_server ? conv_data->server_cipher_ctx : conv_data->client_cipher_ctx;
    nlen = cipher_ctx->cipher->nonce_len;
    tlen = cipher_ctx->cipher->tag_len;

    /*** Length of Salt ***/
    if (!cipher_ctx->init)
        return cipher_ctx->cipher->key_len;

    /*** Length of Encrypted Data ***/
    if (tvb_captured_length_remaining(tvb, offset) < (int)(CHUNK_SIZE_LEN + tlen))
    { /* Should not happen */
        ws_critical("[%u] %s: %u < CHUNK_SIZE_LEN(%d) + tlen(%u)", pinfo->num, __func__, tvb_captured_length_remaining(tvb, offset), CHUNK_SIZE_LEN, tlen);
        return 1;
    }
    err = ss_aead_cipher_ctx_set_key(cipher_ctx);
    if (err)
    {
        ws_critical("[%u] %s: Failed to set key: %s", pinfo->num, __func__, gcry_strerror(err));
        return 1;
    }
    err = gcry_cipher_setiv(cipher_ctx->cipher->hd, cipher_ctx->nonce, nlen);
    if (err)
    {
        ws_critical("[%u] %s: Failed to set nonce: %s", pinfo->num, __func__, gcry_strerror(err));
        return 1;
    }

    /* Decryption */
    len_buf = (uint8_t *)wmem_alloc0(wmem_file_scope(), CHUNK_SIZE_LEN + tlen);
    encrypted_data = (uint8_t *)tvb_memdup(wmem_file_scope(), tvb, offset, CHUNK_SIZE_LEN + tlen);
    err = gcry_cipher_decrypt(cipher_ctx->cipher->hd, len_buf, CHUNK_SIZE_LEN + tlen, encrypted_data, CHUNK_SIZE_LEN + tlen);
    wmem_free(wmem_file_scope(), encrypted_data);
    if (err)
    {
        ws_critical("[%u] %s: Failed to decode length: %s", pinfo->num, __func__, gcry_strerror(err));
        return 1;
    }
    /* Big-endian decoding */
    mlen = load16_be(len_buf);
    wmem_free(wmem_file_scope(), len_buf);
    mlen = mlen & CHUNK_SIZE_MASK;
    if (mlen == 0)
    {
        ws_critical("[%u] %s: Invalid message length decoded: %u", pinfo->num, __func__, mlen);
        return 1;
    }

    // NOTE: encrypted payload length(2) | length tag(tlen) | encrypted payload(plen) | payload tag(tlen)
    return (unsigned)(CHUNK_SIZE_LEN + tlen + mlen + tlen);
}

int dissect_ss_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    ss_packet_info_t *pkt;
    ss_message_info_t *msg;
    tvbuff_t *decrypted_tvb;
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    bool is_from_server;
    ss_cipher_ctx_t *cipher_ctx;

    /*** Already Dissected Packets ***/
    if (PINFO_FD_VISITED(pinfo))
    {
        /*** Lookup Message Info ***/
        pkt = (ss_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ss, 0);
        msg = pkt ? pkt->messages : NULL;
        while (msg)
        {
            if (msg->id == tvb_raw_offset(tvb))
                break;
            msg = msg->next;
        }

        if (!msg)
        { /* Should not happen */
            ws_critical("[%u] %s: Failed to find message info at offset %d", pinfo->num, __func__, tvb_raw_offset(tvb));
            return -1;
        }

        if (msg->type == SS_RELAY_HEADER || msg->type == SS_STREAM_DATA)
        {
            decrypted_tvb = tvb_new_child_real_data(tvb, msg->plain_data, msg->data_len, msg->data_len);
            add_new_data_source(pinfo, decrypted_tvb, "Decrypted Shadowsocks Data");
        }

        switch (msg->type)
        {
        case SS_UNKNOWN:
            col_append_str(pinfo->cinfo, COL_INFO, "[Unknown]");
            break;
        case SS_SALT:
            dissect_ss_salt(tvb, pinfo, tree, NULL);
            break;
        case SS_RELAY_HEADER:
            dissect_ss_relay_header(decrypted_tvb, pinfo, tree, NULL);
            break;
        case SS_STREAM_DATA:
            dissect_ss_stream_data(decrypted_tvb, pinfo, tree, NULL);
            break;
        default:
            ws_critical("[%u] %s: Unknown message type: %d", pinfo->num, __func__, msg->type);
            break;
        }

        return tvb_captured_length(tvb);
    }

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Direction ***/
    if (conv_data->server_addr->data == NULL)
    { /* Should not happen */
        ws_critical("[%u] %s: Server address is NULL", pinfo->num, __func__);
        return -1;
    }
    is_from_server = addresses_equal(&pinfo->src, conv_data->server_addr);
    cipher_ctx = is_from_server ? conv_data->server_cipher_ctx : conv_data->client_cipher_ctx;

    /*** Call Dissectors ***/
    if (!cipher_ctx->init)
        return dissect_ss_salt(tvb, pinfo, tree, NULL);
    else
        return dissect_ss_encrypted_data(tvb, pinfo, tree, NULL);
}

int dissect_ss_encrypted_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    bool is_from_server;
    ss_cipher_ctx_t *cipher_ctx;
    uint8_t *nonce_copy;
    uint8_t *encrypted_data;
    int err;
    uint8_t *plaintext;
    uint32_t *plen;
    ss_packet_info_t *pkt;
    ss_message_info_t *msg;
    ss_message_info_t **pmsgs;
    tvbuff_t *decrypted_tvb;
    int dissector_ret;

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Direction ***/
    if (conv_data->server_addr->data == NULL)
    { /* Should not happen */
        ws_critical("[%u] %s: Server address is NULL", pinfo->num, __func__);
        return -1;
    }
    is_from_server = addresses_equal(&pinfo->src, conv_data->server_addr);

    cipher_ctx = is_from_server ? conv_data->server_cipher_ctx : conv_data->client_cipher_ctx;
    if (!cipher_ctx->init)
    { /* Should not happen */
        ws_critical("[%u] %s: Cipher context is not initialized", pinfo->num, __func__);
        return -1;
    }

    /*** Decryption ***/
    nonce_copy = (uint8_t *)wmem_memdup(wmem_file_scope(), cipher_ctx->nonce, cipher_ctx->cipher->nonce_len);
    encrypted_data = (uint8_t *)tvb_memdup(wmem_file_scope(), tvb, 0, tvb_captured_length(tvb));
    err = ss_crypto->decrypt(cipher_ctx,
                             &plaintext,
                             encrypted_data,
                             cipher_ctx->nonce,
                             &plen,
                             tvb_captured_length(tvb));
    wmem_free(wmem_file_scope(), encrypted_data);
    if (err == RET_CRYPTO_ERROR)
    {
        ws_critical("[%u] %s: Failed to decrypt", pinfo->num, __func__);
        // TODO: Clear the cipher context?
        return -1;
    }
    else if (err == RET_CRYPTO_NEED_MORE)
    {
#if SS_DEBUG
        ws_message("[%u] %s: Need more data", pinfo->num, __func__);
#endif
        // TODO
        return 0;
    }

    /*** Storage of Decrypted Data ***/
    pkt = (ss_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ss, 0);
    if (!pkt)
    {
        pkt = (ss_packet_info_t *)wmem_new0(wmem_file_scope(), ss_packet_info_t);
        pkt->is_from_server = is_from_server;
        pkt->messages = NULL;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ss, 0, pkt);
    }

    msg = wmem_new0(wmem_file_scope(), ss_message_info_t);
    msg->plain_data = wmem_memdup(wmem_file_scope(), plaintext, *plen);
    msg->data_len = *plen;
    msg->cipher_len = tvb_captured_length(tvb);
    msg->id = tvb_raw_offset(tvb);
    msg->type = (!is_from_server && !conv_data->relay_header_dissection_done) ? SS_RELAY_HEADER : SS_STREAM_DATA;
    msg->salt = (uint8_t *)wmem_memdup(wmem_file_scope(), cipher_ctx->salt, cipher_ctx->cipher->key_len);
    msg->skey = (uint8_t *)wmem_memdup(wmem_file_scope(), cipher_ctx->skey, cipher_ctx->cipher->key_len);
    msg->nonce = (uint8_t *)wmem_memdup(wmem_file_scope(), nonce_copy, cipher_ctx->cipher->nonce_len);
    wmem_free(wmem_file_scope(), nonce_copy);
    /* Append to the tail */
    msg->next = NULL;
    pmsgs = &pkt->messages;
    while (*pmsgs)
        pmsgs = &(*pmsgs)->next;
    *pmsgs = msg;

    /*** Dissection ***/
    decrypted_tvb = tvb_new_child_real_data(tvb, plaintext, *plen, *plen);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Shadowsocks Data");
    if (msg->type == SS_RELAY_HEADER)
    {
        dissector_ret = dissect_ss_relay_header(decrypted_tvb, pinfo, tree, NULL);
        if (dissector_ret == -1)
        {
            ws_critical("[%u] %s: Failed to dissect relay header", pinfo->num, __func__);
            // TODO
            return -1;
        }
        conv_data->relay_header_dissection_done = true;
    }
    else if (msg->type == SS_STREAM_DATA)
        dissector_ret = dissect_ss_stream_data(decrypted_tvb, pinfo, tree, NULL);

    return tvb_captured_length(tvb);
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
int dissect_ss_salt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    bool is_from_server;
    ss_cipher_ctx_t *cipher_ctx;
    int err;
    ss_packet_info_t *pkt;
    ss_message_info_t *msg;
    ss_message_info_t **pmsgs;

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /*** Direction ***/
    if (conv_data->server_addr->data == NULL)
    { /* Should not happen */
        ws_critical("[%u] %s: Server address is NULL", pinfo->num, __func__);
        return -1;
    }
    is_from_server = addresses_equal(&pinfo->src, conv_data->server_addr);

    cipher_ctx = is_from_server ? conv_data->server_cipher_ctx : conv_data->client_cipher_ctx;
    if (!cipher_ctx->init)
    { /* The first time of dissection */
        tvb_memcpy(tvb, cipher_ctx->salt, 0, ss_crypto->cipher->key_len);
        err = ss_aead_cipher_ctx_set_key(cipher_ctx);
        if (err)
        {
            ws_critical("[%u] %s: Failed to set key: %s", pinfo->num, __func__, gcry_strerror(err));
            return -1;
        }
        cipher_ctx->init = true;

        /*** Storage ***/
        pkt = (ss_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ss, 0);
        if (!pkt)
        {
            pkt = (ss_packet_info_t *)wmem_new0(wmem_file_scope(), ss_packet_info_t);
            pkt->is_from_server = is_from_server;
            pkt->messages = NULL;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ss, 0, pkt);
        }

        msg = wmem_new0(wmem_file_scope(), ss_message_info_t);
        msg->plain_data = (uint8_t *)wmem_memdup(wmem_file_scope(), cipher_ctx->salt, cipher_ctx->cipher->key_len);
        msg->data_len = cipher_ctx->cipher->key_len;
        msg->cipher_len = cipher_ctx->cipher->key_len;
        msg->id = tvb_raw_offset(tvb);
        msg->type = SS_SALT;
        msg->salt = (uint8_t *)wmem_memdup(wmem_file_scope(), cipher_ctx->salt, cipher_ctx->cipher->key_len);
        msg->skey = (uint8_t *)wmem_memdup(wmem_file_scope(), cipher_ctx->skey, cipher_ctx->cipher->key_len);
        msg->nonce = NULL;
        /* Append to the tail */
        msg->next = NULL;
        pmsgs = &pkt->messages;
        while (*pmsgs)
            pmsgs = &(*pmsgs)->next;
        *pmsgs = msg;
    }

    /*** Column Info & Protocol Tree ***/
    col_append_str(pinfo->cinfo, COL_INFO, "[Salt]");
    proto_tree_add_item(tree, hf_salt, tvb, 0, cipher_ctx->cipher->key_len, ENC_NA);

    return cipher_ctx->cipher->key_len;
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

    /*** Column Info & Protocol Tree ***/
    col_append_str(pinfo->cinfo, COL_INFO, "[Relay Header]");

    /*** Protocol Tree ***/
    atyp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_atyp, tvb, offset++, 1, ENC_BIG_ENDIAN);
    switch (atyp & ADDRTYPE_MASK)
    {
    case RELAY_HEADER_ATYP_IPV4:
    {
        // NOTE: Variable declaration must be in the block
        ws_in4_addr in4_addr = tvb_get_ipv4(tvb, offset);
        host_len = sizeof(struct in_addr);
        proto_tree_add_ipv4(tree, hf_dst_addr_ipv4, tvb, offset, host_len, in4_addr);
        break;
    }
    case RELAY_HEADER_ATYP_DOMAINNAME:
        host_len = (int)tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_dst_addr_domainname_len, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_dst_addr_domainname, tvb, offset, host_len, ENC_ASCII);
        break;
    case RELAY_HEADER_ATYP_IPV6:
    {
        // NOTE: Variable declaration must be in the block
        ws_in6_addr *in6_addr = wmem_new0(wmem_file_scope(), ws_in6_addr);
        tvb_get_ipv6(tvb, offset, in6_addr);
        host_len = sizeof(struct in6_addr);
        proto_tree_add_ipv6(tree, hf_dst_addr_ipv6, tvb, offset, host_len, in6_addr);
        break;
    }
    default:
        // TODO: expert item
        ws_critical("[%u] Invalid ATYP value: %d", pinfo->num, atyp);
        return -1;
    }
    offset += host_len;
    proto_tree_add_item(tree, hf_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

int dissect_ss_stream_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    ss_conv_data_t *conv_data;
    dissector_handle_t tls_handle;
    // dissector_handle_t http_handle;

    /*** Column Info & Protocol Tree ***/
    col_append_str(pinfo->cinfo, COL_INFO, "[Stream Data]");

    /*** Conversation ***/
    conversation = find_or_create_conversation(pinfo);
    conv_data = (ss_conv_data_t *)get_ss_conv_data(conversation, proto_ss);

    /* Call subdissectors */
    tls_handle = find_dissector("tls");
    reassemble_streaming_data_and_call_subdissector(tvb, pinfo, 0,
                                                    tvb_captured_length_remaining(tvb, 0),
                                                    tree, proto_tree_get_parent_tree(tree),
                                                    proto_ss_streaming_reassembly_table,
                                                    conv_data->reassembly_info,
                                                    get_virtual_frame_num64(tvb, pinfo, 0),
                                                    tls_handle,
                                                    proto_tree_get_parent_tree(tree),
                                                    NULL,
                                                    "Shadowsocks",
                                                    &msg_frag_items, hf_msg_body_segment);
    // http_handle = find_dissector("http");
    // call_dissector(http_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/**************************************************/
/*                   Registers                    */
/**************************************************/
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
    /* Subtree arrays */
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

/**************************************************/
/*                    Routines                    */
/**************************************************/
void ss_init_routine(void)
{
    ss_crypto = ss_crypto_init(pref_password, NULL, supported_aead_ciphers[pref_cipher]);
    if (ss_crypto == NULL)
        ws_critical("Failed to initialize ciphers");
}

void ss_cleanup_routine(void)
{
    if (ss_crypto)
        wmem_free(wmem_file_scope(), ss_crypto);
}

/**************************************************/
/*                  Conversation                  */
/**************************************************/
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

    conv_data->relay_header_dissection_done = false;

    conv_data->client_cipher_ctx = wmem_new0(wmem_file_scope(), ss_cipher_ctx_t);
    conv_data->server_cipher_ctx = wmem_new0(wmem_file_scope(), ss_cipher_ctx_t);
    ss_crypto->ctx_init(ss_crypto->cipher, conv_data->client_cipher_ctx);
    ss_crypto->ctx_init(ss_crypto->cipher, conv_data->server_cipher_ctx);

    conv_data->reassembly_info = streaming_reassembly_info_new();

    conversation_add_proto_data(conversation, proto, conv_data);
    return conv_data;
}

/**************************************************/
/*                     Crypto                     */
/**************************************************/
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
int ss_aead_decrypt(ss_cipher_ctx_t *cipher_ctx, uint8_t **p, uint8_t *c, uint8_t *n, uint32_t **plen, uint32_t clen)
{
    gcry_cipher_hd_t hd;
    gcry_error_t err;
    uint32_t mlen, nlen, tlen;
    uint8_t *len_buf;
    uint32_t chunk_len;
    uint8_t *tmp_p;

    hd = cipher_ctx->cipher->hd;
    nlen = cipher_ctx->cipher->nonce_len;
    tlen = cipher_ctx->cipher->tag_len;

    if (!cipher_ctx->init)
    {
        err = ss_aead_cipher_ctx_set_key(cipher_ctx);
        if (err)
        {
            ws_critical("%s: Cipher context is not initialized and failed to set key: %s", __func__, gcry_strerror(err));
            return RET_CRYPTO_ERROR;
        }
        cipher_ctx->init = true;
    }

    if (clen <= 2 * tlen + CHUNK_SIZE_LEN)
    {
#if SS_DEBUG
        ws_message("%s: %u <= 2 * tlen(%u) + CHUNK_SIZE_LEN(%d)", __func__, clen, tlen, CHUNK_SIZE_LEN);
#endif
        return RET_CRYPTO_NEED_MORE;
    }

    /*** Decryption of Payload Length ***/
    err = ss_aead_cipher_ctx_set_key(cipher_ctx);
    if (err)
    {
        ws_critical("%s: Failed to set key: %s", __func__, gcry_strerror(err));
        return 1;
    }
    err = gcry_cipher_setiv(hd, n, nlen);
    if (err)
    {
        ws_critical("%s: Failed to set nonce: %s", __func__, gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }

    len_buf = (uint8_t *)wmem_alloc0(wmem_file_scope(), CHUNK_SIZE_LEN + tlen);
    // NOTE: The `outsize` should always be expected length + tag length
    err = gcry_cipher_decrypt(hd, len_buf, CHUNK_SIZE_LEN + tlen, c, CHUNK_SIZE_LEN + tlen);
    if (err)
    {
        ws_critical("%s: Failed to decode length: %s", __func__, gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    /* Big-endian decoding */
    mlen = load16_be(len_buf);
    wmem_free(wmem_file_scope(), len_buf);
    mlen = mlen & CHUNK_SIZE_MASK;
    if (mlen == 0)
    {
        ws_critical("%s: Invalid message length decoded: %u", __func__, mlen);
        return RET_CRYPTO_ERROR;
    }

    chunk_len = 2 * tlen + CHUNK_SIZE_LEN + mlen;
    if (clen < chunk_len)
    {
#if SS_DEBUG
        ws_message("%s: %u < 2 * tlen(%u) + CHUNK_SIZE_LEN(%d) + mlen(%u)", __func__, clen, tlen, CHUNK_SIZE_LEN, mlen);
#endif
        return RET_CRYPTO_NEED_MORE;
    }

    sodium_increment(n, nlen);

    /*** Decryption of Payload ***/
    err = ss_aead_cipher_ctx_set_key(cipher_ctx);
    if (err)
    {
        ws_critical("%s: Failed to set key: %s", __func__, gcry_strerror(err));
        return 1;
    }
    err = gcry_cipher_setiv(hd, n, nlen);
    if (err)
    {
        ws_critical("%s: Failed to set nonce: %s", __func__, gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }
    tmp_p = (uint8_t *)wmem_alloc0(wmem_file_scope(), mlen + tlen);
    err = gcry_cipher_decrypt(hd, tmp_p, mlen + tlen, c + CHUNK_SIZE_LEN + tlen, mlen + tlen);
    if (err)
    {
        ws_critical(" %s: Failed to decrypt payload: %s", __func__, gcry_strerror(err));
        return RET_CRYPTO_ERROR;
    }

    sodium_increment(n, nlen);

    *plen = (uint32_t *)wmem_memdup(wmem_file_scope(), &mlen, sizeof(uint32_t));
    *p = (uint8_t *)wmem_memdup(wmem_file_scope(), tmp_p, mlen);
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
                            const uint8_t *salt, uint32_t salt_len,
                            const uint8_t *ikm, uint32_t ikm_len,
                            const uint8_t *info, uint32_t info_len,
                            uint8_t *okm, uint32_t okm_len)
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

    if (cipher_ctx == NULL)
    {
        ws_critical("Cipher context is NULL");
        return GPG_ERR_NO_ERROR;
    }

    err = ss_crypto_hkdf(GCRY_MD_SHA1,
                         cipher_ctx->salt, cipher_ctx->cipher->key_len,
                         cipher_ctx->cipher->key, cipher_ctx->cipher->key_len,
                         (uint8_t *)SUBKEY_INFO, (uint32_t)strlen(SUBKEY_INFO),
                         cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err)
    {
        ws_critical("Failed to generate subkey: %s", gcry_strerror(err));
        return err;
    }

    err = gcry_cipher_setkey(cipher_ctx->cipher->hd, cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err)
    {
        ws_critical("Failed to set cipher key: %s", gcry_strerror(err));
        return err;
    }

    return err;
}

int ss_crypto_parse_key(const char *base64 _U_, uint8_t *key _U_, uint32_t key_len)
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
int ss_crypto_derive_key(const char *pass, uint8_t *key, uint32_t key_len)
{
    gcry_error_t err = GPG_ERR_NO_ERROR;
    unsigned int i, j;
    int addmd;
    gcry_md_hd_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    unsigned int mds = gcry_md_get_algo_dlen(GCRY_MD_MD5);
    uint32_t datal = (uint32_t)strlen((const char *)pass);

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
        ws_critical("Key parsing function not implemented");
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
                ws_critical("Failed to initialize cipher: %s", method);
                return NULL;
            }
            ss_crypto_t *crypto = wmem_new0(wmem_file_scope(), ss_crypto_t);
            ss_crypto_t tmp = {
                .cipher = cipher,
                .decrypt = &ss_aead_decrypt,
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
    if (cipher_ctx->cipher != NULL)
    {
        gcry_cipher_close(cipher_ctx->cipher->hd);
        cipher_ctx->cipher = NULL;
    }
    if (cipher_ctx)
        wmem_free(wmem_file_scope(), cipher_ctx);
}

/**************************************************/
/*                     Utils                      */
/**************************************************/
uint16_t load16_be(const void *s)
{
    const uint8_t *in = (const uint8_t *)s;
    return ((uint16_t)in[0] << 8) | ((uint16_t)in[1]);
}

void sodium_increment(unsigned char *n, const uint32_t nlen)
{
    uint32_t i = 0U;
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
        uint32_t label_len = (uint32_t)(hostname_len - (label - hostname));
        char *next_dot = strchr(label, '.');
        if (next_dot != NULL)
            label_len = (uint32_t)(next_dot - label);

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

/**************************************************/
/*                    Debugging                   */
/**************************************************/
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

    for (int i = 0; i < 16; i++)
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

void debug_print_uint8_array(const uint8_t *array, uint32_t len, const char *var_name)
{
    char buf[4096] = {0};
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "[DEBUG] %s: ", var_name);
    strcat(buf, tmp);

    for (uint32_t i = 0; i < len; i++)
    {
        snprintf(tmp, sizeof(tmp), "%02x", array[i]);
        strcat(buf, tmp);
    }
    ws_message("%s", buf);
}

void debug_print_tvb(tvbuff_t *tvb, const char *var_name)
{
    char buf[4096] = {0};
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "[DEBUG] %s: ", var_name);
    strcat(buf, tmp);

    for (uint32_t i = 0; i < tvb_captured_length(tvb); i++)
    {
        snprintf(tmp, sizeof(tmp), "%02x", tvb_get_guint8(tvb, i));
        strcat(buf, tmp);
    }
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
