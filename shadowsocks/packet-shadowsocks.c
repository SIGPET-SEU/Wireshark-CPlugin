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
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>

#include "packet-shadowsocks.h"

/********** Protocol Handles **********/
static int proto_shadowsocks;

/********** Dissector Handles **********/
static dissector_handle_t shadowsocks_handle;

/********** Header Fields **********/
/* Meta Cipher */
static int hf_shadowsocks_meta_cipher;
static int hf_shadowsocks_cipher_type;
static int hf_shadowsocks_password;
static int hf_shadowsocks_derived_key;
static int hf_shadowsocks_salt;
static int hf_shadowsocks_subkey;
static int hf_shadowsocks_nonce;
/* Address */
static int hf_shadowsocks_addr;
static int hf_shadowsocks_atyp;
static int hf_shadowsocks_addr_ipv4;
static int hf_shadowsocks_addr_domain_len;
static int hf_shadowsocks_addr_domain;
static int hf_shadowsocks_addr_ipv6;
static int hf_shadowsocks_port;

/********** Expert Fields **********/
static expert_field ei_shadowsocks_salt _U_;

/********** Subtree pointers **********/
static int ett_shadowsocks;
static int ett_shadowsocks_meta_cipher;
static int ett_shadowsocks_addr;

/********** Preferences **********/
/* Cipher preference */
static cipher_type_e pref_cipher_type = AEAD_AES_256_GCM;
static const char *pref_cipher_password = "";
static const enum_val_t pref_cipher_type_vals[] = {
    {"AEAD_AES_128_GCM", "aes-128-gcm", AEAD_AES_128_GCM},
    {"AEAD_AES_192_GCM", "aes-192-gcm", AEAD_AES_192_GCM},
    {"AEAD_AES_256_GCM", "aes-256-gcm", AEAD_AES_256_GCM},
    {"AEAD_CHACHA20_POLY1305", "chacha20-ietf-poly1305", AEAD_CHACHA20_POLY1305},
    {"AEAD_XCHACHA20_POLY1305", "xchacha20-ietf-poly1305", AEAD_XCHACHA20_POLY1305},
    {NULL, NULL, 0}};

/********** Global Variables **********/
static uint32_t cipher_key_size = AEAD_AES_256_GCM_KEY_LENGTH;
static uint32_t cipher_salt_size = AEAD_AES_256_GCM_KEY_LENGTH;
static uint32_t cipher_nonce_size = HPKE_AEAD_NONCE_LENGTH;
static uint32_t cipher_tag_size = 16;
static uint8_t cipher_derived_key[AEAD_MAX_KEY_LENGTH];
/* Hash tables (use pinfo->num as key) */
wmem_map_t *hash_table_stage;
wmem_map_t *hash_table_nonce;

void dissect_shadowsocks_stage_init(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, shadowsocks_conv_t *conv_data, proto_tree *shadowsocks_tree)
{
    proto_tree_add_item(shadowsocks_tree, hf_shadowsocks_salt, tvb, 0, cipher_salt_size, ENC_BIG_ENDIAN);
    if (!conv_data->shadowsocks_meta_cipher.is_salt_set)
    {
        conv_data->shadowsocks_meta_cipher.salt = tvb_memdup(wmem_file_scope(), tvb, 0, cipher_salt_size);
        conv_data->shadowsocks_meta_cipher.is_salt_set = true;
    }

    /* Initialize the cipher handle */
    if (!conv_data->shadowsocks_meta_cipher.is_handle_initialized)
    {
        init_shadowsocks_cipher_handle(&conv_data->shadowsocks_meta_cipher);
        conv_data->shadowsocks_meta_cipher.is_handle_initialized = true;
    }
}

void dissect_shadowsocks_stage_addr(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, shadowsocks_conv_t *conv_data, proto_tree *shadowsocks_tree)
{
    proto_item *addr_ti;
    proto_tree *addr_tree;

    addr_ti = proto_tree_add_item(shadowsocks_tree, hf_shadowsocks_addr, tvb, 0, 0, ENC_NA);
    proto_item_set_text(addr_ti, "[Address]");
    addr_tree = proto_item_add_subtree(addr_ti, ett_shadowsocks_addr);

    /* Address type */
    proto_tree_add_item(addr_tree, hf_shadowsocks_atyp, conv_data->next_tvb, 0, 1, ENC_BIG_ENDIAN);
    switch (tvb_get_uint8(conv_data->next_tvb, 0))
    {
    case 0x01:
        // 0x01: IPv4 address
        proto_tree_add_item(addr_tree, hf_shadowsocks_addr_ipv4, conv_data->next_tvb, 1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(addr_tree, hf_shadowsocks_port, conv_data->next_tvb, 5, 2, ENC_BIG_ENDIAN);
        break;
    case 0x03:
        // 0x03: Domain name
        proto_tree_add_item(addr_tree, hf_shadowsocks_addr_domain_len, conv_data->next_tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(addr_tree, hf_shadowsocks_addr_domain, conv_data->next_tvb, 2, tvb_get_uint8(conv_data->next_tvb, 1), ENC_ASCII);
        proto_tree_add_item(addr_tree, hf_shadowsocks_port, conv_data->next_tvb, 2 + tvb_get_uint8(conv_data->next_tvb, 1), 2, ENC_BIG_ENDIAN);
        break;
    case 0x04:
        // 0x04: IPv6 address
        proto_tree_add_item(addr_tree, hf_shadowsocks_addr_ipv6, conv_data->next_tvb, 1, 16, ENC_BIG_ENDIAN);
        proto_tree_add_item(addr_tree, hf_shadowsocks_port, conv_data->next_tvb, 17, 2, ENC_BIG_ENDIAN);
        break;
    default:
        report_failure("Unknown address type: %u", tvb_get_uint8(conv_data->next_tvb, 0));
        break;
    }
}

void decrypt_shadowsocks_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, shadowsocks_conv_t *conv_data, proto_tree *shadowsocks_tree _U_, proto_tree *meta_cipher_tree, uint32_t *pkt_idx)
{
    uint8_t *cur_nonce;
    uint8_t *tvb_copy = tvb_memdup(wmem_file_scope(), tvb, 0, tvb_captured_length(tvb));
    uint8_t *decrypted_payload = wmem_alloc0(wmem_file_scope(), tvb_captured_length(tvb));
    uint32_t *real_size = wmem_new0(wmem_file_scope(), uint32_t);
    tvbuff_t *next_tvb;

    if (!conv_data->shadowsocks_meta_cipher.is_handle_initialized)
    {
        report_failure("Failed to dissect the packet: cipher handle is not initialized");
        return;
    }

    /*** Nonce ***/
    cur_nonce = get_shadowsocks_nonce(pkt_idx, conv_data->shadowsocks_meta_cipher.nonce);
    proto_tree_add_bytes(meta_cipher_tree, hf_shadowsocks_nonce, tvb, 0, cipher_nonce_size, cur_nonce);

    /*** Decryption ***/
    decrypt_payload(conv_data->shadowsocks_meta_cipher.cipher_hd, tvb_copy, cur_nonce, decrypted_payload, real_size);

    /*** Add the decrypted payload to a new tab ***/
    next_tvb = tvb_new_child_real_data(tvb, decrypted_payload, *real_size, *real_size);
    add_new_data_source(pinfo, next_tvb, "Decrypted Shadowsocks");
    /* Store to conv_data */
    conv_data->next_tvb = next_tvb;
}

/**
 * @brief Dissect the Shadowsocks packet.
 * @param tvb buffer containing the packet data
 * @param pinfo general packet information
 * @param tree protocol tree
 * @param data user data
 * @return the amount of data this dissector was able to dissect (which may or
 *  may not be the total captured packet as we return here)
 */
int dissect_shadowsocks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t *conversation;
    shadowsocks_conv_t *conv_data;

    proto_item *ti, *meta_cipher_ti, *expert_ti _U_;
    proto_tree *shadowsocks_tree, *meta_cipher_tree;

    uint32_t *pkt_idx = wmem_new0(wmem_file_scope(), uint32_t);
    *pkt_idx = pinfo->num;
    shadowsocks_server_stage_e *cur_stage = wmem_new0(wmem_file_scope(), shadowsocks_server_stage_e);

    /*** Conversation ***/
    /* Lookup the conversation or create a new one */
    conversation = find_or_create_conversation(pinfo);
    conv_data = get_shadowsocks_conv(conversation, proto_shadowsocks);
    /* Lookup and set the stage of the current packet */
    cur_stage = (shadowsocks_server_stage_e *)wmem_map_lookup(hash_table_stage, pkt_idx);
    if (!cur_stage)
    {
        shadowsocks_server_stage_e *tmp_stage = wmem_new0(wmem_file_scope(), shadowsocks_server_stage_e);
        *tmp_stage = STAGE_UNSET;
        wmem_map_insert(hash_table_stage, pkt_idx, tmp_stage);
    }
    cur_stage = (shadowsocks_server_stage_e *)wmem_map_lookup(hash_table_stage, pkt_idx);
    if (!cur_stage)
    {
        report_failure("Failed to lookup the stage of packet %u", *pkt_idx);
        return tvb_captured_length(tvb);
    }
    update_shadowsocks_stage(&conv_data->last_stage, cur_stage, tvb_captured_length(tvb));
    wmem_map_insert(hash_table_stage, pkt_idx, cur_stage);

    /*** Column Data ***/
    /* Set the Protocol column to the constant string of Shadowsocks */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Shadowsocks");
    col_clear(pinfo->cinfo, COL_INFO);

    /*** Protocol Tree ***/
    ti = proto_tree_add_item(tree, proto_shadowsocks, tvb, 0, -1, ENC_NA);
    shadowsocks_tree = proto_item_add_subtree(ti, ett_shadowsocks);
    /* Meta cipher*/
    if (conv_data->shadowsocks_meta_cipher.is_handle_initialized)
    {
        meta_cipher_ti = proto_tree_add_item(shadowsocks_tree, hf_shadowsocks_meta_cipher, tvb, 0, 0, ENC_NA);
        proto_item_set_text(meta_cipher_ti, "[Cipher Metadata]");
        meta_cipher_tree = proto_item_add_subtree(meta_cipher_ti, ett_shadowsocks_meta_cipher);
        proto_tree_add_uint(meta_cipher_tree, hf_shadowsocks_cipher_type, tvb, 0, 0, conv_data->shadowsocks_meta_cipher.cipher_type);
        proto_tree_add_string(meta_cipher_tree, hf_shadowsocks_password, tvb, 0, 0, conv_data->shadowsocks_meta_cipher.password);
        // FIXME: For `proto_tree_add_bytes`, setting `length` to 0 leads to `<MISSING>`
        proto_tree_add_bytes(meta_cipher_tree, hf_shadowsocks_derived_key, tvb, 0, cipher_key_size, conv_data->shadowsocks_meta_cipher.derived_key);
        if (conv_data->shadowsocks_meta_cipher.is_salt_set)
        {
            proto_tree_add_bytes(meta_cipher_tree, hf_shadowsocks_salt, tvb, 0, cipher_salt_size, conv_data->shadowsocks_meta_cipher.salt);
        }
        if (conv_data->shadowsocks_meta_cipher.is_handle_initialized)
        {
            proto_tree_add_bytes(meta_cipher_tree, hf_shadowsocks_subkey, tvb, 0, cipher_key_size, conv_data->shadowsocks_meta_cipher.subkey);
        }
    }

    switch (*cur_stage)
    {
    case STAGE_UNSET:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_UNSET]");
        break;
    case STAGE_UNKNOWN:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_UNKNOWN]");
        break;
    case STAGE_INIT:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_INIT]");
        dissect_shadowsocks_stage_init(tvb, pinfo, tree, data, conv_data, shadowsocks_tree);
        break;
    case STAGE_ADDR:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_ADDR]");
        decrypt_shadowsocks_packet(tvb, pinfo, tree, data, conv_data, shadowsocks_tree, meta_cipher_tree, pkt_idx);
        dissect_shadowsocks_stage_addr(tvb, pinfo, tree, data, conv_data, shadowsocks_tree);
        break;
    case STAGE_UDP_ASSOC:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_UDP_ASSOC]");
        decrypt_shadowsocks_packet(tvb, pinfo, tree, data, conv_data, shadowsocks_tree, meta_cipher_tree, pkt_idx);
        break;
    case STAGE_DNS:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_DNS]");
        decrypt_shadowsocks_packet(tvb, pinfo, tree, data, conv_data, shadowsocks_tree, meta_cipher_tree, pkt_idx);
        break;
    case STAGE_CONNECTING:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_CONNECTING]");
        decrypt_shadowsocks_packet(tvb, pinfo, tree, data, conv_data, shadowsocks_tree, meta_cipher_tree, pkt_idx);
        break;
    case STAGE_STREAM:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_STREAM]");
        decrypt_shadowsocks_packet(tvb, pinfo, tree, data, conv_data, shadowsocks_tree, meta_cipher_tree, pkt_idx);
        break;
    default:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_ERROR]");
        break;
    }

    return tvb_captured_length(tvb);
}

/**
 * @brief Register the Shadowsocks protocol with Wireshark.
 *  This function is called when Wireshark starts up.
 */
void proto_register_shadowsocks(void)
{
    module_t *shadowsocks_module _U_;

    proto_shadowsocks = proto_register_protocol(
        "Shadowsocks", // name
        "Shadowsocks", // short_name
        "shadowsocks"  // filter_name
    );

    shadowsocks_handle = register_dissector("shadowsocks", dissect_shadowsocks, proto_shadowsocks);

    /*** Header Fields & Subtrees ***/
    static hf_register_info hf[] = {
        // // Stage
        // {&hf_shadowsocks_stage,
        //  {"Stage",
        //   "shadowsocks.stage",
        //   FT_INT8,
        //   BASE_DEC,
        //   NULL, 0x0, NULL, HFILL}},
        /* Meta cipher */
        {&hf_shadowsocks_meta_cipher, // node's index
         {"Meta Cipher",              // item's label
          "shadowsocks.meta_cipher",  // abbreviated name, for use in the display filter
          FT_BYTES,                   // item's type
          BASE_NONE,                  // display base for integers
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_cipher_type,
         {"Cipher Type",
          "shadowsocks.cipher_type",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_password,
         {"Password",
          "ss.password",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_derived_key,
         {"Derived Key",
          "ss.derived_key",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_salt,
         {"Salt",
          "shadowsocks.salt",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_subkey,
         {"Subkey",
          "ss.subkey",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_nonce,
         {"Nonce",
          "ss.nonce",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        /* Address */
        {&hf_shadowsocks_addr,
         {"Address",
          "ss.addr",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_atyp,
         {"Address Type",
          "ss.atyp",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_addr_ipv4,
         {"IPv4",
          "ss.ipv4",
          FT_IPv4,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_addr_domain_len,
         {"Domain Length",
          "ss.domain_len",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_addr_domain,
         {"Domain",
          "ss.domain",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_addr_ipv6,
         {"IPv6",
          "ss.ipv6",
          FT_IPv6,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_shadowsocks_port,
         {"Port",
          "ss.port",
          FT_UINT16,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_shadowsocks,
        &ett_shadowsocks_meta_cipher,
        &ett_shadowsocks_addr};

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_shadowsocks, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*** Preferences ***/
    shadowsocks_module = prefs_register_protocol(proto_shadowsocks, proto_reg_handoff_shadowsocks);
    /* Cipher type preference */
    prefs_register_enum_preference(shadowsocks_module,
                                   "cipher_type",
                                   "Cipher type",
                                   "The cipher used by the Shadowsocks server",
                                   (int *)&pref_cipher_type,
                                   pref_cipher_type_vals,
                                   false);
    /* Password preference */
    prefs_register_string_preference(shadowsocks_module,
                                     "password",
                                     "Shadowsocks password",
                                     "The password of the Shadowsocks server",
                                     &pref_cipher_password);

    register_init_routine(shadowsocks_init);
    register_cleanup_routine(shadowsocks_cleanup);
}

/**
 * @brief Associate the protocol handler with the traffic.
 *  Called by Wireshark's preferences manager whenever "Apply" or "OK" are pressed.
 */
void proto_reg_handoff_shadowsocks(void)
{
    gcry_error_t err;
    static bool is_initialized = false;

    if (!is_initialized)
    {
        dissector_add_uint_with_preference("tcp.port", SHADOWSOCKS_PORT, shadowsocks_handle);
        is_initialized = true;
    }

    set_cipher_size(pref_cipher_type);
    /* Derive the key from the password */
    err = shadowsocks_kdf(pref_cipher_password, strlen(pref_cipher_password), cipher_derived_key, cipher_key_size);
    DISSECTOR_ASSERT(err == 0);
}

/**
 * @brief Operations to be performed when the plugin is loaded.
 */
static void shadowsocks_init(void)
{
    hash_table_stage = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    hash_table_nonce = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
}

/**
 * @brief Corresponding to `shadowsocks_init()`.
 */
static void shadowsocks_cleanup(void)
{
    // g_hash_table_destroy(hash_table_stage);
    // g_hash_table_destroy(hash_table_nonce);
    wmem_free(wmem_file_scope(), hash_table_stage);
    wmem_free(wmem_file_scope(), hash_table_nonce);
}

/**
 * @brief Return the Shadowsocks conversation data if it exists, or create a new one.
 * @param conv the conversation
 * @param proto the protocol handle
 * @return the retrieved or created Shadowsocks conversation data
 */
static shadowsocks_conv_t *get_shadowsocks_conv(conversation_t *conv, int proto)
{
    shadowsocks_conv_t *conv_data = (shadowsocks_conv_t *)conversation_get_proto_data(conv, proto);
    if (conv_data)
    {
        return conv_data;
    }

    /*** Initialization ***/
    conv_data = wmem_new0(wmem_file_scope(), shadowsocks_conv_t);
    conv_data->last_stage = STAGE_UNSET;
    /* Meta cipher */
    conv_data->shadowsocks_meta_cipher.is_handle_initialized = false;
    conv_data->shadowsocks_meta_cipher.is_salt_set = false;
    conv_data->shadowsocks_meta_cipher.cipher_hd = NULL;
    conv_data->shadowsocks_meta_cipher.cipher_type = pref_cipher_type;
    conv_data->shadowsocks_meta_cipher.password = pref_cipher_password;
    conv_data->shadowsocks_meta_cipher.derived_key = cipher_derived_key;
    conv_data->shadowsocks_meta_cipher.salt = wmem_alloc0(wmem_file_scope(), cipher_salt_size);
    conv_data->shadowsocks_meta_cipher.subkey = wmem_alloc0(wmem_file_scope(), cipher_key_size);
    conv_data->shadowsocks_meta_cipher.nonce = wmem_alloc0(wmem_file_scope(), cipher_nonce_size);
    /* Decrypted data */
    conv_data->next_tvb = NULL;

    /* Add the conv_data to the conversation */
    conversation_add_proto_data(conv, proto, conv_data);
    return conv_data;
}

/**
 * @brief Similar to a FSM, set the current stage of a Shadowsocks packet.
 * @param last_stage conv_data->last_stage
 * @param cur_stage the current stage of the packet, initialized to `STAGE_UNSET`(-3)
 * @param payload_size
 */
static void update_shadowsocks_stage(shadowsocks_server_stage_e *last_stage, shadowsocks_server_stage_e *cur_stage, uint32_t payload_size)
{
    if (*last_stage == STAGE_UNSET)
    {
        if (*cur_stage != STAGE_UNSET)
        {
            // It should not happen
            *last_stage = *cur_stage;
        }
        else
        {
            /* Check if the payload is salt */
            // NOTE: Not a reliable way
            if (payload_size != cipher_salt_size)
            {
                // It means the conversation is not started from the beginning, leave it unknown
                *cur_stage = STAGE_UNKNOWN;
            }
            else
            {
                *cur_stage = STAGE_INIT;
                *last_stage = STAGE_INIT;
            }
        }
    }
    else
    {
        if (*cur_stage == STAGE_UNSET)
        {
            // TODO: Temporary solution
            shadowsocks_server_stage_e tmp_new_stage = (*last_stage + 1) % 6;
            *cur_stage = tmp_new_stage;
            *last_stage = *cur_stage;
        }
    }
}

/********** Shadowsocks Cipher Related Functions **********/
/**
 * @brief Set key size, nonce size, salt size, and tag size according to the cipher type.
 *  Called by `proto_reg_handoff_shadowsocks()` when the cipher type is updated.
 * @param cipher_type
 */
static void set_cipher_size(cipher_type_e cipher_type)
{
    switch (cipher_type)
    {
    case AEAD_AES_128_GCM:
        cipher_key_size = AEAD_AES_128_GCM_KEY_LENGTH;
        cipher_nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_AES_192_GCM:
        cipher_key_size = 24;
        cipher_nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_AES_256_GCM:
        cipher_key_size = AEAD_AES_256_GCM_KEY_LENGTH;
        cipher_nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_CHACHA20_POLY1305:
        cipher_key_size = AEAD_CHACHA20POLY1305_KEY_LENGTH;
        cipher_nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_XCHACHA20_POLY1305:
        cipher_key_size = 32;
        cipher_nonce_size = 24;
        break;
    default:
        break;
    }
    cipher_salt_size = (cipher_key_size > 16) ? cipher_key_size : 16;
    cipher_tag_size = 16;
}

/**
 * @brief Key-derivation function from original Shadowsocks.
 * @param password the password of the proxy server
 * @param password_len
 * @param out the derived key
 * @param out_len
 * @return 0 on success, error code otherwise
 */
static gcry_error_t shadowsocks_kdf(const char *password, uint32_t password_len, uint8_t *out, uint32_t out_len)
{
    gcry_md_hd_t h;
    gcry_error_t err;
    const uint32_t hash_len = HASH_MD5_LENGTH;
    uint8_t lastoutput[HASH_MD5_LENGTH];

    /* Some sanity checks */
    if (!(out_len > 0 && out_len <= 255 * hash_len) ||
        !(hash_len > 0 && hash_len <= sizeof(lastoutput)))
    {
        return GPG_ERR_INV_ARG;
    }

    // NOTE: Do not set the flags to `GCRY_MD_FLAG_HMAC` to enable the HMAC feature
    err = gcry_md_open(&h, GCRY_MD_MD5, 0);
    if (err)
    {
        return err;
    }

    // NOTE: Keep the same logic as the Clash implementation:
    // ```go
    // for len(b) < keyLen {
    //     h.Write(prev)
    //     h.Write([]byte(password))
    //     b = h.Sum(b)
    //     prev = b[len(b)-h.Size():]
    //     h.Reset()
    // }
    // ```
    for (uint32_t offset = 0; offset < out_len; offset += hash_len)
    {
        gcry_md_reset(h);
        // NOTE: Do not set the key
        // gcry_md_setkey(h, password, password_len);
        if (offset > 0)
        {
            gcry_md_write(h, lastoutput, hash_len);
        }
        gcry_md_write(h, password, password_len);
        memcpy(lastoutput, gcry_md_read(h, GCRY_MD_MD5), hash_len);
        memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
    }

    gcry_md_close(h);
    return 0;
}

/**
 * @brief Generate a subkey from the secret and salt.
 * @param secret the key derived using the function `shadowsocks_kdf()`
 * @param secret_len
 * @param salt the salt sent by the client
 * @param salt_len
 * @param out the subkey
 * @param out_len
 */
static void gen_subkey(const uint8_t *secret, uint32_t secret_len, uint8_t *salt, uint32_t salt_len, uint8_t *out, uint32_t out_len)
{
    gcry_error_t err;
    const char *info = "ss-subkey";
    const uint32_t info_len = strlen(info);
    const uint32_t prk_len = HASH_SHA1_LENGTH;
    uint8_t prk[HASH_SHA1_LENGTH];

    // NOTE: Keep the same logic as the Clash implementation:
    // ```go
    // func New(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
    //     prk := Extract(hash, secret, salt)
    //     return Expand(hash, prk, info)
    // }
    // ```
    err = hkdf_extract(GCRY_MD_SHA1, salt, salt_len, secret, secret_len, prk);
    DISSECTOR_ASSERT(err == 0);

    err = hkdf_expand(GCRY_MD_SHA1, prk, prk_len, info, info_len, out, out_len);
    DISSECTOR_ASSERT(err == 0);
}

/**
 * @brief Initialize the cipher handle.
 *  Make sure the password and salt are set before calling this function.
 * @param meta_cipher the meta cipher structure
 * @return 0 on success, error code otherwise
 */
static void init_shadowsocks_cipher_handle(shadowsocks_meta_cipher_t *meta_cipher)
{
    gcry_error_t err;

    /* Create cipher handler */
    switch (meta_cipher->cipher_type)
    {
    case AEAD_AES_128_GCM:
        err = gcry_cipher_open(&meta_cipher->cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case AEAD_AES_192_GCM:
        err = gcry_cipher_open(&meta_cipher->cipher_hd, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case AEAD_AES_256_GCM:
        err = gcry_cipher_open(&meta_cipher->cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case AEAD_CHACHA20_POLY1305:
        err = gcry_cipher_open(&meta_cipher->cipher_hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
        break;
    case AEAD_XCHACHA20_POLY1305:
        err = gcry_cipher_open(&meta_cipher->cipher_hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
        break;
    default:
        break;
    }
    DISSECTOR_ASSERT(err == 0);

    /* Generate subkey using the derived key and salt */
    if (!meta_cipher->is_salt_set)
    {
        report_failure("Failed to initialize cipher handle: salt is not set");
        return;
    }
    gen_subkey(meta_cipher->derived_key, cipher_key_size, meta_cipher->salt, cipher_salt_size, meta_cipher->subkey, cipher_key_size);

    /* Set key */
    err = gcry_cipher_setkey(meta_cipher->cipher_hd, meta_cipher->subkey, cipher_key_size);
    DISSECTOR_ASSERT(err == 0);
    /* Set IV */
    if (meta_cipher->nonce)
    {
        wmem_free(wmem_file_scope(), meta_cipher->nonce);
    }
    meta_cipher->nonce = wmem_alloc0(wmem_file_scope(), cipher_nonce_size);
    err = gcry_cipher_setiv(meta_cipher->cipher_hd, meta_cipher->nonce, cipher_nonce_size);
    DISSECTOR_ASSERT(err == 0);

    meta_cipher->is_handle_initialized = true;

    // DEBUG
    // printf("Cipher type: %d\n", meta_cipher->cipher_type);
    // printf("Password: %s\n", meta_cipher->password);
    // printf("Key:\n");
    // for (uint32_t i = 0; i < cipher_key_size; i++)
    //     printf("%02x", meta_cipher->derived_key[i]);
    // printf("\n");
    // printf("Salt:\n");
    // for (uint32_t i = 0; i < cipher_salt_size; i++)
    //     printf("%02x", meta_cipher->salt[i]);
    // printf("\n");
    // printf("Subkey:\n");
    // for (uint32_t i = 0; i < cipher_key_size; i++)
    //     printf("%02x", meta_cipher->subkey[i]);
    // printf("\n");
    // printf("Nonce:\n");
    // for (uint32_t i = 0; i < cipher_nonce_size; i++)
    //     printf("%02x", meta_cipher->nonce[i]);
    // printf("\n");
}

/**
 * @brief Increment little-endian encoded unsigned integer b. Wrap around on overflow.
 * @param b the buffer containing the integer
 * @param b_len
 */
static void increment(uint8_t *b, uint32_t b_len)
{
    for (uint32_t i = 0; i < b_len; i++)
    {
        if (++b[i])
        {
            break;
        }
    }
}

/**
 * @brief Lookup the VI used to decrypt the current packet, or create a new one if not found.
 * @param pkt_idx index of current packet
 * @param last_nonce conv_data->shadowsocks_meta_cipher.nonce
 */
static uint8_t *get_shadowsocks_nonce(uint32_t *pkt_idx, uint8_t *last_nonce)
{
    uint8_t *nonce = wmem_new0(wmem_file_scope(), uint8_t);
    nonce = (uint8_t *)wmem_map_lookup(hash_table_nonce, pkt_idx);
    if (!nonce)
    {
        uint8_t *tmp_nonce = wmem_new0(wmem_file_scope(), uint8_t);
        memcpy(tmp_nonce, last_nonce, cipher_nonce_size);
        wmem_map_insert(hash_table_nonce, pkt_idx, tmp_nonce);
        increment(last_nonce, cipher_nonce_size);
        increment(last_nonce, cipher_nonce_size);
    }

    nonce = (uint8_t *)wmem_map_lookup(hash_table_nonce, pkt_idx);
    if (!nonce)
    {
        report_failure("Failed to lookup the nonce of packet %u", *pkt_idx);
        return NULL;
    }

    return nonce;
}

/**
 * @brief Decrypt the payload of the Shadowsocks packet.
 * @param cipher_hd conv_data->shadowsocks_meta_cipher.cipher_hd
 * @param in the encrypted payload
 * @param nonce the nonce used to decrypt the payload
 * @param out the decrypted payload
 * @param real_size the size of out
 */
static void decrypt_payload(gcry_cipher_hd_t cipher_hd, uint8_t *in, uint8_t *nonce, uint8_t *out, uint32_t *real_size)
{
    uint8_t *nonce_copy = wmem_memdup(wmem_file_scope(), nonce, cipher_nonce_size);
    uint8_t *size_part_copy = wmem_memdup(wmem_file_scope(), in, 2 + cipher_tag_size);
    uint8_t *data_part_copy; // The size will be determined later

    gcry_error_t err;

    /* Decryption result */
    uint32_t real_data_size;
    uint8_t *decrypted_data;

    /* Decrypt the size part */
    uint8_t *tmp_buf = wmem_alloc0(wmem_file_scope(), 2 + cipher_tag_size);
    err = gcry_cipher_setiv(cipher_hd, nonce_copy, cipher_nonce_size);
    DISSECTOR_ASSERT(err == 0);
    err = gcry_cipher_decrypt(cipher_hd, tmp_buf, 2 + cipher_tag_size, size_part_copy, 2 + cipher_tag_size);
    DISSECTOR_ASSERT(err == 0);
    increment(nonce_copy, cipher_nonce_size);
    real_data_size = (((int)tmp_buf[0] << 8) + (int)tmp_buf[1]) & PAYLOAD_SIZE_MASK;
    if (real_data_size == 0)
    {
        report_failure("Failed to decrypt the payload: zero chunk");
        return;
    }

    /* Decrypt the data part */
    data_part_copy = wmem_memdup(wmem_file_scope(), in + 2 + cipher_tag_size, real_data_size + cipher_tag_size);
    decrypted_data = wmem_alloc0(wmem_file_scope(), real_data_size + cipher_tag_size);
    err = gcry_cipher_setiv(cipher_hd, nonce_copy, cipher_nonce_size);
    DISSECTOR_ASSERT(err == 0);
    err = gcry_cipher_decrypt(cipher_hd, decrypted_data, real_data_size + cipher_tag_size, data_part_copy, real_data_size + cipher_tag_size);
    DISSECTOR_ASSERT(err == 0);
    increment(nonce_copy, cipher_nonce_size);

    *real_size = real_data_size;
    out = wmem_realloc(wmem_file_scope(), out, real_data_size);
    memcpy(out, decrypted_data, real_data_size);

    /* Free the memory */
    wmem_free(wmem_file_scope(), tmp_buf);
    wmem_free(wmem_file_scope(), nonce_copy);
    wmem_free(wmem_file_scope(), size_part_copy);
    wmem_free(wmem_file_scope(), data_part_copy);
    wmem_free(wmem_file_scope(), decrypted_data);

    // DEBUG
    // printf("Real payload size: %u\n", real_data_size);
    // printf("Decrypted data: ");
    // for (uint32_t i = 0; i < real_data_size; i++)
    // {
    //     printf("%02x ", decrypted_data[i]);
    // }
    // printf("\n");
}

/********** Debugging Functions **********/
static void debug_print_key_value(const void *key, const void *value, void *user_data _U_)
{
    printf("%u -> %u\n", *(uint32_t *)key, *(uint32_t *)value);
}

static void debug_display_hash_table(wmem_map_t *hash_table)
{
    wmem_map_foreach(hash_table, (GHFunc)debug_print_key_value, NULL);
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
