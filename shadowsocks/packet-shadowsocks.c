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

/********** Logging Domain **********/
#define WS_LOG_DOMAIN "packet-shadowsocks"

/********** Constants **********/
#define SHADOWSOCKS_PORT 8388
#define PAYLOAD_SIZE_MASK 0x3FFF

/********** Structure, Enum Definitions **********/
typedef enum
{
    AEAD_AES_128_GCM = 1,
    AEAD_AES_192_GCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
    AEAD_XCHACHA20_POLY1305
} cipher_type_e;

/* Stages of a Shadowsocks handler (defined in Shadowsocks protocol) */
// TODO: Maybe `PacketType` is more appropriate
typedef enum
{
    STAGE_UNSET = -3,
    STAGE_UNKNOWN = -2,
    /* The 2 stages above are defined by myself */
    STAGE_DESTROYED = -1,
    STAGE_INIT = 0,   /* auth METHOD received from local, reply with selection message */
    STAGE_ADDR,       /* addr received from local, query DNS for remote */
    STAGE_UDP_ASSOC,  /* UDP assoc */
    STAGE_DNS,        /* DNS resolved, connect to remote */
    STAGE_CONNECTING, /* still connecting, more data from local received */
    STAGE_STREAM      /* remote connected, piping local and remote */

} shadowsocks_server_stage_e;

typedef struct _shadowsocks_meta_cipher_t
{
    bool is_handle_initialized;
    bool is_salt_set;

    gcry_cipher_hd_t cipher_hd;

    cipher_type_e cipher_type;
    const char *password;
    uint8_t *key;
    uint8_t *salt;
    uint8_t *subkey;
    uint8_t *nonce;
} shadowsocks_meta_cipher_t;

typedef struct _shadowsocks_conv_t
{
    shadowsocks_meta_cipher_t shadowsocks_meta_cipher;

    shadowsocks_server_stage_e last_stage;
    GHashTable *stage_map;
} shadowsocks_conv_t;

/********** Function Prototypes **********/
void proto_reg_handoff_shadowsocks(void);
void proto_register_shadowsocks(void);

static shadowsocks_conv_t *get_shadowsocks_conv(conversation_t *conv, int proto);
static void update_shadowsocks_stage(shadowsocks_server_stage_e *last_stage, shadowsocks_server_stage_e *cur_stage, uint32_t payload_size) _U_;

static void set_cipher_size(cipher_type_e cipher_type);
static void init_shadowsocks_cipher_handle(shadowsocks_meta_cipher_t *meta_cipher) _U_;
static void increment(uint8_t *b, uint32_t b_len) _U_;

/********** Protocol Handles **********/
static int proto_shadowsocks;

/********** Dissector Handles **********/
static dissector_handle_t shadowsocks_handle;

/********** Header Fields **********/
static int hf_shadowsocks_salt;
/* Meta Cipher */
static int hf_shadowsocks_meta_cipher;
static int hf_shadowsocks_cipher_type;
static int hf_shadowsocks_password;
static int hf_shadowsocks_key;

/********** Expert Fields **********/
static expert_field ei_shadowsocks_salt _U_;

/********** Subtree pointers **********/
static int ett_shadowsocks;
static int ett_shadowsocks_meta_cipher;

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
static uint8_t cipher_derived_key[AEAD_MAX_KEY_LENGTH] _U_;

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

    proto_item *ti _U_, *meta_cipher_ti _U_, *expert_ti _U_;
    proto_tree *shadowsocks_tree _U_, *meta_cipher_tree _U_;

    uint32_t *packet_index = wmem_new(wmem_file_scope(), uint32_t);
    *packet_index = pinfo->num;
    shadowsocks_server_stage_e *cur_stage = wmem_new(wmem_file_scope(), shadowsocks_server_stage_e);

    /*** Conversation ***/
    /* Lookup the conversation or create a new one */
    conversation = find_or_create_conversation(pinfo);
    conv_data = get_shadowsocks_conv(conversation, proto_shadowsocks);
    /* Lookup and set the stage of the current packet */
    cur_stage = (shadowsocks_server_stage_e *)g_hash_table_lookup(conv_data->stage_map, packet_index);
    if (!cur_stage)
    {
        shadowsocks_server_stage_e *stage = g_new(shadowsocks_server_stage_e, 1);
        *stage = STAGE_UNSET;
        g_hash_table_insert(conv_data->stage_map, packet_index, stage);
    }
    cur_stage = (shadowsocks_server_stage_e *)g_hash_table_lookup(conv_data->stage_map, packet_index);
    if (!cur_stage)
    {
        report_failure("Failed to get current stage");
        return tvb_captured_length(tvb);
    }
    update_shadowsocks_stage(&conv_data->last_stage, cur_stage, tvb_captured_length(tvb));
    g_hash_table_insert(conv_data->stage_map, packet_index, cur_stage);

    /*** COLUMN DATA ***/
    /* Set the Protocol column to the constant string of Shadowsocks */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Shadowsocks");
    col_clear(pinfo->cinfo, COL_INFO);

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
        break;
    case STAGE_ADDR:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_ADDR]");
        break;
    case STAGE_UDP_ASSOC:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_UDP_ASSOC]");
        break;
    case STAGE_DNS:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_DNS]");
        break;
    case STAGE_CONNECTING:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_CONNECTING]");
        break;
    case STAGE_STREAM:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_STREAM]");
        break;
    default:
        col_set_str(pinfo->cinfo, COL_INFO, "[STAGE_ERROR]");
        break;
    }
#if 0
    /* Differentiate between request and reply */
    // if (SHADOWSOCKS_PORT == pinfo->destport)
    // {
    //     col_set_str(pinfo->cinfo, COL_INFO, "Shadowsocks Request");
    //     is_request = true;
    // }
    // else
    // {
    //     col_set_str(pinfo->cinfo, COL_INFO, "Shadowsocks Reply");
    //     is_request = false;
    // }

    /*** PROTOCOL TREE ***/
    ti = proto_tree_add_item(tree, proto_shadowsocks, tvb, 0, -1, ENC_NA);
    shadowsocks_tree = proto_item_add_subtree(ti, ett_shadowsocks);
    /* Meta Cipher */
    meta_cipher_ti = proto_tree_add_item(shadowsocks_tree, hf_shadowsocks_meta_cipher, tvb, 0, 0, ENC_NA);
    proto_item_set_text(meta_cipher_ti, "[Meta Cipher]");
    meta_cipher_tree = proto_item_add_subtree(meta_cipher_ti, ett_shadowsocks_meta_cipher);
    proto_tree_add_uint(meta_cipher_tree, hf_shadowsocks_cipher_type, tvb, 0, 0, conv_data->shadowsocks_meta_cipher.cipher_type);
    proto_tree_add_string(meta_cipher_tree, hf_shadowsocks_password, tvb, 0, 0, conv_data->shadowsocks_meta_cipher.password);
    // FIXME: Why is uint8_t not accepted?
    // proto_tree_add_uint(meta_cipher_tree, hf_shadowsocks_key, tvb, 0, 0, shadowsocks_meta_cipher.key);
    char key_str[AEAD_MAX_KEY_LENGTH * 2 + 1];
    for (uint32_t i = 0; i < cipher_key_size; i++)
    {
        sprintf(key_str + i * 2, "%02x", conv_data->shadowsocks_meta_cipher.key[i]);
    }
    proto_tree_add_string(meta_cipher_tree, hf_shadowsocks_key, tvb, 0, 0, key_str);

    /*** DISSECT ***/
    // TODO: Maybe FSM should be used to handle different stages
    // TODO: Split into functions
    if (tvb_captured_length(tvb) == shadowsocks_meta_cipher.salt_size)
    {
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt]");
        proto_tree_add_bytes(shadowsocks_tree, hf_shadowsocks_salt, tvb, 0, shadowsocks_meta_cipher.salt_size, shadowsocks_meta_cipher.salt);

        tvb_memcpy(tvb, shadowsocks_meta_cipher.salt, 0, shadowsocks_meta_cipher.salt_size);
        shadowsocks_meta_cipher.is_salt_set = true;

        init_shadowsocks_cipher_handle(&shadowsocks_meta_cipher);
        shadowsocks_meta_cipher.is_cipher_hd_set = true;

        // DEBUG
        printf("Salt: ");
        for (uint32_t i = 0; i < shadowsocks_meta_cipher.salt_size; i++)
        {
            printf("%02x", shadowsocks_meta_cipher.salt[i]);
        }
        printf("\n");
        printf("Subkey: ");
        for (uint32_t i = 0; i < shadowsocks_meta_cipher.key_size; i++)
        {
            printf("%02x", shadowsocks_meta_cipher.subkey[i]);
        }
        printf("\n");
    }
    // TODO: Split into functions
    else
    {
        if (!shadowsocks_meta_cipher.is_salt_set)
        {
            printf("Salt is not found\n");
        }
        else if (!shadowsocks_meta_cipher.is_cipher_hd_set)
        {
            printf("Cipher handle is not initialized\n");
        }
        else
        {
            // FIXME: Associate the nonce with the packet
            /* Decrypt the packet */
            gcry_error_t err;
            uint32_t buf_1_len = 2 + shadowsocks_meta_cipher.tag_size;
            uint8_t *buf_1 = wmem_alloc0(NULL, (buf_1_len) * sizeof(uint8_t));

            uint32_t payload_size = tvb_captured_length(tvb);
            uint8_t *payload = wmem_alloc0(NULL, payload_size * sizeof(uint8_t));
            tvb_memcpy(tvb, payload, 0, payload_size);

            err = gcry_cipher_decrypt(shadowsocks_meta_cipher.cipher_hd, buf_1, buf_1_len, payload, payload_size);
            if (err)
            {
                printf("Decryption failed: %s\n", gcry_strerror(err));
            }
            increment(shadowsocks_meta_cipher.nonce, shadowsocks_meta_cipher.nonce_size);

            wmem_free(NULL, buf_1);

            // DEBUG
            printf("Nonce: ");
            for (uint32_t i = 0; i < shadowsocks_meta_cipher.nonce_size; i++)
            {
                printf("%02x", shadowsocks_meta_cipher.nonce[i]);
            }
            printf("\n");

            uint32_t actual_payload_size = ((buf_1[0] << 8) + buf_1[1]) & PAYLOAD_SIZE_MASK;
            printf("Actual Payload size: %d\n", actual_payload_size);
            if (actual_payload_size == 0)
            {
                printf("Zero chunk\n");
            }
            uint32_t buf_2_len = actual_payload_size + shadowsocks_meta_cipher.tag_size;
            uint8_t *buf_2 = wmem_alloc0(NULL, (buf_2_len) * sizeof(uint8_t));

            err = gcry_cipher_decrypt(shadowsocks_meta_cipher.cipher_hd, buf_2, buf_2_len, tvb_get_ptr(tvb, offset + buf_1_len, buf_2_len), buf_2_len);
            if (err)
            {
                printf("Decryption failed: %s\n", gcry_strerror(err));
            }
            increment(shadowsocks_meta_cipher.nonce, shadowsocks_meta_cipher.nonce_size);

            // DEBUG
            printf("Decrypted payload: ");
            for (uint32_t i = 0; i < actual_payload_size; i++)
            {
                printf("%02x", buf_2[i]);
            }
            printf("\n");
        }
    }
#endif

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
        // Salt
        {&hf_shadowsocks_salt, // node's index
         {"Salt",              // item's label
          "shadowsocks.salt",  // abbreviated name, for use in the display filter
          FT_BYTES,            // item's type
          BASE_NONE,           // display base for integers
          NULL, 0x0, NULL, HFILL}},
        // Meta cipher
        {&hf_shadowsocks_meta_cipher,
         {"Meta Cipher",
          "shadowsocks.meta_cipher",
          FT_BYTES,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        // Cipher type
        {&hf_shadowsocks_cipher_type,
         {"Cipher Type",
          "shadowsocks.cipher_type",
          FT_UINT8,
          BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        // Password
        {&hf_shadowsocks_password,
         {"Password",
          "ss.password",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        // Key
        {&hf_shadowsocks_key,
         {"Key",
          "ss.key",
          FT_STRING,
          BASE_NONE,
          NULL, 0x0, NULL, HFILL}}};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_shadowsocks_meta_cipher,
        &ett_shadowsocks};

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
}

/**
 * @brief Associate the protocol handler with the traffic.
 *  Called by Wireshark's preferences manager whenever "Apply" or "OK" are pressed.
 */
void proto_reg_handoff_shadowsocks(void)
{
    static bool is_initialized = false;

    if (!is_initialized)
    {
        dissector_add_uint_with_preference("tcp.port", SHADOWSOCKS_PORT, shadowsocks_handle);
        is_initialized = true;
    }

    set_cipher_size(pref_cipher_type);
}

/**
 * @brief Return the Shadowsocks conversation data if it exists, or create a new one.
 * @param conv the conversation
 * @param proto the protocol handle
 * @return the retrieved or created Shadowsocks conversation data
 */
static shadowsocks_conv_t *get_shadowsocks_conv(conversation_t *conv, int proto)
{
    shadowsocks_conv_t *conv_data;

    conv_data = (shadowsocks_conv_t *)conversation_get_proto_data(conv, proto);
    if (conv_data)
    {
        return conv_data;
    }

    /*** Initialization ***/
    conv_data = wmem_alloc0(wmem_file_scope(), sizeof(shadowsocks_conv_t));
    conv_data->last_stage = STAGE_UNSET;
    conv_data->stage_map = g_hash_table_new(g_int_hash, g_int_equal);
    /* Meta cipher */
    conv_data->shadowsocks_meta_cipher.is_handle_initialized = false;
    conv_data->shadowsocks_meta_cipher.is_salt_set = false;
    conv_data->shadowsocks_meta_cipher.cipher_hd = NULL;
    conv_data->shadowsocks_meta_cipher.cipher_type = pref_cipher_type;
    conv_data->shadowsocks_meta_cipher.password = pref_cipher_password;
    conv_data->shadowsocks_meta_cipher.key = NULL;
    conv_data->shadowsocks_meta_cipher.salt = NULL;
    conv_data->shadowsocks_meta_cipher.subkey = NULL;
    conv_data->shadowsocks_meta_cipher.nonce = NULL;

    /* Add the conv_data to the conversation */
    conversation_add_proto_data(conv, proto, conv_data);
    return conv_data;
}

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
        if (*cur_stage != STAGE_UNSET)
        {
            // Nothing to do
            printf("Nothing to do\n");
        }
        else
        {
            // TODO: Temporary solution
            shadowsocks_server_stage_e new_stage = (*last_stage + 1) % 6;
            *cur_stage = new_stage;
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
static gcry_error_t shadowsocks_kdf(const uint8_t *password, uint32_t password_len, uint8_t *out, uint32_t out_len)
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

    /* Derive the key from the password */
    err = shadowsocks_kdf((const uint8_t *)meta_cipher->password, strlen(meta_cipher->password), meta_cipher->key, cipher_key_size);
    DISSECTOR_ASSERT(err == 0);
    /* Generate subkey using the derived key and salt */
    if (!meta_cipher->is_salt_set)
    {
        report_failure("Failed to initialize cipher handle: salt is not set");
        return;
    }
    gen_subkey(meta_cipher->key, cipher_key_size, meta_cipher->salt, cipher_salt_size, meta_cipher->subkey, cipher_key_size);

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
    printf("Cipher type: %d\n", meta_cipher->cipher_type);
    printf("Password: %s\n", meta_cipher->password);
    printf("Key:\n");
    for (uint32_t i = 0; i < cipher_key_size; i++)
        printf("%02x", meta_cipher->key[i]);
    printf("\n");
    printf("Salt:\n");
    for (uint32_t i = 0; i < cipher_salt_size; i++)
        printf("%02x", meta_cipher->salt[i]);
    printf("\n");
    printf("Subkey:\n");
    for (uint32_t i = 0; i < cipher_key_size; i++)
        printf("%02x", meta_cipher->subkey[i]);
    printf("\n");
    printf("Nonce:\n");
    for (uint32_t i = 0; i < cipher_nonce_size; i++)
        printf("%02x", meta_cipher->nonce[i]);
    printf("\n");
}

/**
 * @brief Increment little-endian encoded unsigned integer b. Wrap around on overflow.
 * @param b the buffer containing the integer
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
