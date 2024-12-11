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
#include <wsutil/wsgcrypt.h>

/********** Logging Domain **********/
#define WS_LOG_DOMAIN "packet-shadowsocks"

/********** Protocol Handles **********/
static int proto_shadowsocks;

/********** Dissector Handles **********/
static dissector_handle_t shadowsocks_handle;

/********** Header Fields **********/
// static int hf_shadowsocks_stage;
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

/********** Cipher **********/
typedef enum
{
    AEAD_AES_128_GCM = 1,
    AEAD_AES_192_GCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
    AEAD_XCHACHA20_POLY1305
} CipherType;

typedef struct
{
    CipherType cipher_type;
    unsigned int key_size;
    unsigned int salt_size;
    unsigned int nonce_size;
    unsigned int tag_size;

    const char *password;
    uint8_t key[AEAD_MAX_KEY_LENGTH];
    uint8_t salt[AEAD_MAX_KEY_LENGTH];
    uint8_t subkey[AEAD_MAX_KEY_LENGTH];
    uint8_t *nonce;

    gcry_cipher_hd_t cipher_hd;

    bool is_salt_set;
    bool is_cipher_hd_set;
} MetaCipher;

/********** Preferences **********/
/* Port preference */
#define SHADOWSOCKS_PORT 8388
static unsigned shadowsocks_port_pref _U_ = SHADOWSOCKS_PORT;
/* Cipher preference */
static MetaCipher shadowsocks_meta_cipher = {
    .cipher_type = AEAD_AES_256_GCM,
    .key_size = AEAD_AES_256_GCM_KEY_LENGTH,
    .salt_size = AEAD_AES_256_GCM_KEY_LENGTH,
    .nonce_size = HPKE_AEAD_NONCE_LENGTH,
    .tag_size = 16,
    .password = "",
    .key = {0},
    .salt = {0},
    .subkey = {0},
    .nonce = NULL,
    .cipher_hd = NULL,
    .is_salt_set = false,
    .is_cipher_hd_set = false};
static const enum_val_t cipher_pref_vals[] = {
    {"AEAD_AES_128_GCM", "aes-128-gcm", AEAD_AES_128_GCM},
    {"AEAD_AES_192_GCM", "aes-192-gcm", AEAD_AES_192_GCM},
    {"AEAD_AES_256_GCM", "aes-256-gcm", AEAD_AES_256_GCM},
    {"AEAD_CHACHA20_POLY1305", "chacha20-ietf-poly1305", AEAD_CHACHA20_POLY1305},
    {"AEAD_XCHACHA20_POLY1305", "xchacha20-ietf-poly1305", AEAD_XCHACHA20_POLY1305},
    {NULL, NULL, 0}};

/********** Stages of A Shadowsocks Handler **********/
// #define STAGE_INIT 0       // auth METHOD received from local, reply with selection message
// #define STAGE_ADDR 1       // addr received from local, query DNS for remote
// #define STAGE_UDP_ASSOC 2  // UDP assoc
// #define STAGE_DNS 3        // DNS resolved, connect to remote
// #define STAGE_CONNECTING 4 // still connecting, more data from local received
// #define STAGE_STREAM 5     // remote connected, piping local and remote
// #define STAGE_DESTROYED -1 // connection closed
// int shadowsocks_stage = STAGE_INIT;

/********** Prototypes **********/
void proto_reg_handoff_shadowsocks(void);
void proto_register_shadowsocks(void);
static gcry_error_t shadowsocks_kdf(const uint8_t *password, unsigned password_len, uint8_t *out, unsigned out_len);
static void gen_subkey(const uint8_t *secret, unsigned secret_len, uint8_t *salt, unsigned salt_len, uint8_t *out, unsigned out_len);
static void init_shadowsocks_cipher(MetaCipher *meta_cipher);
static void increment(uint8_t *b, unsigned b_len);

#define PAYLOAD_SIZE_MASK 0x3FFF

/**
 * @brief Dissect the Shadowsocks packet.
 * @param tvb buffer containing the packet data
 * @param pinfo general packet information
 * @param tree protocol tree
 * @param data user data
 * @return the amount of data this dissector was able to dissect (which may or
 *  may not be the total captured packet as we return here)
 */
static int
dissect_shadowsocks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *meta_cipher_ti, *expert_ti _U_;
    proto_tree *shadowsocks_tree _U_, *meta_cipher_tree;

    bool is_request _U_ = false;
    unsigned offset = 0;
    int len = 0;

    /*** COLUMN DATA ***/
    /* Set the Protocol column to the constant string of Shadowsocks */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Shadowsocks");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Differentiate between request and reply */
    if (SHADOWSOCKS_PORT == pinfo->destport)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Shadowsocks Request");
        is_request = true;
    }
    else
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Shadowsocks Reply");
        is_request = false;
    }

    /*** PROTOCOL TREE ***/
    ti = proto_tree_add_item(tree, proto_shadowsocks, tvb, 0, -1, ENC_NA);
    shadowsocks_tree = proto_item_add_subtree(ti, ett_shadowsocks);
    /* Meta Cipher */
    meta_cipher_ti = proto_tree_add_item(shadowsocks_tree, hf_shadowsocks_meta_cipher, tvb, 0, 0, ENC_NA);
    proto_item_set_text(meta_cipher_ti, "[Meta Cipher]");
    meta_cipher_tree = proto_item_add_subtree(meta_cipher_ti, ett_shadowsocks_meta_cipher);
    proto_tree_add_uint(meta_cipher_tree, hf_shadowsocks_cipher_type, tvb, 0, 0, shadowsocks_meta_cipher.cipher_type);
    proto_tree_add_string(meta_cipher_tree, hf_shadowsocks_password, tvb, 0, 0, shadowsocks_meta_cipher.password);
    // FIXME: Why is uint8_t not accepted?
    // proto_tree_add_uint(meta_cipher_tree, hf_shadowsocks_key, tvb, 0, 0, shadowsocks_meta_cipher.key);
    char key_str[AEAD_MAX_KEY_LENGTH * 2 + 1];
    for (unsigned i = 0; i < shadowsocks_meta_cipher.key_size; i++)
    {
        sprintf(key_str + i * 2, "%02x", shadowsocks_meta_cipher.key[i]);
    }
    proto_tree_add_string(meta_cipher_tree, hf_shadowsocks_key, tvb, 0, 0, key_str);

    /*** DISSECT ***/
    // TODO: Maybe FSM should be used to handle different stages
    // TODO: Split into functions
    if (tvb_reported_length(tvb) == shadowsocks_meta_cipher.salt_size)
    {
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_str(pinfo->cinfo, COL_INFO, "[Salt]");
        proto_tree_add_bytes(shadowsocks_tree, hf_shadowsocks_salt, tvb, 0, shadowsocks_meta_cipher.salt_size, shadowsocks_meta_cipher.salt);

        memcpy(shadowsocks_meta_cipher.salt, tvb_get_ptr(tvb, 0, shadowsocks_meta_cipher.salt_size), shadowsocks_meta_cipher.salt_size);
        shadowsocks_meta_cipher.is_salt_set = true;

        gen_subkey(shadowsocks_meta_cipher.key, shadowsocks_meta_cipher.key_size, shadowsocks_meta_cipher.salt, shadowsocks_meta_cipher.salt_size, shadowsocks_meta_cipher.subkey, shadowsocks_meta_cipher.key_size);
        init_shadowsocks_cipher(&shadowsocks_meta_cipher);
        shadowsocks_meta_cipher.is_cipher_hd_set = true;

        // DEBUG
        printf("Salt: ");
        for (unsigned i = 0; i < shadowsocks_meta_cipher.salt_size; i++)
        {
            printf("%02x", shadowsocks_meta_cipher.salt[i]);
        }
        printf("\n");
        printf("Subkey: ");
        for (unsigned i = 0; i < shadowsocks_meta_cipher.key_size; i++)
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
            unsigned buf_1_len = 2 + shadowsocks_meta_cipher.tag_size;
            uint8_t *buf_1 = wmem_alloc0(NULL, (buf_1_len) * sizeof(uint8_t));
            err = gcry_cipher_decrypt(shadowsocks_meta_cipher.cipher_hd, buf_1, buf_1_len, tvb_get_ptr(tvb, offset, buf_1_len), buf_1_len);
            if (err)
            {
                printf("Decryption failed: %s\n", gcry_strerror(err));
            }
            increment(shadowsocks_meta_cipher.nonce, shadowsocks_meta_cipher.nonce_size);

            // DEBUG
            printf("Nonce: ");
            for (unsigned i = 0; i < shadowsocks_meta_cipher.nonce_size; i++)
            {
                printf("%02x", shadowsocks_meta_cipher.nonce[i]);
            }
            printf("\n");

            unsigned payload_size = ((buf_1[0] << 8) + buf_1[1]) & PAYLOAD_SIZE_MASK;
            printf("Payload size: %d\n", payload_size);
            if (payload_size == 0)
            {
                printf("Zero chunk\n");
            }
            unsigned buf_2_len = payload_size + shadowsocks_meta_cipher.tag_size;
            uint8_t *buf_2 = wmem_alloc0(NULL, (buf_2_len) * sizeof(uint8_t));
            err = gcry_cipher_decrypt(shadowsocks_meta_cipher.cipher_hd, buf_2, buf_2_len, tvb_get_ptr(tvb, offset + buf_1_len, buf_2_len), buf_2_len);
            if (err)
            {
                printf("Decryption failed: %s\n", gcry_strerror(err));
            }
            increment(shadowsocks_meta_cipher.nonce, shadowsocks_meta_cipher.nonce_size);

            // DEBUG
            printf("Decrypted payload: ");
            for (unsigned i = 0; i < payload_size; i++)
            {
                printf("%02x", buf_2[i]);
            }
            printf("\n");
        }
    }

    // expert_ti = proto_tree_add_item(shadowsocks_tree, hf_shadowsocks_salt, tvb,
    //                                 offset, len, ENC_BIG_ENDIAN);
    offset += len;
    // /* Some fields or situations may require "expert" analysis that can be
    //  * specifically highlighted. */
    // if (TEST_EXPERT_condition)
    //     /* value of hf_FIELDABBREV isn't what's expected */
    //     expert_add_info(pinfo, expert_ti, &ei_shadowsocks_salt);

    return tvb_captured_length(tvb);
}

/**
 * @brief Register the Shadowsocks protocol with Wireshark.
 *  This function is called when Wireshark starts up.
 */
void proto_register_shadowsocks(void)
{
    module_t *shadowsocks_module _U_;
    expert_module_t *expert_shadowsocks _U_;

    /* Setup list of header fields */
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

    /* Setup protocol expert items */
    // static ei_register_info ei[] = {{}};

    /* Register the protocol name and description */
    proto_shadowsocks = proto_register_protocol(
        "Shadowsocks", // name
        "Shadowsocks", // short_name
        "shadowsocks"  // filter_name
    );

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_shadowsocks, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    // expert_shadowsocks = expert_register_protocol(proto_shadowsocks);
    // expert_register_field_array(expert_shadowsocks, ei, array_length(ei));

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    shadowsocks_handle = register_dissector("shadowsocks", dissect_shadowsocks, proto_shadowsocks);

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_PROTOABBREV in the following.
     */
    shadowsocks_module = prefs_register_protocol(proto_shadowsocks, proto_reg_handoff_shadowsocks);

    /* Register a cipher preference */
    prefs_register_enum_preference(shadowsocks_module,
                                   "cipher_type",
                                   "Cipher type",
                                   "The cipher used by the Shadowsocks server",
                                   (int *)&shadowsocks_meta_cipher.cipher_type,
                                   cipher_pref_vals,
                                   false);
    /* Register a password preference */
    prefs_register_string_preference(shadowsocks_module,
                                     "password",
                                     "Shadowsocks password",
                                     "The password of the Shadowsocks server",
                                     &shadowsocks_meta_cipher.password);
}

/**
 * @brief Associate the protocol handler with the traffic.
 *  This function is called by Wireshark's preferences manager whenever "Apply"
 *  or "OK" are pressed.
 */
void proto_reg_handoff_shadowsocks(void)
{
    static bool initialized = false;
    gcry_error_t err;
    static int current_shadowsocks_port_pref _U_;

    /* Set cipher sizes according to the cipher type */
    switch (shadowsocks_meta_cipher.cipher_type)
    {
    case AEAD_AES_128_GCM:
        shadowsocks_meta_cipher.key_size = AEAD_AES_128_GCM_KEY_LENGTH;
        shadowsocks_meta_cipher.nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_AES_192_GCM:
        shadowsocks_meta_cipher.key_size = 24;
        shadowsocks_meta_cipher.nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_AES_256_GCM:
        shadowsocks_meta_cipher.key_size = AEAD_AES_256_GCM_KEY_LENGTH;
        shadowsocks_meta_cipher.nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_CHACHA20_POLY1305:
        shadowsocks_meta_cipher.key_size = AEAD_CHACHA20POLY1305_KEY_LENGTH;
        shadowsocks_meta_cipher.nonce_size = HPKE_AEAD_NONCE_LENGTH;
        break;
    case AEAD_XCHACHA20_POLY1305:
        shadowsocks_meta_cipher.key_size = 32;
        shadowsocks_meta_cipher.nonce_size = 24;
        break;
    default:
        break;
    }
    shadowsocks_meta_cipher.salt_size = (shadowsocks_meta_cipher.key_size > 16)
                                            ? shadowsocks_meta_cipher.key_size
                                            : 16;
    shadowsocks_meta_cipher.tag_size = 16;
    shadowsocks_meta_cipher.nonce = wmem_alloc0(NULL, shadowsocks_meta_cipher.nonce_size);

    /* Derive the key from the password */
    err = shadowsocks_kdf((const uint8_t *)shadowsocks_meta_cipher.password,
                          strlen(shadowsocks_meta_cipher.password),
                          shadowsocks_meta_cipher.key,
                          shadowsocks_meta_cipher.key_size);
    printf("Shadowsocks cipher type: %d\n", shadowsocks_meta_cipher.cipher_type);
    printf("Shadowsocks password: %s\n", shadowsocks_meta_cipher.password);
    printf("Shadowsocks key: ");
    for (unsigned i = 0; i < shadowsocks_meta_cipher.key_size; i++)
    {
        printf("%02x", shadowsocks_meta_cipher.key[i]);
    }
    printf("\n");
    DISSECTOR_ASSERT(err == 0);

    if (!initialized)
    {
        /* Simple port preferences like TCP can be registered as automatic
         * Decode As preferences.
         */
        dissector_add_uint_with_preference("tcp.port", SHADOWSOCKS_PORT, shadowsocks_handle);
        initialized = true;
    }
    else
    {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the value the preference had at the time you registered, which
         * can be saved using local statics in this function (proto_reg_handoff).
         */
        // ssl_dissector_delete(current_shadowsocks_server_port_pref,
        //                      shadowsocks_handle);
    }

    /* Some port preferences, like TLS, are more complicated and cannot
     * be done with auto preferences, because the TCP dissector has to call
     * TLS for the particular port as well as TLS calling this dissector.
     */
    // ssl_dissector_add(shadowsocks_server_port_pref, shadowsocks_handle);
    // current_shadowsocks_server_port_pref = shadowsocks_server_port_pref;
}

/**
 * @brief Key-derivation function from original Shadowsocks.
 * @param password the password of the proxy server
 * @param password_len
 * @param out the derived key
 * @param out_len
 * @return 0 on success, error code otherwise
 */
static gcry_error_t
shadowsocks_kdf(const uint8_t *password, unsigned password_len, uint8_t *out, unsigned out_len)
{
    gcry_md_hd_t h;
    gcry_error_t err;
    const unsigned hash_len = HASH_MD5_LENGTH;
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
    for (unsigned offset = 0; offset < out_len; offset += hash_len)
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
static void gen_subkey(const uint8_t *secret, unsigned secret_len, uint8_t *salt, unsigned salt_len, uint8_t *out, unsigned out_len)
{
    gcry_error_t err;
    const char *info = "ss-subkey";
    const unsigned info_len = strlen(info);
    const unsigned prk_len = HASH_SHA1_LENGTH;
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

    // DEBUG
    printf("Extracted key: ");
    for (unsigned i = 0; i < HASH_SHA1_LENGTH; i++)
    {
        printf("%02x", prk[i]);
    }
    printf("\n");
}

/**
 * @brief Initialize the cipher handler.
 * @param meta_cipher the meta cipher structure
 * @return 0 on success, error code otherwise
 */
static void init_shadowsocks_cipher(MetaCipher *meta_cipher)
{
    gcry_error_t err;
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

    err = gcry_cipher_setkey(meta_cipher->cipher_hd, meta_cipher->subkey, meta_cipher->key_size);
    DISSECTOR_ASSERT(err == 0);

    err = gcry_cipher_setiv(meta_cipher->cipher_hd, meta_cipher->nonce, meta_cipher->nonce_size);
    DISSECTOR_ASSERT(err == 0);
}

/**
 * @brief Increment little-endian encoded unsigned integer b. Wrap around on overflow.
 * @param b the buffer containing the integer
 */
static void increment(uint8_t *b, unsigned b_len)
{
    for (unsigned i = 0; i < b_len; i++)
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
