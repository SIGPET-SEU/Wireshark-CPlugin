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
/* Hash tables (use pinfo->num as key) */
static wmem_map_t *stage_map;
static wmem_map_t *nonce_map;
// NOTE: `shadowsocks-libev` uses a bloom filter to store and check salts. Here a hash table is used instead.
// NOTE AGAIN: Seems that it is used to avoid replay attacks only, so not necessary here?
// static wmem_map_t *salts;

// TODO: Gather the following vars into conv_data?
ss_crypto_t *ss_crypto;
int ss_last_stage;
int ss_frag;
ss_buffer_t *ss_buf;
ss_cipher_ctx_t *ss_cipher_ctx;

int dissect_ss_stage_init(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /*** Protocol Tree ***/
    proto_tree_add_item(tree, hf_cipher_ctx_salt, tvb, 0, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

int dissect_ss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *cipher_ctx_ti, *cipher_ctx_cipher_ti;
    proto_tree *ss_tree, *cipher_ctx_tree, *cipher_ctx_cipher_tree;

    uint32_t *pinfo_num_copy = (uint32_t *)wmem_memdup(wmem_file_scope(), &(pinfo->num), sizeof(uint32_t));

    // ss_buffer_t *buf = ss_buf;

    int *cur_stage = NULL;

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
        proto_tree_add_bytes_with_length(cipher_ctx_tree, hf_cipher_ctx_nonce, tvb, 0, 0, ss_cipher_ctx->nonce, ss_cipher_ctx->cipher->nonce_len);
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

    /*** Stage ***/
    cur_stage = (int *)wmem_map_lookup(stage_map, pinfo_num_copy);
    /* Determine the current stage */
    if (cur_stage == NULL)
    {
        cur_stage = wmem_new0(wmem_file_scope(), int);
        if (ss_last_stage < 0)
        { // Previous stage is unknown
            if (tvb_captured_length(tvb) <= ss_crypto->cipher->key_len && !ss_cipher_ctx->init)
            { // Check if it's a valid salt
                if (tvb_captured_length(tvb) < ss_crypto->cipher->key_len)
                { // Maybe the salt is split into multiple packets
                    // TODO: temporarily set to STAGE_ERROR
                    *cur_stage = STAGE_ERROR;
                }
                else
                { // Assume it's a valid salt
                    gcry_error_t err = ss_aead_cipher_ctx_set_key(ss_cipher_ctx);
                    if (err)
                    {
                        ws_error("Failed to set cipher key: %s", gcry_strerror(err));
                        *cur_stage = STAGE_ERROR;
                    }
                    ss_cipher_ctx->init = 1;
                    *cur_stage = STAGE_INIT;
                }
            }
            else
            { // Can't be a valid salt
                *cur_stage = STAGE_UNKNOWN;
            }
        }
        else
        {
            // TODO: other stages
            *cur_stage = STAGE_UNKNOWN;
        }

        wmem_map_insert(stage_map, pinfo_num_copy, cur_stage);
        ss_last_stage = *cur_stage;
    }

    /*** Column Data & Dissection ***/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Shadowsocks");
    col_clear(pinfo->cinfo, COL_INFO);
    switch (*cur_stage)
    {
    case STAGE_UNKNOWN:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: UNKNOWN");
        break;
    case STAGE_UNSET:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: UNSET");
        break;
    case STAGE_ERROR:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: ERROR");
        break;
    case STAGE_INIT:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: INIT");
        dissect_ss_stage_init(tvb, pinfo, ss_tree, NULL);
        break;
    case STAGE_HANDSHAKE:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: HANDSHAKE");
        break;
    case STAGE_RESOLVE:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: RESOLVE");
        break;
    case STAGE_STREAM:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: STREAM");
        break;
    case STAGE_STOP:
        col_set_str(pinfo->cinfo, COL_INFO, "Stage: STOP");
        return tvb_captured_length(tvb);
        break;
    default:
        ws_error("Unknown stage: %d", *cur_stage);
        break;
    }

    // ss_buf->len = tvb_captured_length(tvb);
    // ss_crypto->decrypt(ss_buf, ss_cipher_ctx, BUF_SIZE);

    return tvb_captured_length(tvb);
}

void proto_register_ss(void)
{
    module_t *ss_module;

    proto_ss = proto_register_protocol(
        "Shadowsocks", // name
        "Shadowsocks", // short_name
        "shadowsocks"  // filter_name
    );

    ss_handle = register_dissector("shadowsocks", dissect_ss, proto_ss);

    /*** Header Fields & Subtrees ***/
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
    };

    /* Subtree array */
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

    register_init_routine(ss_init_routine);
    register_cleanup_routine(ss_cleanup_routine);
}

void proto_reg_handoff_ss(void)
{
    dissector_add_uint_with_preference("tcp.port", SHADOWSOCKS_TCP_PORT, ss_handle);
}

/********** Routine **********/
void ss_init_routine(void)
{
    ss_crypto = ss_crypto_init(pref_password, NULL, supported_aead_ciphers[pref_cipher]);
    if (ss_crypto == NULL)
    {
        ws_error("Failed to initialize ciphers");
        exit(-1);
    }

    ss_buf = wmem_new0(wmem_file_scope(), ss_buffer_t);
    ss_balloc(ss_buf, BUF_SIZE);
    ss_last_stage = STAGE_UNSET;
    ss_frag = 0;
    ss_cipher_ctx = wmem_new0(wmem_file_scope(), ss_cipher_ctx_t);
    ss_crypto->ctx_init(ss_crypto->cipher, ss_cipher_ctx);

    stage_map = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    nonce_map = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
    // salts = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
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

    wmem_free(wmem_file_scope(), stage_map);
    wmem_free(wmem_file_scope(), nonce_map);
    // wmem_free(wmem_file_scope(), salts);
}

/********** Crypto **********/
/**
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
    gcry_error_t err;
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

    return 0;
}

gcry_error_t ss_aead_cipher_ctx_set_key(ss_cipher_ctx_t *cipher_ctx)
{
    gcry_error_t err;

    err = ss_crypto_hkdf(GCRY_MD_SHA1,
                         cipher_ctx->salt, cipher_ctx->cipher->key_len,
                         cipher_ctx->cipher->key, cipher_ctx->cipher->key_len,
                         (uint8_t *)SUBKEY_INFO, strlen(SUBKEY_INFO),
                         cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err)
    {
        ws_error("Failed to generate subkey: %s", gcry_strerror(err));
        return err;
    }

    memset(cipher_ctx->nonce, 0, cipher_ctx->cipher->nonce_len);

    err = gcry_cipher_setkey(cipher_ctx->cipher->hd, cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err)
    {
        ws_error("Failed to set cipher key: %s", gcry_strerror(err));
        return err;
    }

    return 0;
}

int ss_crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
    size_t datal;
    datal = strlen((const char *)pass);

    gcry_md_hd_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int addmd;
    unsigned int i, j, mds;

    mds = gcry_md_get_algo_dlen(GCRY_MD_MD5);

    if (pass == NULL)
        return key_len;

    gcry_error_t err;
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
    gcry_error_t err;
    ss_cipher_t *cipher;

    if (method < AEAD_CIPHER_AES128GCM || method >= AEAD_CIPHER_NUM)
    {
        ws_error("Illegal method: %d", method);
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
        ws_error("Unsupported cipher: xchacha20-ietf-poly1305");
        break;
#endif
    default:
        err = GPG_ERR_UNKNOWN_ALGORITHM;
        break;
    }
    if (err)
    {
        ws_error("Failed to initialize the cipher: %s", gcry_strerror(err));
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
            ws_error("Invalid cipher name: %s, use chacha20-ietf-poly1305 instead", method);
            m = AEAD_CIPHER_CHACHA20POLY1305IETF;
        }
    }
    return ss_aead_key_init(m, pass, key);
}

ss_crypto_t *ss_crypto_init(const char *password, const char *key, const char *method)
{
    int i, m = -1;

    if (method != NULL)
    {
        // NOTE: Stream ciphers are deprecated
        for (i = 0; i < AEAD_CIPHER_NUM; i++)
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

    ws_error("Invalid cipher name: %s", method);
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

/********** Debugging **********/
void debug_print_key_value(const void *key, const void *value, void *user_data _U_)
{
    printf("%u -> %u\n", *(uint32_t *)key, *(uint32_t *)value);
}

void debug_print_hash_table(wmem_map_t *hash_table, const char *var_name)
{
    printf("[DEBUG] %s:\n", var_name);
    wmem_map_foreach(hash_table, (GHFunc)debug_print_key_value, NULL);
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
