/* packet-shadowsocks.h
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

/********** Constants **********/
#define SHADOWSOCKS_TCP_PORT 8388
/* Ciphers */
// NOTE: XChaCha20-Poly1305-IETF is removed in upstream, and not supported by libgcrypt
#ifdef FS_HAVE_XCHACHA20IETF
#define AEAD_CIPHER_NUM 5
#else
#define AEAD_CIPHER_NUM 4
#endif
#define AEAD_CIPHER_NONE (-1)
#define AEAD_CIPHER_AES128GCM 0
#define AEAD_CIPHER_AES192GCM 1
#define AEAD_CIPHER_AES256GCM 2
#define AEAD_CIPHER_CHACHA20POLY1305IETF 3
#ifdef FS_HAVE_XCHACHA20IETF
#define AEAD_CIPHER_XCHACHA20POLY1305IETF 4
#endif
/* Key */
#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH 32
#define MAX_MD_SIZE 64
#define SUBKEY_INFO "ss-subkey"
#define IV_INFO "ss-iv"
/* Buffer */
#define BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size
/* Decryption */
#define ADDRTYPE_MASK 0xF
#define CHUNK_SIZE_LEN 2
#define CHUNK_SIZE_MASK 0x3FFF
/* Stages */
#define STAGE_UNKNOWN -3
#define STAGE_UNSET -2
// NOTE: The 2 stages above are defined by myself
#define STAGE_ERROR -1    /* Error detected                   */
#define STAGE_INIT 0      /* Initial stage                    */
#define STAGE_HANDSHAKE 1 /* Handshake with client            */
#define STAGE_RESOLVE 4   /* Resolve the hostname             */
#define STAGE_STREAM 5    /* Stream between client and server */
#define STAGE_STOP 6      /* Server stop to response          */
/* Content */
#define MAX_HOSTNAME_LEN 256 // FQCN <= 255 characters
#define MAX_PORT_STR_LEN 6   // PORT < 65536
#define INET_SIZE 4
#define INET6_SIZE 16
/* Return Codes */
#define RET_WRONG_STAGE -3
#define RET_CRYPTO_ERROR -2
#define RET_CRYPTO_NEED_MORE -1
#define RET_OK 0

/********** Macros **********/
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

/********** Typedefs **********/
typedef struct ss_buffer
{
    size_t idx;
    size_t len;
    size_t capacity;
    char *data;
} ss_buffer_t;

typedef struct ss_cipher
{
    int method;
    size_t nonce_len;
    size_t key_len;
    size_t tag_len;
    uint8_t key[MAX_KEY_LENGTH];
    gcry_cipher_hd_t hd;
} ss_cipher_t;

typedef struct ss_cipher_ctx
{
    uint32_t init;
    uint64_t counter;
    // ss_cipher_evp_t *evp;
    // aes256gcm_ctx *aes256gcm_ctx;
    ss_cipher_t *cipher;
    ss_buffer_t *chunk;
    uint8_t salt[MAX_KEY_LENGTH];
    uint8_t skey[MAX_KEY_LENGTH];
    uint8_t nonce[MAX_NONCE_LENGTH];
} ss_cipher_ctx_t;

typedef struct ss_crypto
{
    ss_cipher_t *cipher;

    // int (*const encrypt_all)(ss_buffer_t *, ss_cipher_t *, size_t);
    // int (*const decrypt_all)(ss_buffer_t *, ss_cipher_t *, size_t);
    // int (*const encrypt)(ss_buffer_t *, ss_cipher_ctx_t *, size_t);
    int (*const decrypt)(ss_buffer_t *, ss_cipher_ctx_t *, size_t);

    void (*const ctx_init)(ss_cipher_t *, ss_cipher_ctx_t *);
    void (*const ctx_release)(ss_cipher_ctx_t *);
} ss_crypto_t;

/********** Function Prototypes **********/
/* Register */
void proto_reg_handoff_ss(void);
void proto_register_ss(void);
/* Routine */
void ss_init_routine(void);
void ss_cleanup_routine(void);
/* Buffer Operations */
int ss_balloc(ss_buffer_t *ptr, size_t capacity);
int ss_brealloc(ss_buffer_t *ptr, size_t len, size_t capacity);
void ss_bfree(ss_buffer_t *ptr);
int ss_bprepend(ss_buffer_t *dst, ss_buffer_t *src, size_t capacity);
/* Crypto */
gcry_error_t ss_aead_cipher_ctx_set_key(ss_cipher_ctx_t *cipher_ctx);
ss_crypto_t *ss_crypto_init(const char *password, const char *key, const char *method);
int aead_decrypt(ss_buffer_t *ciphertext, ss_cipher_ctx_t *cipher_ctx, size_t capacity);
void ss_aead_ctx_init(ss_cipher_t *cipher, ss_cipher_ctx_t *cipher_ctx);
void ss_aead_ctx_release(ss_cipher_ctx_t *cipher_ctx);
/********** Utils **********/
uint16_t load16_be(const void *s);
void sodium_increment(unsigned char *n, const size_t nlen);
/* Debugging */
void debug_print_hash_table(wmem_map_t *hash_table, const char *var_name);