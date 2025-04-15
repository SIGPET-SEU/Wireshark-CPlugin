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
/* ATYP in Relay Header */
#define RELAY_HEADER_ATYP_IPV4 1
#define RELAY_HEADER_ATYP_DOMAINNAME 3
#define RELAY_HEADER_ATYP_IPV6 4
/* Return Codes */
#define RET_CRYPTO_ERROR -2
#define RET_CRYPTO_NEED_MORE -1
#define RET_OK 0

/********** Macros **********/
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

/********** Typedefs **********/
typedef enum
{
    SS_UNKNOWN,
    SS_SALT,
    SS_RELAY_HEADER,
    SS_STREAM_DATA
} SsRecordType;

typedef struct ss_cipher
{
    int method;
    uint32_t nonce_len;
    uint32_t key_len;
    uint32_t tag_len;
    uint8_t key[MAX_KEY_LENGTH];
    gcry_cipher_hd_t hd;
} ss_cipher_t;

typedef struct ss_cipher_ctx
{
    bool init;
    ss_cipher_t *cipher;
    uint8_t salt[MAX_KEY_LENGTH];
    uint8_t skey[MAX_KEY_LENGTH];
    uint8_t nonce[MAX_NONCE_LENGTH];
} ss_cipher_ctx_t;

typedef struct ss_crypto
{
    ss_cipher_t *cipher;
    int (*const decrypt)(ss_cipher_ctx_t *cipher_ctx, uint8_t **p, uint8_t *c, uint8_t *n, uint32_t **plen, uint32_t clen);
    void (*const ctx_init)(ss_cipher_t *, ss_cipher_ctx_t *);
    void (*const ctx_release)(ss_cipher_ctx_t *);
} ss_crypto_t;

typedef struct ss_conv_data
{
    address *server_addr;
    bool relay_header_dissection_done; // A flag to indicate if the relay header has been dissected
    ss_cipher_ctx_t *client_cipher_ctx;
    ss_cipher_ctx_t *server_cipher_ctx;
    streaming_reassembly_info_t *reassembly_info;
} ss_conv_data_t;

typedef struct ss_message_info
{
    uint8_t *plain_data;
    uint32_t plain_len;
    uint32_t cipher_len;
    int offset;
    SsRecordType type;
    uint8_t *salt;
    uint8_t *skey;
    uint8_t *nonce;
    struct ss_message_info *next;
} ss_message_info_t;

typedef struct ss_packet_info
{
    bool is_from_server;
    ss_message_info_t *messages;
} ss_packet_info_t;

/********** Function Prototypes **********/
/* Dissectors */
unsigned get_ss_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_);
int dissect_ss_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
int dissect_ss_encrypted_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
int dissect_ss_salt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
int dissect_ss_relay_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
int dissect_ss_stream_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
/* Registers */
void proto_reg_handoff_ss(void);
void proto_register_ss(void);
/* Routines */
void ss_init_routine(void);
void ss_cleanup_routine(void);
/* Conversation */
ss_conv_data_t *get_ss_conv_data(conversation_t *conversation, const int proto_ss);
/* Crypto */
int ss_aead_decrypt(ss_cipher_ctx_t *ctx, uint8_t **p, uint8_t *c, uint8_t *n, uint32_t **plen, uint32_t clen);
gcry_error_t ss_aead_cipher_ctx_set_key(ss_cipher_ctx_t *cipher_ctx);
ss_crypto_t *ss_crypto_init(const char *password, const char *key, const char *method);
void ss_aead_ctx_init(ss_cipher_t *cipher, ss_cipher_ctx_t *cipher_ctx);
void ss_aead_ctx_release(ss_cipher_ctx_t *cipher_ctx);
/* Utils */
uint16_t load16_be(const void *s);
void sodium_increment(unsigned char *n, const uint32_t nlen);
int validate_hostname(const char *hostname, const int hostname_len);
/* Debugging */
typedef void (*PrintFunc)(const void *key, const void *value, void *user_data);
void debug_print_uint_key_int_value(const void *key, const void *value, void *user_data);
void debug_print_uint_key_uint_value(const void *key, const void *value, void *user_data);
void debug_print_uint_key_uint8_array_value(const void *key, const void *value, void *user_data);
void debug_print_hash_map(wmem_map_t *hash_map, const char *var_name, PrintFunc print_func);
void debug_print_list(wmem_list_t *list, const char *var_name);
void debug_print_uint8_array(const uint8_t *array, uint32_t len, const char *var_name);
void debug_print_tvb(tvbuff_t *tvb, const char *var_name);
