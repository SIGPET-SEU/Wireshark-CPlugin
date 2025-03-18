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
/* Packet Type */
// NOTE: For fragmented packets, XXX_NEED_MORE is used to indicate the beginning of reassembly, and XXX_REASSEMBLY is used to indicate the end of reassembly
// NOTE: For requests (client -> server): [SALT] -> [RELAY HEADER] -> [STREAM DATA] -> ... -> [STREAM DATA]
// NOTE: For responses (server -> client): [SALT & STREAM DATA] -> [STREAM DATA] -> ... -> [STREAM DATA]
#define PKT_TYPE_UNKNOWN -2
#define PKT_TYPE_ERROR -1
#define PKT_TYPE_UNSET 0
#define PKT_TYPE_SALT 1
#define PKT_TYPE_RELAY_HEADER 2
#define PKT_TYPE_SALT_WITH_STREAM_DATA 3
#define PKT_TYPE_STREAM_DATA 4
#define PKT_TYPE_SALT_NEED_MORE 11
#define PKT_TYPE_RELAY_HEADER_NEED_MORE 12
#define PKT_TYPE_SALT_WITH_STREAM_DATA_NEED_MORE 13
#define PKT_TYPE_STREAM_DATA_NEED_MORE 14
#define PKT_TYPE_SALT_REASSEMBLY 21
#define PKT_TYPE_RELAY_HEADER_REASSEMBLY 22
#define PKT_TYPE_SALT_WITH_STREAM_DATA_REASSEMBLY 23
#define PKT_TYPE_STREAM_DATA_REASSEMBLY 24
/* Content */
#define MAX_HOSTNAME_LEN 256 // FQCN <= 255 characters
#define MAX_PORT_STR_LEN 6   // PORT < 65536
#define INET_SIZE 4
#define INET6_SIZE 16
/* ATYP in Relay Header */
#define RELAY_HEADER_ATYP_IPV4 1
#define RELAY_HEADER_ATYP_DOMAINNAME 3
#define RELAY_HEADER_ATYP_IPV6 4
/* Return Codes */
#define RET_WRONG_PKT_TYPE -3
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
    ss_cipher_t *cipher;
    ss_buffer_t *chunk;
    uint8_t salt[MAX_KEY_LENGTH];
    uint8_t skey[MAX_KEY_LENGTH];
    // uint8_t nonce[MAX_NONCE_LENGTH];
} ss_cipher_ctx_t;

typedef struct ss_crypto
{
    ss_cipher_t *cipher;

    // int (*const decrypt_all)(ss_buffer_t *, ss_cipher_t *, size_t);
    // int (*const decrypt)(ss_buffer_t *, ss_cipher_ctx_t *, size_t);
    void (*const ctx_init)(ss_cipher_t *, ss_cipher_ctx_t *);
    void (*const ctx_release)(ss_cipher_ctx_t *);
} ss_crypto_t;

typedef struct ss_conv_data
{
    address *server_addr;

    ss_cipher_ctx_t *request_cipher_ctx;
    ss_cipher_ctx_t *response_cipher_ctx;

    /* Double Linked Lists */
    wmem_list_t *request_pkt_order_list;
    wmem_list_t *response_pkt_order_list;

    /* Hash Tables (key: pinfo->num) */
    wmem_map_t *pkt_type_map; // value: int
    wmem_map_t *nonce_map;    // value: uint8_t array
    wmem_map_t *salts;        // NOTE: `shadowsocks-libev` uses a bloom filter to store and check salts. Here a hash table is used instead.

    streaming_reassembly_info_t *reassembly_info;
} ss_conv_data_t;

typedef int ss_pkt_type_t;

typedef void (*PrintFunc)(const void *key, const void *value, void *user_data);

/********** Function Prototypes **********/
/* Dissectors */
ss_pkt_type_t detect_ss_pkt_type(tvbuff_t *tvb, uint32_t pinfo_num, ss_conv_data_t *conv_data, bool is_request);
int dissect_ss_salt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
int dissect_ss_relay_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
int dissect_ss_stream_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ss_tree, ss_conv_data_t *conv_data);
tvbuff_t *dissect_ss_encrypted_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, ss_conv_data_t *conv_data, bool is_request, bool reassembly_flag);
int dissect_ss_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
unsigned get_ss_salt_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb _U_, int offset _U_, void *data _U_);
unsigned get_ss_stream_data_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, void *data _U_);
unsigned get_ss_salt_with_stream_data_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, void *data _U_);
/* Registers */
void proto_reg_handoff_ss(void);
void proto_register_ss(void);
/* Routines */
void ss_init_routine(void);
void ss_cleanup_routine(void);
/* Conversation */
ss_conv_data_t *get_ss_conv_data(conversation_t *conversation, const int proto_ss);
/* Crypto */
int ss_aead_decrypt(ss_cipher_ctx_t *ctx, uint8_t **p, uint8_t *c, uint8_t *n, size_t **plen, size_t clen);
gcry_error_t ss_aead_cipher_ctx_set_key(ss_cipher_ctx_t *cipher_ctx);
ss_crypto_t *ss_crypto_init(const char *password, const char *key, const char *method);
void ss_aead_ctx_init(ss_cipher_t *cipher, ss_cipher_ctx_t *cipher_ctx);
void ss_aead_ctx_release(ss_cipher_ctx_t *cipher_ctx);
/* Buffer Operations */
int ss_balloc(ss_buffer_t *ptr, size_t capacity);
int ss_brealloc(ss_buffer_t *ptr, size_t len, size_t capacity);
void ss_bfree(ss_buffer_t *ptr);
int ss_bprepend(ss_buffer_t *dst, ss_buffer_t *src, size_t capacity);
/* Utils */
uint16_t load16_be(const void *s);
void sodium_increment(unsigned char *n, const size_t nlen);
int validate_hostname(const char *hostname, const int hostname_len);
int cmp_list_frame_uint_data(const void *a, const void *b);
ss_pkt_type_t get_prev_pkt_type(wmem_list_frame_t *frame, wmem_map_t *pkt_type_map);
void get_nonce(uint32_t pinfo_num, uint8_t **nonce, wmem_list_t *pkt_order_list, wmem_map_t *nonce_map, bool reassembly_flag);
/* Debugging */
void debug_print_uint_key_int_value(const void *key, const void *value, void *user_data);
void debug_print_uint_key_uint_value(const void *key, const void *value, void *user_data);
void debug_print_uint_key_uint8_array_value(const void *key, const void *value, void *user_data);
void debug_print_hash_map(wmem_map_t *hash_map, const char *var_name, PrintFunc print_func);
void debug_print_list(wmem_list_t *list, const char *var_name);
void debug_print_uint8_array(const uint8_t *array, size_t len, const char *var_name);
void debug_print_tvb(tvbuff_t *tvb, const char *var_name);