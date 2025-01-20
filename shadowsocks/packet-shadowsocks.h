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
    uint8_t *derived_key;
    uint8_t *salt;
    uint8_t *subkey;
    uint8_t *nonce;
} shadowsocks_meta_cipher_t;

typedef struct _shadowsocks_conv_t
{
    shadowsocks_meta_cipher_t shadowsocks_meta_cipher;

    shadowsocks_server_stage_e last_stage;

    tvbuff_t *next_tvb;
} shadowsocks_conv_t;

/********** Function Prototypes **********/
void proto_reg_handoff_shadowsocks(void);
void proto_register_shadowsocks(void);

static void shadowsocks_init(void);
static void shadowsocks_cleanup(void);

static shadowsocks_conv_t *get_shadowsocks_conv(conversation_t *conv, int proto);
static void update_shadowsocks_stage(shadowsocks_server_stage_e *last_stage, shadowsocks_server_stage_e *cur_stage, uint32_t payload_size);

static void set_cipher_size(cipher_type_e cipher_type);
static gcry_error_t shadowsocks_kdf(const char *password, uint32_t password_len, uint8_t *out, uint32_t out_len);
static void init_shadowsocks_cipher_handle(shadowsocks_meta_cipher_t *meta_cipher);
static void increment(uint8_t *b, uint32_t b_len);
static uint8_t *get_shadowsocks_nonce(uint32_t *pkt_idx, uint8_t *last_nonce);
static void decrypt_payload(gcry_cipher_hd_t cipher_hd, uint8_t *in, uint8_t *nonce, uint8_t *out, uint32_t *real_size);

static void debug_display_hash_table(wmem_map_t *hash_table) _U_;