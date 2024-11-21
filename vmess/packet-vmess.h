/* packet-vmess.h
 *
 * Updated routines for VMess protocol packet dissection
 * By Linxiao Yu. <yulinxiaoybbb@gmail.com>
 *
 * Definitions for VMess packet disassembly structures and routines
 * By Linxiao Yu. <yulinxiaoybbb@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <gcrypt.h>

void proto_register_vmess(void);
void proto_reg_handoff_vmess(void);
int dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
int dissect_vmess_response_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
int dissect_vmess_data_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
int dissect_vmess(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);


/* Used to do the overall initialization. */
void vmess_init(void);


/* Used to do the overall clean-up. */
void vmess_cleanup(void);

void vmess_free(gpointer data);



#define TLS_SIGNUM (gint)5 /* The number of TLS record types. */

#define VMESS_PROTO_DATA_REQRES	0
#define VMESS_PROTO_DATA_INFO	1

#define VMESS_TCP_PORT 20332 /* Not IANA registed */



#define VMESS_CIPHER_CTX gcry_cipher_hd_t

typedef struct _vmess_key_map_t {
    GHashTable* header_key;
    GHashTable* header_iv;
    GHashTable* data_key;
    GHashTable* data_iv;
    GHashTable* response_token; // Check if the response matches the request.
} vmess_key_map_t;

/* Used to clean the VMess key map. */
static void vmess_common_clean(vmess_key_map_t* km);

/* Used to initialize the VMess key map. */
static void vmess_common_init(vmess_key_map_t* km);

typedef enum {
    MODE_NONE,      /* No encryption, for debug only */
    MODE_CFB,       /* CFB mode */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} vmess_cipher_mode_t;

typedef struct _VMessCipherSuite {
    vmess_cipher_mode_t mode;
} VMessCipherSuite;

typedef struct {
    /* In this version, I decide to use GByteArray instead of StringInfo used in packet-tls-utils.h
     * to record key/iv or other things. Since GByteArray has an intrinsic length field, it should
     * avoid some cumbersome operations (I hope so).
     */
    GByteArray* write_iv;
    const VMessCipherSuite* cipher_suite;
    VMESS_CIPHER_CTX evp;
} VMessDecoder;

typedef struct {
    VMessDecoder data_decoder;
    VMessDecoder header_decoder;
} vmess_decrypt_info_t;

typedef struct vmess_master_key_match_group {
    const char* re_group_name;
    GHashTable* key_ht;
} vmess_key_match_group_t;



/* Routines */

//static void vmess_keylog_read(const gchar* vmess_keylog_filename, FILE** keylog_file,
//    const vmess_key_map_t* km);
void vmess_keylog_read(void);

/* Remove all entries for each table in the key map. */
void vmess_keylog_remove(vmess_key_map_t* mk);

/*
 * Reset the keylog file.
 */
void vmess_keylog_reset(void);

void vmess_keylog_process_line(const char* data, const guint8 datalen, vmess_key_map_t* km);

/*
 * Must be called before attempting decryption.
 */
gboolean vmess_decrypt_init(void);

/**
 * Since VMess auth is 16-byte long, we could split the auth into 4-byte long and hash.
 */



/*
 * User preference related variables.
 * See Section 2.6 in README.dissector for some guide.
 * 
 * See packet-wireguard.c for instructions on how to register pref in practice.
 */

#define VMESS_AUTH_LENGTH (guint) 16
#define VMESS_RESPONSE_HEADER_LENGTH (guint) 40
#define VMESS_DATA_HEADER_LENGTH (guint) 2

// reassembly table for streaming chunk mode
static reassembly_table proto_vmess_streaming_reassembly_table;



/** information about a request and response on a VMess conversation. */
typedef struct _vmess_req_res_t {
    /** the running number on the conversation */
    guint32 number;
    /** frame number of the request */
    guint32 req_framenum;
    /** frame number of the corresponding response */
    guint32 res_framenum;
    /** timestamp of the request */
    //nstime_t req_ts;
    //guint    response_code;
    //gchar* request_method;
    //gchar* vmess_host;
    //gchar* request_uri;
    //gchar* full_uri;
    gboolean req_has_range;
    gboolean resp_has_range;

    /** private data used by vmess dissector */
    void* private_data;
} vmess_req_res_t;

typedef struct _vmess_conv_t {
    gboolean req_decrypted;     /* Used to check if the VMess header is decrypted */
    gboolean data_decrypted;    /* Used to check if the Data is decrypted */
    gboolean resp_decrypted;    /* Used to check if the Response Header is decrypted */
    streaming_reassembly_info_t* reassembly_info;
    //vmess_decrypt_info_t* vmess_decrypt_info;
    VMessDecoder* data_decoder;
    VMessDecoder* header_decoder;
    gchar* auth;
    /* Used to speed up desegmenting of chunked Transfer-Encoding. */
    wmem_map_t* chunk_offsets_fwd;
    wmem_map_t* chunk_offsets_rev;

    /* Fields related to proxied/tunneled/Upgraded connections. */
    guint32	 startframe;	/* First frame of proxied connection */
    int    	 startoffset;	/* Offset within the frame where the new protocol begins. */
    dissector_handle_t next_handle;	/* New protocol */

    gchar* websocket_protocol;	/* Negotiated WebSocket protocol */
    gchar* websocket_extensions;	/* Negotiated WebSocket extensions */
    /* Server address and port, known after first server response */
    guint16 server_port;
    address server_addr;
    /** the tail node of req_res */
    vmess_req_res_t* req_res_tail;
    /** Information from the last request or response can
     * be found in the tail node. It is only sensible to look
     * at on the first (sequential) pass, or after startframe /
     * startoffset on connections that have proxied/tunneled/Upgraded.
     */

     /* TRUE means current message is chunked streaming, and not ended yet.
      * This is only meaningful during the first scan.
      */
    gboolean message_ended;

    /* Used for req/res matching */
    GSList* req_list;
    wmem_map_t* matches_table;

} vmess_conv_t;

/**
 * Encapsulate the conv_data fetching process:
 * 
 *  conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
 *  if (!conv_data) {
 *      conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
 *      conversation_add_proto_data(conversation, proto_vmess, conv_data);
 *  }
 *  if (!conv_data->reassembly_info) {
 *      conv_data->reassembly_info = streaming_reassembly_info_new();
 *  }
 * 
 * into a single routine.
 */
vmess_conv_t* get_vmess_conv(conversation_t* conversation, const int proto_vmess);

/* request or response streaming reassembly data */
typedef struct {
    /* reassembly information only for request or response with chunked and streaming data */
    streaming_reassembly_info_t* streaming_reassembly_info;
    /* subdissector handler for request or response with chunked and streaming data */
    dissector_handle_t streaming_handle;
    /* message being passed to subdissector if the request or response has chunked and streaming data */
    //media_content_info_t* content_info;
    //headers_t* main_headers;
} vmess_streaming_reassembly_data_t;

/* vmess request or response private data */
typedef struct {
    /* direction of request message */
    int req_fwd_flow;
    /* request or response streaming reassembly data */
    vmess_streaming_reassembly_data_t* req_streaming_reassembly_data;
    vmess_streaming_reassembly_data_t* res_streaming_reassembly_data;
} vmess_req_res_private_data_t;


/* Some util functions */
bool gbytearray_eq(const GByteArray*, const GByteArray*);

bool char_array_eq(const char*, const char*, size_t);

/*
 * Search if the tvb contains the needle, start at offset, end at offset + maxlength, if maxlength
 * is -1, then search until the end of the tvb. Returns the offset of the first match if found,
 * or -1 otherwise.
 * NOTE: This function will strip the terminating nul of the needle.
 */
gint tvb_find_bytes(tvbuff_t* tvb, const gint offset, const gint max_length, const char* needle);

/*
 * Search if the tvb contains the TLS signatures. If the tvb contains any of
 * the signature, then return the first offset (>=0) of all the possible match.
 * Otherwise, return -1.
 */
gint tvb_find_TLS_signiture(tvbuff_t* tvb);

/*
 * Search a string (needle) in another string (haystack), like memmem in glibc, except that we
 * return the index instead of the pointer to the match. It returns -1 if no match was found.
 */
gint mem_search(const char* haystack, guint haystack_size, const char* needle, guint needle_size);

/* Debug relavant variables and functions */
/* From packet-ssh.c, packet-tls.c and packet-tls-utils.c */
#define VMESS_DECRYPT_DEBUG

#ifdef VMESS_DECRYPT_DEBUG /* {{{ */

static const gchar* vmess_debug_file_name;
#define VMESS_DEBUG_USE_STDERR "-"

static FILE* vmess_debug_file;

void vmess_set_debug(const gchar* name);

void vmess_debug_printf(const gchar* fmt, ...);

void vmess_prefs_apply_cb(void);

void vmess_debug_flush(void);

void vmess_debug_print_hash_table(GHashTable* hash_table);

void vmess_debug_print_key_value(gpointer key, gpointer value, gpointer user_data);
#else
#define vmess_set_debug(name)
#define vmess_debug_flush()
#define vmess_debug_print_hash_table(hash_table)
#define vmess_debug_print_key_value(key, value, user_data)
#endif /* VMESS_DECRYPT_DEBUG }}} */

/*
 * Write the content of a string into its hex form. For example, given the string
 * "0102030aefbb", we convert each octet into a single byte into the target.
 * After conversion, the result should be "\x01\x02\x03\x0a\xef\xbb".
 *
 * @param in    The string to be converted.
 * @param out   The output hex-formed string.
 * @param datalen   The length of the input string.
 *
 * @return  TRUE if succeeded, FALSE otherwise.
 */
gboolean from_hex(const char* in, GByteArray* out, guint datalen);

/**
 * This is the raw char* version of from_hex, used for handling the raw bytes
 * read from tvb, where looking up the GHashMap with GByteArray would be cumbersome.
 * 
 * NOTE that the caller is responsbile for memory allocattion with reasonable size.
 */
gboolean from_hex_raw(const char* in, gchar * out, guint datalen);
