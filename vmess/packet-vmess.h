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
#include <stdarg.h> /* For variable number of args in VMess KDF */

/* This should be put in tfs.h, but the compiler complains that initializer is not a constant */
const true_false_string tfs_set_notset_vmess = { "Set", "Not set" };

#define TLS_SIGNUM (gint)5 /* The number of TLS record types. */

#define VMESS_PROTO_DATA_REQRES	0
#define VMESS_PROTO_DATA_INFO	1

#define VMESS_TCP_PORT 20332 /* Not IANA registed */

#define VMESS_AUTH_LENGTH (guint) 16
#define VMESS_RESPONSE_HEADER_LENGTH (guint) 40
#define VMESS_DATA_HEADER_LENGTH (guint) 2

/* Protocol register and dissection routines */
void proto_register_vmess(void);
void proto_reg_handoff_vmess(void);
int dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
int dissect_vmess_response_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
int dissect_vmess_data_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
int dissect_vmess(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);

/* Protocol data structure init and cleanup routines */
/* Used to do the overall initialization. */
void vmess_init(void);
/* Used to do the overall clean-up. */
void vmess_cleanup(void);
void vmess_free(gpointer data);


/* VMess decryption structures and routines */
/* Error handling for libgcrypt */ 
#define GCRYPT_CHECK(gcry_error)                        \
    if (gcry_error) {                                   \
        fprintf(stderr, "Failure at line %d: %s\n",     \
                __LINE__, gcry_strerror(gcry_error));   \
        return gcry_error;                              \
    }

#define AES_128_KEY_SIZE 16

#define VMESS_CIPHER_CTX gcry_cipher_hd_t
#define GCM_IV_SIZE 12
#define POLY1305_IV_SIZE 12

#define GCM_TAG_SIZE 16
#define POLY1305_TAG_SIZE 16

typedef struct _vmess_key_map_t {
    GHashTable* req_key;
    GHashTable* req_iv;
    GHashTable* data_key;
    GHashTable* data_iv;
    GHashTable* response_token; // Check if the response matches the request.
} vmess_key_map_t;

/*
 * The C implementation of VMess HMACCreator implemented in Clash.
 * Currently, only SHA256-based HMAC is supported.
 */
#define SHA_256_BLOCK_SIZE 64

typedef struct HMACCreator_t {
    struct HMACCreator_t* parent;
    guchar* value;
    gsize value_len;
    gcry_md_hd_t* h_in, * h_out;
} HMACCreator;

/*
 * Note that it is hmac_create's duty to open hashing handles, this
 * function only takes care of setting up keys.
 */
HMACCreator*
hmac_creator_new(HMACCreator* parent, const guchar* value, gsize value_len);

/*
 * HMAC creator cleanup routine, it will clear all the memory the
 * possible parents allocated recursively.
 *
 * Since it will also close the hashing handles, the caller should
 * keep in mind to call hmac_create FIRST to avoid closing an
 * uninitialized hashing handle, which ALWAYS raises SIGSEGV error.
 *
 * NOTE: This routine also frees the param, so the caller should NOT free the param again.
 */
void
hmac_creator_free(HMACCreator* creator);

/*
 * Create HMAC using the base creator.
 */
gcry_error_t
hmac_create(const HMACCreator* creator);


/*
 * This struct is used to produce the actual nested HMAC computation.
 * It is based on the array structure, where each of the entry is a
 * hash handle.
 */
typedef struct HMACDigester_t {
    int size;
    guint* order;
    gcry_md_hd_t** head;
} HMACDigester;

/*
 * Create the digester based on the creator.
 */
HMACDigester*
hmac_digester_new(HMACCreator* creator);

/*
 * HMAC digester cleanup routine, it will clear all the memory for the digester.
 *
 * Note that all the hash handles are copies of the original ones, so the digester
 * only closes their copies. The caller is responsible to call hmac_creator_free to
 * safely free the allocated memory for that creator.
 *
 * NOTE: This routine also frees the param, so the caller should NOT free the param again.
 */
void
hmac_digester_free(HMACDigester* digester);

/*
 * This function computes nested HMAC based on iterative approach instead of
 * the recursive one which is adopted in the Golang implementation.
 */
gcry_error_t
hmac_digest(HMACDigester* digester, const guchar* msg, gssize msg_len, guchar* digest);

/*
 * This function is a convenient function to compute the digest of msg given hd, while
 * maintain the internal state of hd by creating a copy of it. Therefore, using this
 * routine will NOT change the internal state of hd.
 *
 * NOTE that the caller is responsible to allocate enough memory for param digest.
 */
gcry_error_t
hmac_digest_on_copy(gcry_md_hd_t hd, const guchar* msg, gssize msg_len, guchar* digest);


/* Used to clean the VMess key map. */
void vmess_common_clean(vmess_key_map_t* km);

/* Used to initialize the VMess key map. */
void vmess_common_init(vmess_key_map_t* km);

typedef struct vmess_cipher_suite {
    enum gcry_cipher_modes mode;
    enum gcry_cipher_algos algo;
} vmess_cipher_suite_t;

typedef struct {
    /* In this version, I decide to use GByteArray instead of StringInfo used in packet-tls-utils.h
     * to record key/iv or other things. Since GByteArray has an intrinsic length field, it should
     * avoid some cumbersome operations (I hope so).
     */
    GString* write_iv;
    const vmess_cipher_suite_t* cipher_suite;
    VMESS_CIPHER_CTX evp;
} VMessDecoder;

typedef struct vmess_master_key_match_group {
    const char* re_group_name;
    GHashTable* key_ht;
} vmess_key_match_group_t;

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

/*
 * Decoder initialization routine.
 *
 * @param algo          A cipher algorithm
 * @param key           The encryption key, since the key length could be inferred by the algorithm,
 *                      it does not need to be specified explicitly
 * @param iv            encryption IV, since the iv length could be inferred by the mode, it does not
 *                      need to be specified explicitly
 * @param flag          Some extra flag.
 */
VMessDecoder*
vmess_decoder_new(int algo, int mode, guchar* key, guchar* iv, guint flags);

/*
 * Cipher initialization routine.
 *
 * @param alg       The encryption algorithm
 * @param mode      The cipher mode
 * @param key       The encryption key
 * @param key_len   The length of the key, if set 0, automatic inference will be used
 * @param iv        The initialization IV
 * @param iv_len    The length of the iv, if set 0, automatic inference will be used
 * @param flag      The flag for encryption
 *
 * @return gboolean TRUE on success.
 */
gcry_error_t
vmess_cipher_init(gcry_cipher_hd_t* hd, int algo, int mode, guchar* key, gsize key_len, guchar* iv, gsize iv_len, guint flags);

/*
 * Key derive function for VMess.
 *
 * @param key           The original key used for key derivation
 * @param derived_key   The key derived by the KDF
 * @param num           The number of the messages for key derivation
 *
 * @return guchar*      The derived key byte buffer
 */
guchar*
vmess_kdf(const guchar* key, guint key_len, guint num, ...);

gcry_error_t
vmess_byte_decryption(VMessDecoder* decoder, const guchar* in, const gsize inl, guchar* out, gsize outl, const guchar* ad, gsize ad_len);


/* Reassembly related structures and routines */
// reassembly table 
static reassembly_table proto_vmess_streaming_reassembly_table;

typedef struct _vmess_conv_t {
    gboolean req_decrypted;     /* Used to check if the VMess header is decrypted */
    gboolean data_decrypted;    /* Used to check if the Data is decrypted */
    gboolean resp_decrypted;    /* Used to check if the Response Header is decrypted */
    streaming_reassembly_info_t* reassembly_info;
    //vmess_decrypt_info_t* vmess_decrypt_info;
    VMessDecoder* req_length_decoder;
    VMessDecoder* req_decoder;
    VMessDecoder* data_decoder;
    GString* auth;

    address srv_addr;
    guint srv_port;

    guint16 count_writer;   /* The counter for AEAD client(writer) */
    guint16 count_reader;   /* The counter for AEAD server(reader) */

    /* Fields related to proxied/tunneled/Upgraded connections. */
    guint32	 startframe;	/* First frame of proxied connection */
    int    	 startoffset;	/* Offset within the frame where the new protocol begins. */
    dissector_handle_t next_handle;	/* New protocol */
} vmess_conv_t;

/* VMess record type */
typedef enum {
    VMESS_REQUEST,
    VMESS_RESPONSE,
    VMESS_DATA,
} VMessRecordType;

/* Used to record decrypted messages for dissection. Ref: packet-ssh.c */
typedef struct _vmess_message_info_t {
    guchar* plain_data;     /**< Decrypted data. */
    guint   data_len;       /**< Length of decrypted data. */
    gint    id;             /**< Identifies the exact message within a frame
                                 (there can be multiple records in a frame). */
    struct _vmess_message_info_t* next;
    VMessRecordType type;
} vmess_message_info_t;

typedef struct {
    gboolean from_server;
    vmess_message_info_t* messages;
} vmess_packet_info_t;

/**
 * Fetch the VMess message from the packet attached to pinfo.
 */
vmess_message_info_t* get_vmess_message(packet_info* pinfo, guint record_id);

int dissect_decrypted_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_,
    vmess_message_info_t* msg);

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

/* Debug relavant variables and routines */
/* From packet-ssh.c, packet-tls.c and packet-tls-utils.c */
#define VMESS_DECRYPT_DEBUG

#ifdef VMESS_DECRYPT_DEBUG /* {{{ */

/*
 * User preference related variables.
 * See Section 2.6 in README.dissector for some guide.
 *
 * See packet-wireguard.c for instructions on how to register pref in practice.
 */
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
gboolean from_hex(const char* in, GString* out, guint datalen);

/**
 * This is the raw char* version of from_hex, used for handling the raw bytes
 * read from tvb, where looking up the GHashMap with GByteArray would be cumbersome.
 * 
 * NOTE that the caller is responsbile for memory allocattion with reasonable size.
 */
gboolean from_hex_raw(const char* in, gchar * out, guint datalen);
