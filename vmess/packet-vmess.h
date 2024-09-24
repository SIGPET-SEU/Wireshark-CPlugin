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

void proto_register_vmess(void);
void proto_reg_handoff_vmess(void);
static int dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static int dissect_vmess_response_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static int dissect_vmess_data_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static int dissect_vmess(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static void vmess_keylog_read(void);

/*
 * Reset the keylog file.
 */
static void vmess_keylog_reset(void);

static void vmess_keylog_process_lines(const void* data, guint datalen);

/*
 * Must be called before attempting decryption.
 */
static gboolean vmess_decrypt_init(void);

static dissector_handle_t vmess_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t vmess_request_handle;

#define TLS_SIGNUM (gint)5 /* The number of TLS record types. */

static char* TLS_signiture[TLS_SIGNUM] = {
    "\x14\x03\x03", /* Change Cipher Spec */
    "\x15\x03\x03", /* Alert */
    "\x16\x03\x03", /* Handshake */
    "\x16\x03\x01", /* Handshake Legacy */
    "\x17\x03\x03"  /* Application Data */
};

#define VMESS_PROTO_DATA_REQRES	0
#define VMESS_PROTO_DATA_INFO	1

#define VMESS_TCP_PORT 20332 /* Not IANA registed */

static bool vmess_desegment = true; /* VMess is run atop of TCP */

/* Keylog and decryption related variables */
static bool vmess_decryption_supported;
static const gchar* pref_keylog_file;
/*
 * Key log file handle. Opened on demand (when keys are actually looked up),
 * closed when the capture file closes.
 */
static FILE* vmess_keylog_file;


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

static int proto_vmess;

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
    streaming_reassembly_info_t* reassembly_info;
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


/****************VMess Fields******************/
static int hf_vmess_request_auth;
static int hf_vmess_response_header;
static int hf_vmess_payload_length;

// heads for displaying reassembly information
static int hf_msg_fragments;
static int hf_msg_fragment;
static int hf_msg_fragment_overlap;
static int hf_msg_fragment_overlap_conflicts;
static int hf_msg_fragment_multiple_tails;
static int hf_msg_fragment_too_long_fragment;
static int hf_msg_fragment_error;
static int hf_msg_fragment_count;
static int hf_msg_reassembled_in;
static int hf_msg_reassembled_length;
static int hf_msg_body_segment;
/**************VMess Fields End****************/

/**************VMess ETT Fileds****************/

static int ett_vmess;

static gint ett_msg_fragment;
static gint ett_msg_fragments;

/************VMess ETT Fileds End**************/

static const fragment_items msg_frag_items = {
    &ett_msg_fragment,
    &ett_msg_fragments,
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    &hf_msg_reassembled_in,
    &hf_msg_reassembled_length,
 };

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
#else
#define vmess_set_debug(name)
#define vmess_debug_flush()
#endif /* VMESS_DECRYPT_DEBUG }}} */
