
/* 1. 注册 Trojan 协议  */
void proto_register_trojan(void);
/* 2. Trojan 协议 调用的解析器 */
static int dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
/* 3. 将 Trojan 协议和解析器加载到 tls.port 中  */
void proto_reg_handoff_trojan(void);

/* trojan 协议的 request 解析器 */
static int dissect_trojan_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
bool char_array_eq(const char* arr_1, const char* arr_2, size_t len);

#define TROJAN_TCP_PORT 49637
#define TROJAN_PASSWORD_LENGTH (guint)56
#define TROJAN_CRLF_LENGTH (guint)2

static int proto_trojan;

static dissector_handle_t trojan_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t h2_handle;

const char* CRLF = "\x0d\x0a";

#define TLS_SIGNUM (gint)5 /* The number of TLS record types. */

static char* TLS_signiture[TLS_SIGNUM] = {
    "\x14\x03\x03", /* Change Cipher Spec */
    "\x15\x03\x03", /* Alert */
    "\x16\x03\x03", /* Handshake */
    "\x16\x03\x01", /* Handshake Legacy */
    "\x17\x03\x03"  /* Application Data */
};

/****************Trojan Fields******************/

static int hf_trojan_password;
static int hf_trojan_cmd;
static int hf_trojan_atype;
static int hf_trojan_dst_addr;
static int hf_trojan_dst_port;
static int hf_trojan_tunnel_data; /* 数据流 */

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

/****************Trojan Fields End******************/

/****************Trojan ETT Fields******************/

static gint ett_trojan;

static gint ett_msg_fragment;
static gint ett_msg_fragments;

/****************Trojan ETT Fields End******************/


// reassembly table for streaming chunk mode
static reassembly_table proto_trojan_streaming_reassembly_table;

/** information about a request and response on a trojan conversation. */
typedef struct _trojan_req_res_t {
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
    //gchar* trojan_host;
    //gchar* request_uri;
    //gchar* full_uri;
    gboolean req_has_range;
    gboolean resp_has_range;

    /** private data used by trojan dissector */
    void* private_data;
} trojan_req_res_t;

typedef struct _trojan_conv_t {
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
    trojan_req_res_t* req_res_tail;
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

} trojan_conv_t;

/* request or response streaming reassembly data */
typedef struct {
    /* reassembly information only for request or response with chunked and streaming data */
    streaming_reassembly_info_t* streaming_reassembly_info;
    /* subdissector handler for request or response with chunked and streaming data */
    dissector_handle_t streaming_handle;
    /* message being passed to subdissector if the request or response has chunked and streaming data */
    //media_content_info_t* content_info;
    //headers_t* main_headers;
} trojan_streaming_reassembly_data_t;

/* trojan request or response private data */
typedef struct {
    /* direction of request message */
    int req_fwd_flow;
    /* request or response streaming reassembly data */
    trojan_streaming_reassembly_data_t* req_streaming_reassembly_data;
    trojan_streaming_reassembly_data_t* res_streaming_reassembly_data;
} trojan_req_res_private_data_t;

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
