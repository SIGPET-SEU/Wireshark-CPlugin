/****************Trojan Register*********************/

void proto_register_trojan(void); // 1. 注册 Trojan 协议
static int dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_); // 2. Trojan 协议 调用的解析器
void proto_reg_handoff_trojan(void); // 3. 将 Trojan 协议和解析器加载到 tls.port 中
/****************Trojan Register End*********************/


/****************Trojan Utils Function*********************/

static int dissect_trojan_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static int dissect_trojan_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static bool dissect_trojan_over_http1(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static int dissect_trojan_over_http2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
static bool dissect_trojan_heur_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);

bool char_array_eq(const char* arr_1, const char* arr_2, size_t len);
gint tvb_find_crlf_pos(tvbuff_t* tvb);

/****************Trojan Utils Function End******************/

#define TROJAN_TCP_PORT 49637
#define TROJAN_PASSWORD_LENGTH (guint)56
#define TROJAN_CRLF_LENGTH (guint)2
#define TROJAN_PORT_LENGTH (guint)2

static int proto_trojan;

static dissector_handle_t trojan_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t h2_handle;
static dissector_handle_t http_handle;
static dissector_handle_t http_tcp_handle;
static dissector_handle_t http_tls_handle;

const char* TROJAN_CRLF = "\x0d\x0a";

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
static int hf_trojan_crlf; // CRLF
static int hf_trojan_cmd;
static int hf_trojan_atype;
static int hf_trojan_dst_addr;
static int hf_trojan_dst_port;
static int hf_trojan_tunnel_data; // 数据流

/****************Trojan Fields End******************/

/****************Trojan ETT Fields******************/

static gint ett_trojan;

static gint ett_msg_fragment;
static gint ett_msg_fragments;

/****************Trojan ETT Fields End******************/
