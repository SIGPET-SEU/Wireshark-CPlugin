#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <glib.h>
#include <epan/wmem_scopes.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tls.h>
#include <epan/dissectors/packet-tls-utils.h>

#include "packet-trojan.h"

// heads for displaying reassembly information
REASSEMBLE_ITEMS_DEFINE(msg, "Trojan Message");

bool proto_desegment = true;

/* Common HTTP/1.1 header fields, stolen from packet-http.h */
typedef struct {
    const char* name;
    int		special;
} http_header_info;

static const value_string data_type[] = {
        { TROJAN_TLS, "TLS" },
        { TROJAN_HTTP, "HTTP" },
        { TROJAN_UNKNOWN, NULL },
};


#define HDR_NO_SPECIAL			0
#define HDR_AUTHORIZATION		1
#define HDR_AUTHENTICATE		2
#define HDR_CONTENT_TYPE		3
#define HDR_CONTENT_LENGTH		4
#define HDR_CONTENT_ENCODING		5
#define HDR_TRANSFER_ENCODING		6
#define HDR_HOST			7
#define HDR_UPGRADE			8
#define HDR_COOKIE			9
#define HDR_WEBSOCKET_PROTOCOL		10
#define HDR_WEBSOCKET_EXTENSIONS	11
#define HDR_REFERER			12
#define HDR_LOCATION			13
#define HDR_HTTP2_SETTINGS		14
#define HDR_RANGE           		15
#define HDR_CONTENT_RANGE		16

static const http_header_info headers[] = {
        { "Authorization", HDR_AUTHORIZATION },
        { "Proxy-Authorization", HDR_AUTHORIZATION },
        { "Proxy-Authenticate", HDR_AUTHENTICATE },
        { "WWW-Authenticate", HDR_AUTHENTICATE },
        { "Content-Type", HDR_CONTENT_TYPE },
        { "Content-Length", HDR_CONTENT_LENGTH },
        { "Content-Encoding", HDR_CONTENT_ENCODING },
        { "Transfer-Encoding", HDR_TRANSFER_ENCODING },
        { "Upgrade", HDR_UPGRADE },
        { "User-Agent",	HDR_NO_SPECIAL },
        { "Host", HDR_HOST },
        { "Range", HDR_RANGE },
        { "Content-Range", HDR_CONTENT_RANGE },
        { "Connection", HDR_NO_SPECIAL },
        { "Cookie", HDR_COOKIE },
        { "Accept", HDR_NO_SPECIAL },
        { "Referer", HDR_REFERER },
        { "Accept-Language", HDR_NO_SPECIAL },
        { "Accept-Encoding", HDR_NO_SPECIAL },
        { "Date", HDR_NO_SPECIAL },
        { "Cache-Control", HDR_NO_SPECIAL },
        { "Server", HDR_NO_SPECIAL },
        { "Location", HDR_LOCATION },
        { "Sec-WebSocket-Accept", HDR_NO_SPECIAL },
        { "Sec-WebSocket-Extensions", HDR_WEBSOCKET_EXTENSIONS },
        { "Sec-WebSocket-Key", HDR_NO_SPECIAL },
        { "Sec-WebSocket-Protocol", HDR_WEBSOCKET_PROTOCOL },
        { "Sec-WebSocket-Version", HDR_NO_SPECIAL },
        { "Set-Cookie", HDR_NO_SPECIAL },
        { "Last-Modified", HDR_NO_SPECIAL },
        { "X-Forwarded-For", HDR_NO_SPECIAL },
        { "HTTP2-Settings", HDR_HTTP2_SETTINGS },
        { "Pragma", HDR_NO_SPECIAL },
        { "Priority", HDR_NO_SPECIAL },
        { "ETag", HDR_NO_SPECIAL },
        { "Expires", HDR_NO_SPECIAL },
};

static unsigned
tls_record_length(tvbuff_t* tvb, int offset) {
    const guchar* raw_buf = tvb_get_ptr(tvb, offset, 5);
    guint plen = ((guint)raw_buf[3] << 8) + (guint)(raw_buf[4]) + 5;
    return plen;
}


/**
 * Passing the line and check if the line belongs to HTTP Request/Response.
 *
 * Currently, only HTTP/1.1 is supported.
 */
static bool
is_http_request_or_response(const char* line, int linelen) {
    /* Check HTTP/1.1 Response */
    if (linelen >= 8 && strncmp(line, "HTTP/1.1", 8) == 0) {
        /* We restrict to HTTP/1.1 only now */
        return true;
    }


    /* Decide whether the tvb is HTTP/1.1 Request/Response or unknown protocol */
    /* Check HTTP/1.1 Request */
    int indx = 0;
    /* Basic check if this is HTTP/1.1, OSCP seems to use HTTP/1.1 more, so currently we only consider OSCP over HTTP/1.1 */
    while (indx < linelen) {
        if (line[indx] == ' ')
            break;
        else
            indx++;
    }
    switch (indx) {
        /**
         * OCSP only use HTTP GET/POST method in request, here we use the following codes in respect with
         * packet-http.c is_http_request_or_reply function
         *
         */
    case 3:
        if (strncmp(line, "GET", indx) == 0) {
            return true;
        }
    case 4:
        if (strncmp(line, "POST", indx) == 0) {
            return true;
        }
    }

    return false;
}

/*
* Decide the upper layer of Trojan using the preface with enough preface_len. The caller
* is responsible to pass enough data to compute the data type.
*/
static int
trojan_data_type(tvbuff_t* tvb, int offset) {
    if (tvb_reported_length_remaining(tvb, offset) < 8)
        return TROJAN_ONE_MORE_SEGMENT;  /* Require more data to decide data type*/

    /* Check if the tvb is actually a TLS record */
    const char* needle = tvb_get_ptr(tvb, offset, 8);
    for (guint i = 0; i < TLS_SIGNUM; i++)
        if (memcmp(needle, TLS_signature[i], 3) == 0)
            return TROJAN_TLS;

    if (is_http_request_or_response(needle, 8))
        return TROJAN_HTTP;

    return TROJAN_UNKNOWN;
}

/* /* Find the index of HTTP header field index defined in headers */
static int
find_header_hf_value(const char* line, int linelen, unsigned header_len)
{
    unsigned i;

    if (linelen < header_len)
        return -1;

    for (i = 0; i < array_length(headers); i++) {
        if (header_len == strlen(headers[i].name) &&
            memcmp(line, headers[i].name, header_len) == 0)
            return i;
    }

    return -1;
}

/* For OCSP connection, get the length of underlying HTTP frame length, such that we could pass the
* correct tvb to the HTTP handle. Currently, only HTTP/1.1 is supported.
*
* Moreover, we now assume that the (possible imcomplete) tvb contains Content-Length field, such
* that we could decide the length of reassembly.
*
* TODO: What if the first tvb does not contain Content-Length?
*/
static unsigned
http_frame_length(tvbuff_t* tvb, int offset) {
    /* Here we need to do basic HTTP/1.1 reassembly for OCSP protocol dissection */
        /* Search for Content-Length in the tvb, iterate through lines in the obtained buffer */
    int linelen, next_offset;
    guint content_length = 0;
    const unsigned char* line;
    const unsigned char* lineend;
    int colon_offset;
    bool is_request_or_response = false;

    /* Fetch the first line */
    linelen = tvb_find_line_end(tvb, offset,
        tvb_ensure_captured_length_remaining(tvb, offset), &next_offset,
        false);



    /*
     * Get a buffer that refers to the line.
     *
     * Note that "tvb_find_line_end()" will return a value that
     * is not longer than what's in the buffer, so the
     * "tvb_get_ptr()" call won't throw an exception.
     */
    line = tvb_get_ptr(tvb, offset, linelen);
    //is_request_or_response = is_http_request_or_response(line, linelen);

    offset = next_offset; /* Start from the line right after the first line */
    while (tvb_offset_exists(tvb, offset)) {
        int value_offset;
        unsigned char c;
        int header_len;
        int hf_index;
        int value_bytes_len;
        char* value_bytes;
        const char* linep;


        linelen = tvb_find_line_end(tvb, offset,
            tvb_ensure_captured_length_remaining(tvb, offset), &next_offset,
            false);

        if (linelen < 0)
            break;

        if (linelen == 0)
            /* The scanner has reached the end of HTTP/1.1 header, plus Content-Length, and the last /r/n in the header */
            return (guint)next_offset + content_length;

        if (linelen == tvb_reported_length_remaining(tvb, offset)) {
            /* It seems that the line splits over several segments, we require ONE MORE SEGMENTS to handle this */
            return DESEGMENT_ONE_MORE_SEGMENT;
        }

        line = tvb_get_ptr(tvb, offset, linelen);
        lineend = line + linelen;

        /* Search for colon in the line */
        linep = (const unsigned char*)memchr(line, ':', linelen);
        colon_offset = linep - line;
        /*
            * Skip whitespace after the colon.
            */
        value_offset = colon_offset + 1;
        while (value_offset < linelen
            && ((c = line[value_offset]) == ' ' || c == '\t'))
            value_offset++;

        header_len = colon_offset;
        hf_index = find_header_hf_value(line, linelen, header_len);

        value_bytes_len = linelen - value_offset;
        value_bytes = (char*)malloc(value_bytes_len + 1);
        if (!value_bytes) {
            ws_critical("Failed to allocate space, dissection impossible");
            return 0;
        }

        memcpy(value_bytes, line + value_offset, value_bytes_len);
        value_bytes[value_bytes_len] = '\0';
        if (hf_index == -1) {
            return 0; /* Malformed tvb ? */
        }
        /* Get the value of content length */
        switch (headers[hf_index].special) {
        case HDR_CONTENT_LENGTH:
            content_length = g_ascii_strtoll(value_bytes, NULL, 10);
            break;
        default:
            break;  /* We only handle Content-Length case*/
        }

        free(value_bytes);
        offset = next_offset;
    }

    return 0;
}


static int
dissect_trojan_http(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    conversation_t* conversation;
    trojan_conv_t* conv_data = NULL;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = get_trojan_conv(conversation, proto_trojan);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trojan");
    col_set_str(pinfo->cinfo, COL_INFO, "HTTP over Trojan");

    /* Mark the outer TLS tunnel as Trojan layer */
    proto_tree* trojan_tree = proto_tree_get_child_nth(tree, 5);
    proto_item_set_text(trojan_tree, "Trojan");

    proto_item_set_generated(proto_tree_add_uint(trojan_tree, hf_trojan_data_type, tvb, 0, 0, TROJAN_HTTP));
    proto_item_set_generated(proto_tree_add_uint(trojan_tree, hf_trojan_data_length, tvb, 0, 0, tvb_ensure_reported_length_remaining(tvb, 0)));

    reassemble_streaming_data_and_call_subdissector(tvb, pinfo, 0,
        tvb_reported_length_remaining(tvb, 0),
        trojan_tree,
        proto_tree_get_parent_tree(trojan_tree),
        proto_trojan_streaming_reassembly_table,
        conv_data->reassembly_info,
        get_virtual_frame_num64(tvb, pinfo, tvb_reported_length_remaining(tvb, 0)),
        http_handle,
        proto_tree_get_parent_tree(tree),
        NULL,
        "Trojan",
        &msg_fragment_items,
        hf_msg_segment);

    return tvb_reported_length_remaining(tvb, 0);
}

static int
dissect_trojan_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    //tvbuff_t* next_tvb;

    port_type save_port_type;
    uint16_t save_can_desegment;

    conversation_t* conversation;
    trojan_conv_t* conv_data = NULL;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = get_trojan_conv(conversation, proto_trojan);

    // printf(trojan_keylog_file_name, "\n");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trojan");
    col_set_str(pinfo->cinfo, COL_INFO, "TLS over Trojan");

    proto_tree* trojan_tree = proto_tree_get_child_nth(tree, 5);
    proto_item_set_generated(proto_tree_add_uint(trojan_tree, hf_trojan_data_type, tvb, 0, 0, TROJAN_HTTP));
    proto_item_set_generated(proto_tree_add_uint(trojan_tree, hf_trojan_data_length, tvb, 0, 0, tvb_ensure_reported_length_remaining(tvb, 0)));
    proto_item_set_text(trojan_tree, "Trojan");

    save_port_type = pinfo->ptype;
    save_can_desegment = pinfo->can_desegment;
    pinfo->ptype = PT_NONE;
    pinfo->can_desegment = pinfo->saved_can_desegment;

    dissector_add_string("tls.alpn", "h2", h2_handle);
    //dissector_add_string("tls.alpn", "http/1.1", http_tls_handle);
    //dissector_add_string("http.upgrade", "h2", h2_handle);
    //dissector_add_string("http.upgrade", "h2c", h2_handle);

    reassemble_streaming_data_and_call_subdissector(tvb, pinfo, 0,
        tvb_reported_length_remaining(tvb, 0),
        trojan_tree,
        proto_tree_get_parent_tree(trojan_tree),
        proto_trojan_streaming_reassembly_table,
        conv_data->reassembly_info,
        get_virtual_frame_num64(tvb, pinfo, tvb_reported_length_remaining(tvb, 0)),
        tls_handle,
        proto_tree_get_parent_tree(tree),
        NULL,
        "Trojan",
        &msg_fragment_items,
        hf_msg_segment);

    dissector_delete_string("tls.alpn", "h2", h2_handle);
    //dissector_delete_string("tls.alpn", "http/1.1", http_tls_handle);
    //dissector_delete_string("http.upgrade", "h2", h2_handle);
    //dissector_delete_string("http.upgrade", "h2c", h2_handle);

    pinfo->ptype = save_port_type;
    pinfo->can_desegment = save_can_desegment;

    /* We introduce an "empty" fake Trojan layer for display filter */
    proto_item* fake_trojan_ti;
    proto_tree* fake_trojan_tree;

    fake_trojan_ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(fake_trojan_ti);
    fake_trojan_tree = proto_item_add_subtree(fake_trojan_ti, ett_trojan);

    return tvb_reported_length_remaining(tvb, 0);
}

static int
dissect_trojan_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {

    int offset = 0, second_crlf_pos;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trojan");
    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Request");

    // conversation = find_or_create_conversation(pinfo);
    //proto_get_id_by_short_name

    proto_tree* trojan_tree = proto_tree_get_child_nth(tree, 5);
    proto_item_set_text(trojan_tree, "Trojan");

    //ti = proto_tree_add_item(tls_tree, proto_trojan, tvb, 0, -1, ENC_NA);
    proto_tree_add_item(trojan_tree, hf_trojan_password, tvb, offset, TROJAN_PASSWORD_LENGTH, ENC_BIG_ENDIAN);
    offset += TROJAN_PASSWORD_LENGTH;
    proto_tree_add_item(trojan_tree, hf_trojan_crlf, tvb, offset, TROJAN_CRLF_LENGTH, ENC_BIG_ENDIAN);
    offset += TROJAN_CRLF_LENGTH;
    proto_tree_add_item(trojan_tree, hf_trojan_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(trojan_tree, hf_trojan_atype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    second_crlf_pos = tvb_find_crlf_pos(tvb_new_subset_remaining(tvb, offset));
    if (second_crlf_pos) {
        proto_tree_add_item(trojan_tree, hf_trojan_dst_addr, tvb, offset + 1, second_crlf_pos - TROJAN_PORT_LENGTH - 1, ENC_BIG_ENDIAN);// 这里为什么+1? trojan文档没写，但实际流量中，这个字节是没用的
        proto_tree_add_item(trojan_tree, hf_trojan_dst_port, tvb, offset + second_crlf_pos - TROJAN_PORT_LENGTH, TROJAN_PORT_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(trojan_tree, hf_trojan_crlf, tvb, offset + second_crlf_pos, TROJAN_CRLF_LENGTH, ENC_BIG_ENDIAN);
        proto_item_set_generated(proto_tree_add_uint(trojan_tree, hf_trojan_data_length, tvb, 0, 0, tvb_ensure_reported_length_remaining(tvb, 0)));

    }

    // todo: 后面还有数据吗?

    // return offset + second_crlf_pos + TROJAN_CRLF_LENGTH; // 
    
    return tvb_captured_length(tvb);
}

/*
* TODO: Consider use function pointer to remove redundant codes.
* 1. plen fetcher
* 2. dissection routine
*/
static int
dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    conversation_t* conversation;
    trojan_conv_t* conv_data = NULL;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = get_trojan_conv(conversation, proto_trojan);


    /* trojan request packet */
    if (is_trojan_request(tvb)) {
        //*(tlsinfo->app_handle) = trojan_handle;
        return dissect_trojan_request(tvb, pinfo, tree, data);
    }

    guint offset = 0;
    guint offset_before;
    unsigned length;
    tvbuff_t* next_tvb;

    guint plen;

    if (conv_data->conv_type == TROJAN_UNINITIALIZED)
        /* Trojan conversation type should be inferred in the first data tvb */
        conv_data->conv_type = trojan_data_type(tvb, 0);
    

    unsigned (*get_pdu_len)(tvbuff_t*, int);
    dissector_t dissect_pdu;

    switch (conv_data->conv_type) {
    case TROJAN_HTTP:
        //get_pdu_len = http_frame_length;
        dissect_pdu = dissect_trojan_http;
        break;
    case TROJAN_TLS:
        //get_pdu_len = tls_record_length;
        dissect_pdu = dissect_trojan_tls;
        break;
    default:
        goto unknown;
    }

    (*dissect_pdu)(tvb, pinfo, tree, data);


    return tvb_captured_length(tvb);
    

unknown:
    /* Not an HTTP frame, currently we simply call data dissector to handle this */

    printf("[Warning]: Cannot be parsed by trojan dissect, call data dissector\n");

    // return call_dissector_with_data(http_handle, tvb, pinfo, tree, data); // 
    return call_data_dissector(tvb, pinfo, tree);
}

static bool
dissect_trojan_heur_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {

    conversation_t* conversation;
    struct tlsinfo* tlsinfo = (struct tlsinfo*)data;

    /* found trojan request or response(tunnel data) */
    if (is_trojan_request(tvb) || is_trojan_response(tvb)) {
        conversation = find_or_create_conversation(pinfo);
        //conversation_set_dissector(conversation, trojan_handle); // conversation_get_dissector()
        dissect_trojan(tvb, pinfo, tree, data);
        //*(tlsinfo->app_handle) = trojan_handle;
        return true;
    }


    /* not trojan packet */
    // printf("[Info Frame number %d]：dissect_trojan_heur_tls return false\n", pinfo->num);



    return false;
}

void
proto_reg_handoff_trojan(void)
{

    tls_handle = find_dissector("tls");
    h2_handle = find_dissector("http2");
    http_handle = find_dissector("http"); /* For OCSP dissection */
    http_tls_handle = find_dissector("http-over-tls");

    dissector_add_uint_range_with_preference("tls.port", TROJAN_TLS_RANGE_PORT, trojan_handle);
    // dissector_add_for_decode_as("trojan", trojan_handle); // ui

    /* 将 trojan 注册到 tls 的启发式解析器中 */
    //heur_dissector_add("tls", dissect_trojan_heur_tls, "Trojan Over Tls", "trojan_over_tls", proto_trojan, HEURISTIC_ENABLE);

    //tls_heur_subdissector_list = find_heur_dissector_list("tls"); // tls 的启发式解析器列表


    //module_t* ssl_module = prefs_find_module("tls");
    //prefs_register_filename_preference(ssl_module, "trojan_keylog_file", "Trojan-Secret log filename",
    //    "Trojan keylog file name",
    //    &(trojan_keylog_file_name), false);
}

void
proto_register_trojan(void)
{
    static hf_register_info hf[] = {
        { &hf_trojan_password,
            { "Trojan Password", "trojan.password",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_crlf,
            { "Trojan CRLF", "trojan.CRLF",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_cmd,
            { "Trojan Command", "trojan.cmd",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_atype,
            { "Trojan Address Type", "trojan.addr_type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_dst_addr,
            { "Trojan Dst Addr", "trojan.dst_addr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_dst_port,
            { "Trojan Dst Port", "trojan.dst_port",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_tunnel_data,
            { "Trojan Tunnel Data", "trojan.tunnel_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_data_type,
            { "Trojan Data Type", "trojan.data_type",
            FT_UINT8, BASE_DEC,
            VALS(data_type), 0x0,
            NULL, HFILL }
        },
        { &hf_trojan_data_length,
            { "Trojan Data Length", "trojan.data_length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        // Trojan Fragment
         { &hf_msg_fragments,
             {"Reassembled Trojan Segments", "trojan.fragments",
             FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
         },
         { &hf_msg_fragment,
             {"Message fragment", "trojan.fragment",
             FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_overlap,
             {"Message fragment overlap", "trojan.fragment.overlap",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_overlap_conflicts,
             {"Message fragment overlapping with conflicting data",
             "trojan.fragment.overlap.conflicts",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_multiple_tails,
             {"Message has multiple tail fragments",
             "trojan.fragment.multiple_tails",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_too_long_fragment,
             {"Message fragment too long", "trojan.fragment.too_long_fragment",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_error,
             {"Message defragmentation error", "trojan.fragment.error",
             FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_count,
             {"Message fragment count", "trojan.fragment.count",
             FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_reassembled_in,
             {"Reassembled in", "trojan.reassembled_in",
             FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_reassembled_length,
             {"Reassembled length", "trojan.reassembled.length",
             FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_reassembled_data,
             {"Reassembled data",  "trojan.reassembled.data",
             FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL} },
         { &hf_msg_segment,
             {"Trojan segment", "trojan.segment_data",
             FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_trojan,
    };

    proto_trojan = proto_register_protocol(
        "Trojan Protocol", /* name        */
        "Trojan",          /* short_name  */
        "trojan"           /* filter_name */
    );

    proto_register_field_array(proto_trojan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&proto_trojan_streaming_reassembly_table,
        &addresses_ports_reassembly_table_functions);

    trojan_handle = register_dissector("trojan", dissect_trojan, proto_trojan);
}


/* utils functions */
bool
char_array_eq(const char* arr_1, const char* arr_2, size_t len) {

    if (arr_1 == NULL && arr_2 == NULL)
        return true;

    if (arr_1 == NULL || arr_2 == NULL)
        return false;

    return memcmp(arr_1, arr_2, len) == 0;
}

gint tvb_find_crlf_pos(tvbuff_t* tvb) {

    guint tvb_len;

    if (!tvb) return -1;

    tvb_len = tvb_captured_length(tvb);

    for (guint i = 0; i <= tvb_len - TROJAN_CRLF_LENGTH; i++) {
        if (tvb_get_guint8(tvb, i) == TROJAN_CRLF[0] && tvb_get_guint8(tvb, i+1) == TROJAN_CRLF[1]) {
            return i;
        }
    }

    return -1;
}

gint
tvb_find_TLS_signature(tvbuff_t* tvb) {
    gint min_pos = -1;

    for (gint i = 0; i < TLS_SIGNUM; i++) {
        gint pos = tvb_find_bytes(tvb, 0, -1, TLS_signature[i]);
        if (pos >= 0)
            if (min_pos >= 0)
                min_pos = min_pos <= pos ? min_pos : pos; /* 返回较小的 */
            else
                min_pos = pos;
    }

    return min_pos;
}

gint
tvb_find_bytes(tvbuff_t* tvb, const gint offset, const gint max_length, const char* needle) {

    guint limit_bufsize = tvb_reported_length_remaining(tvb, offset);
    guint bufsize;
    if (max_length < 0)
        bufsize = limit_bufsize + 1; /* 1 for the terminating nul */
    else
        if ((guint)max_length < limit_bufsize)
            bufsize = (guint)max_length + 1;
        else {
            g_print("Warning: max_length is larger than the tvb remaining size, clip to the tvb remaining size.\n");
            bufsize = limit_bufsize + 1;
        }
    char* buffer = (char*)malloc(bufsize);
    if (!buffer) {
        return -1;
    }
    tvb_get_raw_bytes_as_string(tvb, offset, buffer, bufsize);
    /* Strip the terminating nul for both buffer and needle */
    gint result = mem_search(buffer, bufsize - 1, needle, 3);
    free(buffer);
    return result;
}

gint
mem_search(const char* haystack, guint haystack_size, const char* needle, guint needle_size) {
    if (haystack == NULL || needle == NULL) {
        g_print("Warning: Either haystack or needle is NULL\n");
        return -1;
    }


    if (needle_size == 0) return 0; /* Empty needle matches the beginning of haystack */
    if (haystack_size < needle_size) return -1; /* Haystack is smaller than needle */

    guint limit = haystack_size - needle_size;

    for (guint i = 0; i <= limit; i++)
        if (memcmp(haystack + i, needle, needle_size) == 0)
            return (gint)i; /* Warning: Convert unsigned int to int */
    return -1;
}

bool
is_trojan_request(tvbuff_t* tvb) {
    /* trojan request packet */
    if (tvb_reported_length(tvb) > TROJAN_PASSWORD_LENGTH && tvb_reported_length(tvb) < TROJAN_REQUEST_MAX_LENGTH) { /* Minimum Trojan request length */
        gchar* tmp_crlf = (gchar*)g_malloc((TROJAN_CRLF_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, TROJAN_PASSWORD_LENGTH, tmp_crlf, (TROJAN_CRLF_LENGTH + 1));
        if (char_array_eq(TROJAN_CRLF, tmp_crlf, TROJAN_CRLF_LENGTH)) {
            g_free(tmp_crlf);
            return true;
        }
        g_free(tmp_crlf);
    }

    return false;
}

proto_tree* proto_tree_get_child_nth(proto_tree* parent, guint n)
{
    if (!parent) return NULL;
    if (n == 0) return parent;
    proto_tree* child = parent->first_child;

    for (guint i = 2; i <= n; i++) {
        if (!child) return NULL;
        child = child->next;
    }
    return child;
}

trojan_conv_t* get_trojan_conv(conversation_t* conversation, const int proto)
{
    trojan_conv_t* conv_data;

    conv_data = (trojan_conv_t*)conversation_get_proto_data(conversation, proto);
    if (conv_data != NULL)
        return conv_data;

    /* no previous Trojan conversation info, initialize it. */
    conv_data = wmem_new0(wmem_file_scope(), trojan_conv_t);
    conv_data->reassembly_info = streaming_reassembly_info_new();
    /* Defer the conversation type inference in dissect_trojan routine */
    conv_data->conv_type = TROJAN_UNINITIALIZED;
    conversation_add_proto_data(conversation, proto_trojan, conv_data);

    return conv_data;
}
