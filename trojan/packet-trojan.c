#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-http.h>
// #include <epan/dissectors/packet-http2.c>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include <string.h>
#include <glib.h>
#include <epan/wmem_scopes.h>
#include "packet-trojan.h"


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
        }

    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_trojan,

        & ett_msg_fragment,
        & ett_msg_fragments
    };

    proto_trojan = proto_register_protocol(
        "Trojan Protocol", /* name        */
        "Trojan",          /* short_name  */
        "trojan"           /* filter_name */
    );

    proto_register_field_array(proto_trojan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    trojan_handle = register_dissector("trojan", dissect_trojan, proto_trojan);

}

void
proto_reg_handoff_trojan(void)
{

    //trojan_handle = create_dissector_handle(dissect_trojan, proto_trojan); /* 创建一个匿名解析器，不建议使用*/
    tls_handle = find_dissector("tls");
    http_tcp_handle = find_dissector("http-over-tcp");
    http_tls_handle = find_dissector("http-over-tls");
    http_handle = find_dissector("http");
    h2_handle = find_dissector("http2");
    dissector_add_uint("tls.port", TROJAN_TCP_PORT, trojan_handle);
    //ssl_dissector_add(TROJAN_TCP_PORT, trojan_handle);

    // 添加子解析器? tls后 分析 dissect_trojan_heur_tls 在决定是否调用trojan
    // heur_dissector_add("tls", dissect_trojan_heur_tls, "Trojan Over Tls", "trojan_over_tls", proto_trojan, 1);
    // heur_dissector_add("tcp", dissect_trojan_heur_tls, "Trojan Over Tcp", "trojan_over_tcp", proto_trojan, 1);

}

static bool
dissect_trojan_heur_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {

    if (tvb_find_TLS_signiture(tvb) == 0) {
        printf("find tls signiture & call tls_dissector\n");
        call_dissector_with_data(tls_handle, tvb, pinfo, tree, data);
        return true;
    }

    printf("dissect_trojan_heur_tls\n");
    dissect_trojan(tvb, pinfo, tree, data);
    return true;
}

static int
dissect_trojan_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    tvbuff_t* next_tvb;
    int ret;
    


    printf("--dissect_trojan_response\n");
    printf("----pinfo->curr_layer_num: %d -----call tls_handle \n",pinfo->curr_layer_num);

    port_type save_port_type = pinfo->ptype;
    uint16_t saved_can_desegment = pinfo->saved_can_desegment;

    pinfo->ptype = PT_NONE; // 代码生效后，tls->trojan->tls->trojan 而不是 tls->trojan->tls->http2, 所以后续手动调用了http2的dissector
    pinfo->can_desegment = 2;

    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Response & call tls_handle");
    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
    proto_tree_add_item(trojan_tree, hf_trojan_tunnel_data, tvb, 0, tvb_reported_length(tvb), ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_remaining(tvb, 0);

    dissector_add_string("tls.alpn", "h2", h2_handle);
    dissector_add_string("http.upgrade", "h2", h2_handle);
    dissector_add_string("http.upgrade", "h2c", h2_handle);

    ret = call_dissector_with_data(tls_handle, next_tvb, pinfo, tree, data);

    dissector_delete_string("tls.alpn", "h2", h2_handle);
    dissector_delete_string("http.upgrade", "h2", h2_handle);
    dissector_delete_string("http.upgrade", "h2c", h2_handle);

    pinfo->ptype = save_port_type;
    pinfo->can_desegment = saved_can_desegment;

    
    return ret;
}

static int
dissect_trojan_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    int offset = 0, second_crlf_pos;

    printf("--dissect_trojan_request\n");
    printf("----pinfo->curr_layer_num = %d\n", pinfo->curr_layer_num);


    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Request");
    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
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
    }

    // todo: 后面还有数据吗?
    
    return offset + second_crlf_pos + TROJAN_CRLF_LENGTH;
}

static bool
dissect_trojan_over_http1(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {

    int offset = 0, next_offset, linelen;
    conversation_t* conversation;
    proto_item* ti;
    proto_tree* trojan_tree;
    tvbuff_t* next_tvb;
    http_conv_t* conv_data;

    conversation = find_or_create_conversation(pinfo);
    conv_data = (http_conv_t*)conversation_get_proto_data(conversation, proto_get_id_by_filter_name("http"));
    /* A http conversation was previously started, assume it is still active */
    //if (conv_data) {
    //    printf("----pinfo->curr_layer_num = %d -----call http_tls_handle \n", pinfo->curr_layer_num);

    //    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Response & call http_tls_handle");
    //    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    //    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
    //    proto_tree_add_item(trojan_tree, hf_trojan_tunnel_data, tvb, 0, tvb_reported_length(tvb), ENC_BIG_ENDIAN);


    //    call_dissector_with_data(http_tls_handle, tvb, pinfo, tree, data);
    //    return true;
    //}

    /* Check if we have a line terminated by CRLF
     * Return the length of the line (not counting the line terminator at
     * the end), or, if we don't find a line terminator:
     *
     *	if "deseg" is true, return -1;
     */
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, true);
    if ((linelen == -1) || (linelen == 8)) {
        return false;
    }

    /* Check if the line start or ends with the HTTP token */
    if ((tvb_strncaseeql(tvb, linelen - 8, "HTTP/1.", 7) == 0) || (tvb_strncaseeql(tvb, 0, "HTTP/1.", 7) == 0)) {
        //conversation = find_or_create_conversation(pinfo);
        //conversation_set_dissector_from_frame_number(conversation, pinfo->num, http_tcp_handle);
        //dissect_http_tcp(tvb, pinfo, tree, data);

        col_set_str(pinfo->cinfo, COL_INFO, "Trojan Response & call http_tcp_handle");
        ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
        trojan_tree = proto_item_add_subtree(ti, ett_trojan);
        proto_tree_add_item(trojan_tree, hf_trojan_tunnel_data, tvb, 0, tvb_reported_length(tvb), ENC_BIG_ENDIAN);


        printf("----pinfo->curr_layer_num = %d -----call http_tcp_handle \n", pinfo->curr_layer_num);
        // call_dissector_with_data(http_tcp_handle, tvb, pinfo, tree, data);
        call_dissector_with_data(http_handle, tvb, pinfo, tree, data);
        return true;
    }

    return false;
}

static int
dissect_trojan_over_http2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    int ret;

    printf("----pinfo->curr_layer_num = %d > 7 -----call http2_dissector \n", pinfo->curr_layer_num);

    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Response & call http_tcp_handle");
    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
    proto_tree_add_item(trojan_tree, hf_trojan_tunnel_data, tvb, 0, tvb_reported_length(tvb), ENC_BIG_ENDIAN);

    ret = call_dissector_with_data(h2_handle, tvb_new_subset_remaining(tvb, 0), pinfo, tree, NULL);

    return ret;
}

static int
dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {


    printf("dissect_trojan  pinfo->Frame number: %d, 4bytes: %s\n",
        pinfo->num, tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_STR_HEX));


    bool is_request = false;
    bool is_response = false;


    //if (pinfo->curr_layer_num > 7) {
    //    /* 避免陷入 tls->trojan->trojan的循环，所以手动调用 http2_handle */
    //    return dissect_trojan_over_http2(tvb, pinfo, tree, data);
    //}
    //if (dissect_trojan_over_http2(tvb, pinfo, tree, data)) {
    //    return tvb_captured_length(tvb);
    //}


    if (tvb_reported_length(tvb) > TROJAN_PASSWORD_LENGTH) { /* Minimum Trojan request length */
        gchar* tmp_crlf = (gchar*)g_malloc((TROJAN_CRLF_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, 56, tmp_crlf, (TROJAN_CRLF_LENGTH + 1));
        if (char_array_eq(TROJAN_CRLF, tmp_crlf, 2)) {
            is_request = true;
        }
        g_free(tmp_crlf);
    }

    if (is_request) {
        return dissect_trojan_request(tvb, pinfo, tree, data);
    }

    // tls->trojan->http 如果只是一层tls加密，则这里直接call_http1_dissector
    if (dissect_trojan_over_http1(tvb, pinfo, tree, data)) {
        return tvb_captured_length(tvb);
    }


    //if (tvb_find_TLS_signiture(tvb) == 0) {
    //    is_response = true;
    //    dissect_trojan_response(tvb, pinfo, tree, data);
    //}

    dissect_trojan_response(tvb, pinfo, tree, data); // tls->trojan->tls->http2

    return tvb_captured_length(tvb);
}


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
tvb_find_TLS_signiture(tvbuff_t* tvb) {
    gint min_pos = -1;

    for (gint i = 0; i < TLS_SIGNUM; i++) {
        gint pos = tvb_find_bytes(tvb, 0, -1, TLS_signiture[i]);
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
