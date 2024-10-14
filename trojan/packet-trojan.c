#include "config.h"

#include <epan/packet.h>
#include <glib.h>
#include <epan/wmem_scopes.h>
#include "packet-trojan.h"

static int
dissect_trojan_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    tvbuff_t* next_tvb;
    int ret;
    
    //printf("--dissect_trojan_response\n");
    //printf("----pinfo->curr_layer_num: %d -----call tls_handle \n",pinfo->curr_layer_num);

    port_type save_port_type = pinfo->ptype;
    uint16_t saved_can_desegment = pinfo->saved_can_desegment;

    pinfo->ptype = PT_NONE;
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

    // printf("--dissect_trojan_request\n");
    // printf("----pinfo->curr_layer_num = %d\n", pinfo->curr_layer_num);

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
    
    // return offset + second_crlf_pos + TROJAN_CRLF_LENGTH;
    return tvb_captured_length(tvb);
}

static int
dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {


    //printf("dissect_trojan  pinfo->Frame number: %d, 4bytes: %s\n",
    //    pinfo->num, tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_STR_HEX));

    /* trojan request packet */
    if (tvb_reported_length(tvb) > TROJAN_PASSWORD_LENGTH && tvb_reported_length(tvb) < TROJAN_REQUEST_MAX_LENGTH) { /* Trojan request length */
        gchar* tmp_crlf = (gchar*)g_malloc((TROJAN_CRLF_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, TROJAN_PASSWORD_LENGTH, tmp_crlf, (TROJAN_CRLF_LENGTH + 1));
        if (char_array_eq(TROJAN_CRLF, tmp_crlf, TROJAN_CRLF_LENGTH)) {
            g_free(tmp_crlf);
            return dissect_trojan_request(tvb, pinfo, tree, data);
        }
        g_free(tmp_crlf);
    }

    /* trojan response tunnel data packet */
    if (tvb_find_TLS_signiture(tvb) == 0) {
        return dissect_trojan_response(tvb, pinfo, tree, data);
    }

    /* not trojan packet */

    printf("【Waring】: Cannot be parsed by trojan dissect\n");

    return tvb_captured_length(tvb);
}

static bool
dissect_trojan_heur_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {

    //printf("dissect_trojan_heur_tls  pinfo->Frame number: %d, 4bytes: %s\n",
    //    pinfo->num, tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_STR_HEX));

    /* trojan request packet */
    if (tvb_reported_length(tvb) > TROJAN_PASSWORD_LENGTH && tvb_reported_length(tvb) < TROJAN_REQUEST_MAX_LENGTH) { /* Minimum Trojan request length */
        gchar* tmp_crlf = (gchar*)g_malloc((TROJAN_CRLF_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, TROJAN_PASSWORD_LENGTH, tmp_crlf, (TROJAN_CRLF_LENGTH + 1));
        if (char_array_eq(TROJAN_CRLF, tmp_crlf, TROJAN_CRLF_LENGTH)) {
            dissect_trojan(tvb, pinfo, tree, data);
            g_free(tmp_crlf);
            return true;
        }
        g_free(tmp_crlf);
    }

    /* trojan response tunnel data packet */
    if (tvb_find_TLS_signiture(tvb) == 0) {
        dissect_trojan(tvb, pinfo, tree, data);
        return true;
    }

    /* not trojan packet */
    printf("【Info Frame number %d】：dissect_trojan_heur_tls return false\n", pinfo->num);
    return false;
}

void
proto_reg_handoff_trojan(void)
{

    // trojan_handle = create_dissector_handle(dissect_trojan, proto_trojan); /* 创建一个匿名解析器，不建议使用 */
    tls_handle = find_dissector("tls");
    h2_handle = find_dissector("http2");
    http_handle = find_dissector("http");
    dissector_add_uint("tls.port", TROJAN_TLS_PORT, trojan_handle);

    // 添加子解析器: tls解析后调用dissect_trojan_heur_tls函数，在决定是否调用trojan解析器
    heur_dissector_add("tls", dissect_trojan_heur_tls, "Trojan Over Tls", "trojan_over_tls", proto_trojan, 1);

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
        }

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

    trojan_handle = register_dissector("trojan", dissect_trojan, proto_trojan);
}


/* utils function */
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
