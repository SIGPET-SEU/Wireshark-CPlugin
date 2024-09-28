#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include <string.h>
#include <glib.h>
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

    printf("proto_register_trojan\n");
}

void
proto_reg_handoff_trojan(void)
{

    //trojan_handle = create_dissector_handle(dissect_trojan, proto_trojan); /* 创建一个匿名解析器，不建议使用*/
    tls_handle = find_dissector("tls");
    h2_handle = find_dissector("http2");
    dissector_add_uint("tls.port", TROJAN_TCP_PORT, trojan_handle);
    //ssl_dissector_add(TROJAN_TCP_PORT, trojan_handle);
    printf("proto_reg_handoff_trojan\n");
}


static int
dissect_trojan_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    tvbuff_t* next_tvb;

    //conversation_t* conversation;
    //trojan_conv_t* conv_data;

    printf("--dissect_trojan_response\n");
    printf("----pinfo->current_proto: %s\n",pinfo->current_proto);
    printf("----pinfo->curr_layer_num: %d\n",pinfo->curr_layer_num);
    printf("----pinfo->curr_proto_layer_num: %d\n",pinfo->curr_proto_layer_num);
    printf("----pinfo->ptype: %d\n",pinfo->ptype);
    printf("----pinfo->Frame number: %d\n",pinfo->num);

    port_type save_port_type = pinfo->ptype;
    uint16_t saved_can_desegment = pinfo->saved_can_desegment;


    pinfo->ptype = PT_NONE; // 代码生效后，tls->trojan->trojan 而不是 tls->trojan->http2, 所以后续手动调用了http2的dissector
    pinfo->can_desegment = 2;



    ///* get conversation, create if necessary*/
    //conversation = find_or_create_conversation(pinfo);

    ///* get associated state information, create if necessary */
    //conv_data = (trojan_conv_t*)conversation_get_proto_data(conversation, proto_trojan);
    //if (!conv_data) {
    //    conv_data = wmem_new0(wmem_file_scope(), trojan_conv_t);
    //    conversation_add_proto_data(conversation, proto_trojan, conv_data);
    //}
    //if (!conv_data->reassembly_info) {
    //    conv_data->reassembly_info = streaming_reassembly_info_new();
    //}


    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Response");
    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
    proto_tree_add_item(trojan_tree, hf_trojan_tunnel_data, tvb, 0, tvb_reported_length(tvb), ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_remaining(tvb, 0);

    //if (next_tvb) {
    //    reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
    //        trojan_tree, tree, proto_trojan_streaming_reassembly_table,
    //        conv_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
    //        proto_tree_get_parent_tree(tree), NULL, "Trojan", &msg_frag_items, hf_msg_body_segment);
    //}

    call_dissector_with_data(tls_handle, next_tvb, pinfo, tree, NULL);

    pinfo->ptype = save_port_type;
    pinfo->can_desegment = saved_can_desegment;

    return 0;
}

static int
dissect_trojan_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    // todo:
    // 1. 根据 cmd 判断 addr 的表达形式 ipv4/ipv6/domain，然后计算addr的长度; 或者找到下一把 CRLF标志位;
    // 2. 利用 offset 表示偏移
    printf("--dissect_trojan_request\n");

    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Request");
    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
    proto_tree_add_item(trojan_tree, hf_trojan_password, tvb, 0, 56, ENC_BIG_ENDIAN);
    proto_tree_add_item(trojan_tree, hf_trojan_cmd, tvb, 58, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(trojan_tree, hf_trojan_atype, tvb, 59, 1, ENC_BIG_ENDIAN);
    //proto_tree_add_item(trojan_tree, hf_trojan_dst_addr, tvb, 0, 56, ENC_BIG_ENDIAN);
    //proto_tree_add_item(trojan_tree, hf_trojan_dst_port, tvb, 0, 56, ENC_BIG_ENDIAN);

    return 0;
}

static int
dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {


    printf("dissect_trojan\n");

    bool is_request = false;
    bool is_response = false;

    if (pinfo->curr_layer_num > 7) {
        /* 避免陷入 tls->trojan->trojan的循环，所以手动调用 http2_handle*/
        printf("pinfo->curr_layer_num > 7\n");
        call_dissector_with_data(h2_handle, tvb_new_subset_remaining(tvb, 0), pinfo, tree, NULL);
        return tvb_captured_length(tvb);;
    }


    if (tvb_reported_length(tvb) > TROJAN_PASSWORD_LENGTH) { /* Minimum Trojan request length */
        gchar* tmp_crlf = (gchar*)g_malloc((TROJAN_CRLF_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, 56, tmp_crlf, (TROJAN_CRLF_LENGTH + 1));
        if (char_array_eq(CRLF, tmp_crlf, 2)) {
            is_request = true;
        }
    }

    if (is_request) {
        dissect_trojan_request(tvb, pinfo, tree, data);
        return tvb_captured_length(tvb);
    }

    //if (tvb_find_TLS_signiture(tvb) == 0) {
    //    is_response = true;
    //    dissect_trojan_response(tvb, pinfo, tree, data);
    //}
    dissect_trojan_response(tvb, pinfo, tree, data);

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
    tvb_get_raw_bytes_as_string(tvb, offset, buffer, bufsize);
    /* Strip the terminating nul for both buffer and needle */
    return mem_search(buffer, bufsize - 1, needle, 3);
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


