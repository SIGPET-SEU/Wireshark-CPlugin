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

static int
dissect_trojan_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    //tvbuff_t* next_tvb;
    port_type save_port_type;
    uint16_t save_can_desegment;
    int ret;
    conversation_t* conversation;
    trojan_conv_data* conv_data;

    // printf(trojan_keylog_file_name, "\n");


    
    /*printf("--dissect_trojan_response\n");
    printf("----pinfo->curr_layer_num: %d -----call tls_handle \n",pinfo->curr_layer_num);*/
    // printf("----pinfo->ptype: %d\n", pinfo->ptype); //全是 PT_TCP
    //printf("----pinfo->fd->visited: %d\n", pinfo->fd->visited); //第一轮全是0 后面全是1 所以应该不是影响的条件
    //printf("can_desegment: %d, saved_can_desegment: %d\n", pinfo->can_desegment, pinfo->saved_can_desegment);//全是1,2

    save_port_type = pinfo->ptype;
    save_can_desegment = pinfo->can_desegment;
    pinfo->ptype = PT_NONE;
    pinfo->can_desegment = pinfo->saved_can_desegment;

    conversation = find_or_create_conversation(pinfo);
    conv_data = (trojan_conv_data *)conversation_get_proto_data(conversation, proto_trojan);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), trojan_conv_data);
        conv_data->save_port_type = save_port_type;
        conv_data->reassembly_info = streaming_reassembly_info_new();
        conversation_add_proto_data(conversation, proto_trojan, conv_data);
    }


    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Response & call tls_handle");
    ti = proto_tree_add_item(tree, proto_trojan, tvb, 0, -1, ENC_NA);
    trojan_tree = proto_item_add_subtree(ti, ett_trojan);
    proto_tree_add_item(trojan_tree, hf_trojan_tunnel_data, tvb, 0, tvb_reported_length(tvb), ENC_BIG_ENDIAN);

    //next_tvb = tvb_new_subset_remaining(tvb, 0);

    dissector_add_string("tls.alpn", "h2", h2_handle);
    //dissector_add_string("tls.alpn", "http/1.1", http_tls_handle);
    //dissector_add_string("http.upgrade", "h2", h2_handle);
    //dissector_add_string("http.upgrade", "h2c", h2_handle);

    ret = call_dissector_only(tls_handle, tvb, pinfo, trojan_tree, data);
    //reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
    //    trojan_tree, proto_tree_get_parent_tree(trojan_tree), proto_trojan_streaming_reassembly_table,
    //    conv_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
    //    proto_tree_get_parent_tree(tree), NULL, "Trojan", &msg_fragment_items, hf_msg_segment);

    dissector_delete_string("tls.alpn", "h2", h2_handle);
    //dissector_delete_string("tls.alpn", "http/1.1", http_tls_handle);
    //dissector_delete_string("http.upgrade", "h2", h2_handle);
    //dissector_delete_string("http.upgrade", "h2c", h2_handle);

    pinfo->ptype = save_port_type;
    pinfo->can_desegment = save_can_desegment;

    return ret;
}

static int
dissect_trojan_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_item* ti;
    proto_tree* trojan_tree;
    int offset = 0, second_crlf_pos;
    // conversation_t* conversation;


     /*printf("--dissect_trojan_request\n");
     printf("----pinfo->curr_layer_num = %d\n", pinfo->curr_layer_num);*/


    col_set_str(pinfo->cinfo, COL_INFO, "Trojan Request");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trojan");

    // conversation = find_or_create_conversation(pinfo);

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

    // return offset + second_crlf_pos + TROJAN_CRLF_LENGTH; // 
    
    return tvb_captured_length(tvb);
}

static int
dissect_trojan(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {

    struct tlsinfo* tlsinfo = (struct tlsinfo*)data;
    //dissector_handle_t save_handle = *(tlsinfo->app_handle);

    /*printf("dissect_trojan  pinfo->Frame number: %d, 4bytes: %s\n",
        pinfo->num, tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_STRING));*/

    /* trojan request packet */
    if (is_trojan_request(tvb)) {
        //*(tlsinfo->app_handle) = trojan_handle;
        return dissect_trojan_request(tvb, pinfo, tree, data);
    }

    guint offset = 0;
    guint offset_before;
    unsigned length;
    tvbuff_t* next_tvb;

    while (tvb_reported_length_remaining(tvb, offset)) {
        const guchar* raw_buf = tvb_get_ptr(tvb, offset, 5);
        guint plen = ((guint)raw_buf[3] << 8) + (guint)(raw_buf[4]) + 5;
        unsigned captured_length_remaining;
        //pinfo->desegment_offset = offset;
        //pinfo->desegment_len = plen;

        captured_length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

        if (!pinfo->fd->visited) {
            unsigned remaining_bytes;
            remaining_bytes = tvb_reported_length_remaining(tvb, offset);
            if (plen > remaining_bytes) {
                pinfo->want_pdu_tracking = 2;
                pinfo->bytes_until_next_pdu = plen - remaining_bytes;
            }
        }

        /*
          * Can we do reassembly?
          */
        if (proto_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the PDU split across segment boundaries?
             */
            if (captured_length_remaining < plen) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us, and how many more bytes we
                 * need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = plen - captured_length_remaining;
                return 0;
            }
        }

        /*
         * Construct a tvbuff containing the amount of the payload we have
         * available.  Make its reported length the amount of data in the PDU.
         */
        length = captured_length_remaining;
        if (length > plen)
            length = plen;
        next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, plen);
        if (!(proto_desegment && pinfo->can_desegment)) {
            if (plen > length) {
                /* If we can't do reassembly but the PDU is split across
                 * segment boundaries, mark the tvbuff as a fragment so
                 * we throw FragmentBoundsError instead of malformed
                 * errors.
                 */
                tvb_set_fragment(next_tvb);
            }
        }

        dissect_trojan_response(next_tvb, pinfo, tree, data);

        /*
         * Step to the next PDU.
         * Make sure we don't overflow.
         */
        offset_before = offset;
        offset += plen;
        if (offset <= offset_before)
            return 0;
    }

    return 0;

    ///* trojan response(tunnel data) packet */
    //if (is_trojan_response(tvb)) {
    //    //*(tlsinfo->app_handle) = trojan_handle;
    //    return dissect_trojan_response(tvb, pinfo, tree, data);
    //}

    /* not trojan packet */
    //*(tlsinfo->app_handle) = save_handle;




    // 尝试其他常见协议
    // printf(dissector_handle_get_dissector_name(*(tlsinfo->app_handle)));
    if (dissector_try_heuristic(tls_heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, data)) {
        // 打印被成功调用的启发器的名字
        printf("Successful heuristic dissector: %s\n", heur_dtbl_entry->short_name);
        return tvb_captured_length(tvb);
    }



    printf("【Waring】: Cannot be parsed by trojan dissect, call data dissector\n");

    // return call_dissector_with_data(http_handle, tvb, pinfo, tree, data); // 
    return call_data_dissector(tvb, pinfo, tree);
}

static bool
dissect_trojan_heur_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {

    conversation_t* conversation;
    struct tlsinfo* tlsinfo = (struct tlsinfo*)data;
   /* printf("【Info Frame number %d】：dissect_trojan_heur_tls, 4bytes: %s \n", pinfo->num, tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_STRING));*/

    /* found trojan request or response(tunnel data) */
    if (is_trojan_request(tvb) || is_trojan_response(tvb)) {
        conversation = find_or_create_conversation(pinfo);
        //conversation_set_dissector(conversation, trojan_handle); // conversation_get_dissector()
        dissect_trojan(tvb, pinfo, tree, data);
        //*(tlsinfo->app_handle) = trojan_handle;
        return true;
    }


    /* not trojan packet */
    // printf("【Info Frame number %d】：dissect_trojan_heur_tls return false\n", pinfo->num);



    return false;
}

void
proto_reg_handoff_trojan(void)
{

    tls_handle = find_dissector("tls");
    h2_handle = find_dissector("http2");
    http_tls_handle = find_dissector("http-over-tls");
    //dissector_add_uint("tls.port", TROJAN_TLS_PORT, trojan_handle);
    //dissector_add_string("tls.alpn", "http/1.1", trojan_handle);
    //dissector_add_string("tls.alpn", "h2", trojan_handle);
    //dissector_add_string("http.upgrade", "h2", trojan_handle);
    //dissector_add_string("http.upgrade", "h2c", trojan_handle);
    dissector_add_uint_range_with_preference("tls.port", TROJAN_TLS_RANGE_PORT, trojan_handle);
    // dissector_add_for_decode_as("trojan", trojan_handle); // ui

    /* 将 trojan 注册到 tls 的启发式解析器中 */
    heur_dissector_add("tls", dissect_trojan_heur_tls, "Trojan Over Tls", "trojan_over_tls", proto_trojan, HEURISTIC_ENABLE);

    tls_heur_subdissector_list = find_heur_dissector_list("tls"); // tls 的启发式解析器列表


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
        // Trojan Fragment
         { &hf_msg_fragments,
             {"Reassembled VMess Segments", "vmess.fragments",
             FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
         },
         { &hf_msg_fragment,
             {"Message fragment", "vmess.fragment",
             FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_overlap,
             {"Message fragment overlap", "vmess.fragment.overlap",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_overlap_conflicts,
             {"Message fragment overlapping with conflicting data",
             "vmess.fragment.overlap.conflicts",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_multiple_tails,
             {"Message has multiple tail fragments",
             "vmess.fragment.multiple_tails",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_too_long_fragment,
             {"Message fragment too long", "vmess.fragment.too_long_fragment",
             FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_error,
             {"Message defragmentation error", "vmess.fragment.error",
             FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_fragment_count,
             {"Message fragment count", "vmess.fragment.count",
             FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_reassembled_in,
             {"Reassembled in", "vmess.reassembled_in",
             FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_reassembled_length,
             {"Reassembled length", "vmess.reassembled.length",
             FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
         { &hf_msg_reassembled_data,
             {"Reassembled data",  "vmess.reassembled.data",
             FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL} },
         { &hf_msg_segment,
             {"VMess segment", "vmess.segment_data",
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

bool
is_trojan_response(tvbuff_t* tvb) {
    return tvb_find_TLS_signature(tvb) == 0 ? true : false;
}
