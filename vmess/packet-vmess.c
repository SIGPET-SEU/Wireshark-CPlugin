/* packet-vmess.c
 *
 * Updated routines for Gryphon protocol packet dissection
 * By Mark C. <markc@dgtech.com>
 * Copyright (C) 2018 DG Technologies, Inc. (Dearborn Group, Inc.) USA
 *
 * Routines for Gryphon protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: http://www.dgtech.com/product/vmess/manual/html/GCprotocol/
 *
 */

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
#include "packet-vmess.h"

/*
 * See
 *
 *     https://www.dgtech.com/product/vmess/manual/html/GCprotocol/
 */

void
proto_register_vmess(void)
{
    static hf_register_info hf[] = {
        { &hf_vmess_request_auth, 
            {"VMess Request Auth", "vmess.request.auth",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_response_header,
            {"VMess Response Header", "vmess.response.header",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vmess_payload_length,
            {"VMess Payload Length", "vmess.payload.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_msg_fragments,
            {"Reassembled VMess Message fragments", "vmess.msg.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_fragment,
            {"Message fragment", "vmess.msg.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_overlap,
            {"Message fragment overlap", "vmess.msg.fragment.overlap",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_overlap_conflicts,
            {"Message fragment overlapping with conflicting data",
            "vmess.msg.fragment.overlap.conflicts",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_multiple_tails,
            {"Message has multiple tail fragments",
            "vmess.msg.fragment.multiple_tails",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_too_long_fragment,
            {"Message fragment too long", "vmess.msg.fragment.too_long_fragment",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_error,
            {"Message defragmentation error", "vmess.msg.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_count,
            {"Message fragment count", "vmess.msg.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_in,
            {"Reassembled in", "vmess.msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_length,
            {"Reassembled length", "vmess.msg.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_body_segment,
            {"VMess body segment", "vmess.msg.body.segment",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_vmess,
        &ett_msg_fragment,
        &ett_msg_fragments
    };

    proto_vmess = proto_register_protocol (
        "VMESS Protocol", /* name        */
        "VMESS",          /* short name  */
        "vmess"           /* filter_name */
        );

    proto_register_field_array(proto_vmess, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&proto_vmess_streaming_reassembly_table,
        &addresses_ports_reassembly_table_functions);
}

void
proto_reg_handoff_vmess(void)
{
    static dissector_handle_t vmess_handle;

    vmess_handle = create_dissector_handle(dissect_vmess, proto_vmess);
    dissector_add_uint("tcp.port", VMESS_TCP_PORT, vmess_handle);
}

static void
dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Request");
    proto_item* ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    proto_tree* vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_request_auth, tvb, 0, 16, ENC_BIG_ENDIAN);
}

static guint
get_dissect_vmess_response_len(packet_info* pinfo _U_, tvbuff_t* tvb,
    int offset, void* data _U_) {
    return tvb_get_ntohs(tvb, offset + 38) + 40;
}

static int
dissect_vmess_response_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_tree* vmess_tree;
    proto_item* ti;
    tvbuff_t* next_tvb;

    conversation_t* conversation;
    vmess_conv_t* conv_data;
    int offset = 0;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conversation_add_proto_data(conversation, proto_vmess, conv_data);
    }
    if (!conv_data->reassembly_info) {
        conv_data->reassembly_info = streaming_reassembly_info_new();
    }

    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Response");
    ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_response_header, tvb, 0, 38, ENC_BIG_ENDIAN);
    proto_tree_add_item(vmess_tree, hf_vmess_payload_length, tvb, 38, 2, ENC_BIG_ENDIAN);
    

    next_tvb = tvb_new_subset_remaining(tvb, 40);

    tls_handle = find_dissector("tls");

    if (next_tvb) {
        //add_new_data_source(pinfo, next_tvb, "vmess segment data");
        reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
            vmess_tree, tree, proto_vmess_streaming_reassembly_table,
            conv_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
            proto_tree_get_parent_tree(tree), NULL, "VMess", &msg_frag_items, hf_msg_body_segment);
    }
    //tls_handle = find_dissector("tls");
    //call_dissector(tls_handle, next_tvb, pinfo, tree);

    return 0;
}

static guint
get_dissect_vmess_data_len(packet_info* pinfo _U_, tvbuff_t* tvb,
    int offset, void* data _U_) {
    return tvb_get_ntohs(tvb, offset) + 2;
}

static int
dissect_vmess_data_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    proto_tree* vmess_tree;
    proto_item* ti;
    tvbuff_t* next_tvb;

    conversation_t* conversation;
    vmess_conv_t* conv_data;
    int offset = 0;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conversation_add_proto_data(conversation, proto_vmess, conv_data);
    }
    if (!conv_data->reassembly_info) {
        conv_data->reassembly_info = streaming_reassembly_info_new();
    }

    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Data");
    ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_payload_length, tvb, 0, 2, ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_remaining(tvb, 2);

    tls_handle = find_dissector("tls");

    if (next_tvb) {
        //add_new_data_source(pinfo, next_tvb, "vmess segment data");
        reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
            vmess_tree, tree, proto_vmess_streaming_reassembly_table,
            conv_data->reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
            proto_tree_get_parent_tree(tree), NULL, "VMess", &msg_frag_items, hf_msg_body_segment);
    }

    //tls_handle = find_dissector("tls");
    //if (pinfo->can_desegment > 0)
    //    pinfo->can_desegment++;
    //call_dissector(tls_handle, next_tvb, pinfo, tree);
    //if (pinfo->desegment_len) {
    //    pinfo->desegment_offset += 2;
    //}
    // 
    //streaming_reassembly_info_t* streaming_reassembly_info = NULL;
    //if (!PINFO_FD_VISITED(pinfo)) {
    //    streaming_reassembly_info = streaming_reassembly_info_new();
    //}

    //reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0, tvb_reported_length_remaining(next_tvb, 0),
    //                                                vmess_tree, proto_tree_get_parent_tree(tree), proto_vmess_streaming_reassembly_table,
    //                                                streaming_reassembly_info, get_virtual_frame_num64(next_tvb, pinfo, 0), tls_handle,
    //                                                proto_tree_get_parent_tree(tree), NULL, "VMess", &msg_frag_items, hf_msg_body_segment);

    return 0;
}

static int
dissect_vmess(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t* conversation;
    vmess_conv_t* conv_data = NULL;

    const char* auth = "\xb0\xb2\x5c\xda\x68\x1c\x15\x53\x74\xb3\x5b\x5f\xcc\x3f\x81\xe7";

    bool is_request = false;

    if (tvb_reported_length(tvb) > 61) {
        char tmp_auth[17];
        tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, 17);
        /*tvb_get_string_bytes(tvb, 0, 16, ENC_ASCII | ENC_STR_HEX | ENC_SEP_NONE, tmp_auth, NULL);*/
        if(char_array_eq(auth, tmp_auth, 16))
            is_request = true;
    }

    if (is_request) {
        dissect_vmess_request(tvb, pinfo, tree, NULL);
        return tvb_captured_length(tvb);
    }

    bool is_response = false;
    gint pos = tvb_find_TLS_signiture(tvb);
    if (pos == 40) is_response = true;

    conversation = find_conversation_pinfo(pinfo, 0);
    if (conversation) {
        conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    }

    if (conv_data && is_response && pinfo->num > conv_data->startframe) {
        tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment,
            VMESS_RESPONSE_HEADER_LENGTH,
            get_dissect_vmess_response_len,
            dissect_vmess_response_pdu, data);
    }
    else {
        tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment,
            VMESS_DATA_HEADER_LENGTH, get_dissect_vmess_data_len,
            dissect_vmess_data_pdu, data);
    }

    return tvb_reported_length(tvb);

    //col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMESS");
    ///* Clear the info column */
    //col_clear(pinfo->cinfo, COL_INFO);

    //const char* auth = "\xb0\xb2\x5c\xda\x68\x1c\x15\x53\x74\xb3\x5b\x5f\xcc\x3f\x81\xe7";

    //bool is_request = false;

    //conversation_t* conversation;
    //vmess_conv_t* conv_data;

    //conv_data = get_vmess_conversation_data(pinfo, &conversation);

    //return dissect_vmess_on_stream(tvb, pinfo, tree, conv_data, FALSE, NULL);


    //if (tvb_reported_length(tvb) > 61) {
    //    char tmp_auth[17];
    //    tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, 17);
    //    /*tvb_get_string_bytes(tvb, 0, 16, ENC_ASCII | ENC_STR_HEX | ENC_SEP_NONE, tmp_auth, NULL);*/
    //    if(char_array_eq(auth, tmp_auth, 16))
    //        is_request = true;
    //}

    //if (is_request) {
    //    dissect_vmess_request(tvb, pinfo, tree, NULL);
    //    return tvb_captured_length(tvb);
    //}

    //bool is_response = false;
    //gint pos = tvb_find_TLS_signiture(tvb);
    //if (pos == 40) is_response = true;

    //if (is_response) {
    //    tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment, VMESS_RESPONSE_HEADER_LENGTH,
    //        get_dissect_vmess_response_len, dissect_vmess_response_pdu, data);
    //    return tvb_reported_length(tvb);
    //}
    //else {
    //    tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment, VMESS_DATA_HEADER_LENGTH,
    //        get_dissect_vmess_data_len, dissect_vmess_data_pdu, data);
    //    return tvb_reported_length(tvb);
    //}


    ///* The number returned tells how many bytes are consumed by current dissector */
    //return tvb_captured_length(tvb); 
}

bool
gbytearray_eq(const GByteArray* arr_1, const GByteArray* arr_2) {
    if (arr_1 == NULL && arr_2 == NULL)
        return true;

    if (arr_1 == NULL || arr_2 == NULL)
        return false;

    if (arr_1->len != arr_2->len)
        return false;

    return memcmp(arr_1->data, arr_2->data, arr_1->len)== 0;
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
            return (gint) i; /* Warning: Convert unsigned int to int */
    return -1;
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
    char* buffer = (char*) malloc(bufsize);
    tvb_get_raw_bytes_as_string(tvb, offset, buffer, bufsize);
    /* Strip the terminating nul for both buffer and needle */
    return mem_search(buffer, bufsize-1, needle, 3);
}

gint
tvb_find_TLS_signiture(tvbuff_t* tvb) {
    gint min_pos = -1;

    for (gint i = 0; i < TLS_SIGNUM; i++) {
        gint pos = tvb_find_bytes(tvb, 0, -1, TLS_signiture[i]);
        if (pos >= 0)
            if (min_pos >= 0)
                min_pos = min_pos <= pos ? min_pos : pos;
            else
                min_pos = pos;
    }

    return min_pos;
}

static vmess_conv_t*
get_vmess_conversation_data(packet_info* pinfo, conversation_t** conversation)
{
    vmess_conv_t* conv_data;

    *conversation = find_or_create_conversation(pinfo);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data = (vmess_conv_t*)conversation_get_proto_data(*conversation, proto_vmess);
    if (!conv_data) {
        /* Setup the conversation structure itself */
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conv_data->chunk_offsets_fwd = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conv_data->chunk_offsets_rev = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conv_data->req_list = NULL;
        conv_data->matches_table = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(*conversation, proto_vmess,
            conv_data);
    }

    return conv_data;
}

static int dissect_vmess_on_stream(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
    vmess_conv_t* conv_data, gboolean end_of_stream, const guint32* seq) {
    int	offset = 0;
    int	len = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /* Switch protocol if the data starts after response headers. */
        if (conv_data->startframe &&
            (pinfo->num > conv_data->startframe ||
                (pinfo->num == conv_data->startframe && offset >= conv_data->startoffset))) {
            /* Increase pinfo->can_desegment because we are traversing
             * http and want to preserve desegmentation functionality for
             * the proxied protocol
             */
            if (pinfo->can_desegment > 0)
                pinfo->can_desegment++;
            if (conv_data->next_handle) {
                call_dissector_only(conv_data->next_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
            }
            else {
                call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
            }
            /*
             * If a subdissector requests reassembly, be sure not to
             * include the preceding VMess headers.
             */
            if (pinfo->desegment_len) {
                pinfo->desegment_offset += offset;
            }
            break;
        }
        len = dissect_vmess_message(tvb, offset, pinfo, tree, conv_data, "VMess", proto_vmess, end_of_stream, seq);
        if (len < 0)
            break;
        offset += len;

        /*
         * OK, we've set the Protocol and Info columns for the
         * first VMess message; set a fence so that subsequent
         * VMess messages don't overwrite the Info column.
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
    }
    /* dissect_vmess_message() returns -2 if message is not valid VMess */
    return (len == -2)
        ? 0
        : (int)tvb_captured_length(tvb);
}

static int dissect_http_message(tvbuff_t* tvb, int offset, packet_info* pinfo, proto_tree* tree, vmess_conv_t* conv_data,
    const char* proto_tag, int proto, gboolean end_of_stream, const guint32* const seq) {

    proto_tree* vmess_tree = NULL;
    proto_item* ti = NULL;
    proto_item* hidden_item;
    const guchar* line, * firstline;
    gint		next_offset;
    const guchar* linep, * lineend;
    int		orig_offset = offset;
    int		first_linelen, linelen;
    gboolean	is_request_or_reply, is_tls = FALSE;
    gboolean	saw_req_resp_or_header;
    //media_container_type_t     http_type;
    proto_item* hdr_item = NULL;
    //ReqRespDissector reqresp_dissector;
    proto_tree* req_tree;
    int		colon_offset;
    //headers_t* headers = NULL;
    int		datalen;
    int		reported_datalen = -1;
    dissector_handle_t handle = NULL;
    bool	dissected = false;
    gboolean	first_loop = TRUE;
    gboolean	have_seen_vmess = FALSE;
    /*guint		i;*/
    /*http_info_value_t *si;*/
    //http_eo_t* eo_info;
    heur_dtbl_entry_t* hdtbl_entry;
    int reported_length;
    guint16 word;
    gboolean	leading_crlf = FALSE;
    gboolean	excess_data = FALSE;
    //media_content_info_t* content_info = NULL;
    wmem_map_t* header_value_map = NULL;
    int 		chunk_offset = 0;
    wmem_map_t* chunk_map = NULL;

    gboolean streaming_chunk_mode = FALSE;
    gboolean begin_with_chunk = FALSE;
    vmess_streaming_reassembly_data_t* streaming_reassembly_data = NULL;

    vmess_req_res_t* curr = (vmess_req_res_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_vmess, VMESS_PROTO_DATA_REQRES);
    vmess_req_res_private_data_t* prv_data = curr ? (vmess_req_res_private_data_t*)curr->private_data : NULL;
    vmess_req_res_private_data_t* tail_prv_data = NULL;

    /* Determine the direction as in the TCP dissector, but don't call
     * get_tcp_conversation_data because we don't want to create a new
     * TCP stream if it doesn't exist.
     */
    int direction = cmp_address(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if (direction == 0) {
        direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    if (direction >= 0) {
        chunk_map = conv_data->chunk_offsets_fwd;
    }
    else {
        chunk_map = conv_data->chunk_offsets_rev;
    }

    if (seq && chunk_map) {
        chunk_offset = GPOINTER_TO_INT(wmem_map_lookup(chunk_map, GUINT_TO_POINTER(*seq)));
        /* Returns 0 when there is no entry in the map, as we want. */
    }

    reported_length = tvb_reported_length_remaining(tvb, offset);
    if (reported_length < 1) {
        return -1;
    }

    /*
     * If we previously dissected an VMess request in this conversation then
     * we should be pretty sure that whatever we got in this TVB is
     * actually VMess (even if what we have here is part of a file being
     * transferred over VMess).
     */
    if (conv_data->req_res_tail)
        have_seen_vmess = TRUE;

}
