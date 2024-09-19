/* packet-vmess.c
 *
 * Updated routines for VMess protocol packet dissection
 * By Linxiao Yu <yulinxiaoybbb@gmail.com>
 *
 * Routines for VMess protocol packet disassembly
 * By Linxiao Yu <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: https://xtls.github.io/development/protocols/vmess.html
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

    return 0;
}

static int
dissect_vmess(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t* conversation;
    vmess_conv_t* conv_data = NULL;
    port_type save_port_type;
    guint16 save_can_desegment;

    /* get conversation, create if necessary*/
    conversation = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    conv_data = (vmess_conv_t*)conversation_get_proto_data(conversation, proto_vmess);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), vmess_conv_t);
        conv_data->auth = NULL;
        conversation_add_proto_data(conversation, proto_vmess, conv_data);
    }
    if (!conv_data->reassembly_info) {
        conv_data->reassembly_info = streaming_reassembly_info_new();
    }

    //const char* auth = "\xb0\xb2\x5c\xda\x68\x1c\x15\x53\x74\xb3\x5b\x5f\xcc\x3f\x81\xe7";
    //const char* auth = "\x43\xe7\xf4\x86\xc9\x36\xde\x80\xec\x3d\x0e\xbf\x82\x06\x5e\x8c";
    const char* auth = "\xfc\xc1\x8b\x89\x42\xc6\x70\xfd\xcb\x17\xe3\xb0\x7f\x72\xf2\x7f";

    bool is_request = false;

    if (!conv_data->auth) { /* If the auth of the conversation is not NULL, there is no need for auth check */
        if (tvb_reported_length(tvb) > 61) { /* Minimum VMess request length */
            gchar* tmp_auth = (gchar*)g_malloc((VMESS_AUTH_LENGTH + 1) * sizeof(gchar));
            tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, (VMESS_AUTH_LENGTH + 1));
            if (char_array_eq(auth, tmp_auth, VMESS_AUTH_LENGTH)) {
                conv_data->auth = wmem_strndup(pinfo->pool, tmp_auth, VMESS_AUTH_LENGTH);
                is_request = true;
            }
        }
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

        save_port_type = pinfo->ptype;
        pinfo->ptype = PT_NONE;
        save_can_desegment = pinfo->can_desegment;
        pinfo->can_desegment = pinfo->saved_can_desegment;

        tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment,
            VMESS_RESPONSE_HEADER_LENGTH,
            get_dissect_vmess_response_len,
            dissect_vmess_response_pdu, data);

        pinfo->ptype = save_port_type;
        pinfo->can_desegment = save_can_desegment;
    }
    else {
        save_port_type = pinfo->ptype;
        pinfo->ptype = PT_NONE;
        save_can_desegment = pinfo->can_desegment;
        pinfo->can_desegment = pinfo->saved_can_desegment;

        tcp_dissect_pdus(tvb, pinfo, tree, vmess_desegment,
            VMESS_DATA_HEADER_LENGTH, get_dissect_vmess_data_len,
            dissect_vmess_data_pdu, data);

        pinfo->ptype = save_port_type;
        pinfo->can_desegment = save_can_desegment;
    }

    return tvb_reported_length(tvb);
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
