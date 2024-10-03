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
#include <wsutil/file_util.h>
#include <wsutil/wslog.h>
#include <string.h>
#include <glib.h>
#include "packet-vmess.h"

static int
dissect_vmess_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    col_set_str(pinfo->cinfo, COL_INFO, "VMESS Request");
    proto_item* ti = proto_tree_add_item(tree, proto_vmess, tvb, 0, -1, ENC_NA);
    proto_tree* vmess_tree = proto_item_add_subtree(ti, ett_vmess);
    proto_tree_add_item(vmess_tree, hf_vmess_request_auth, tvb, 0, 16, ENC_BIG_ENDIAN);

    return 0;
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

    if (next_tvb) {
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

    if (next_tvb) {
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

    vmess_keylog_read();

    //const char* auth = "\xb0\xb2\x5c\xda\x68\x1c\x15\x53\x74\xb3\x5b\x5f\xcc\x3f\x81\xe7";
    //const char* auth = "\x43\xe7\xf4\x86\xc9\x36\xde\x80\xec\x3d\x0e\xbf\x82\x06\x5e\x8c";
    //const char* auth = "\xfc\xc1\x8b\x89\x42\xc6\x70\xfd\xcb\x17\xe3\xb0\x7f\x72\xf2\x7f";

    bool is_request = false;

    
    //if (tvb_reported_length(tvb) > 61) { /* Minimum VMess request length */
    //    gchar* tmp_auth = (gchar*)g_malloc((VMESS_AUTH_LENGTH + 1) * sizeof(gchar));
    //    tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, (VMESS_AUTH_LENGTH + 1));
    //    if (char_array_eq(auth, tmp_auth, VMESS_AUTH_LENGTH)) {
    //        if (!PINFO_FD_VISITED(pinfo) && !conv_data->auth) { 
    //            conv_data->auth = wmem_strndup(wmem_file_scope(), tmp_auth, VMESS_AUTH_LENGTH);
    //            g_free(tmp_auth);
    //        }
    //        is_request = true;
    //    }
    //}

    if (tvb_reported_length(tvb) > 61) { /* Minimum VMess request length */
        gchar* tmp_auth = (gchar*)g_malloc((VMESS_AUTH_LENGTH + 1) * sizeof(gchar));
        tvb_get_raw_bytes_as_string(tvb, 0, tmp_auth, (VMESS_AUTH_LENGTH + 1));
        gchar* key = g_hash_table_lookup(vmess_key_map, tmp_auth);
        if (key) {
            if (!PINFO_FD_VISITED(pinfo) && !conv_data->auth) { 
                conv_data->auth = wmem_strndup(wmem_file_scope(), tmp_auth, VMESS_AUTH_LENGTH);
                g_free(tmp_auth);
            }
            is_request = true;
        }
    }

    if (is_request) {
        dissect_vmess_request(tvb, pinfo, tree, NULL);

        vmess_debug_flush();

        return tvb_captured_length(tvb);
    }

    bool is_response = false;
    gint pos = tvb_find_TLS_signiture(tvb);
    if (pos == 40) is_response = true;

    save_port_type = pinfo->ptype;
    pinfo->ptype = PT_NONE;
    save_can_desegment = pinfo->can_desegment;
    pinfo->can_desegment = pinfo->saved_can_desegment;

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

    pinfo->ptype = save_port_type;
    pinfo->can_desegment = save_can_desegment;

    vmess_debug_flush();

    return tvb_reported_length(tvb);
}



static void
vmess_keylog_read(void) {
    if (!vmess_decryption_supported) {
        return;
    }

    if (!pref_keylog_file || !*pref_keylog_file) {
        vmess_debug_printf("No Keylog file is selected.\n");
        return;
    }

    // Reopen file if it got deleted/overwritten.
    if (vmess_keylog_file && file_needs_reopen(ws_fileno(vmess_keylog_file), pref_keylog_file)) {
        ws_debug("Key log file got changed or deleted, trying to re-open.");
        vmess_keylog_reset();
        g_hash_table_remove_all(vmess_key_map);
    }

    if (!vmess_keylog_file) {
        vmess_keylog_file = ws_fopen(pref_keylog_file, "r");
        if (!vmess_keylog_file) {
            ws_debug("Failed to open key log file %s: %s", pref_keylog_file, g_strerror(errno));
            return;
        }
        ws_debug("Opened key log file %s", pref_keylog_file);
    }

    /*
     *
     * File format: each line of the keylog file follows the format
     * 
     * <TYPE> <VALUE>
     *
     * currently, only AUTH type is supported. The value is a 16-byte string.
     *
     */

    for (;;) {
        char buf[512];
        if (!fgets(buf, sizeof(buf), vmess_keylog_file)) {
            if (feof(vmess_keylog_file)) {
                clearerr(vmess_keylog_file);
                /* For debugging, print the key map table. */
#define VMESS_DEBUG_PRINT_KEY_MAP
#ifdef VMESS_DEBUG_PRINT_KEY_MAP
                vmess_debug_print_hash_table(vmess_key_map);
#endif // VMESS_DEBUG_PRINT_KEY_MAP
            }
            else if (ferror(vmess_keylog_file)) {
                ws_debug("Error while reading %s, closing it.", pref_keylog_file);
                vmess_keylog_reset();
                g_hash_table_remove_all(vmess_key_map);
            }
            break;
        }

        /* Strip '\n' and '\r' chars from lines. */
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) { len -= 1; buf[len] = 0; }

        vmess_keylog_process_line((const guint8*)buf);
    }

}

static void
vmess_keylog_process_line(const char* line)
{
    ws_noisy("vmess process line: %s", line);

    /* Check if this line is the header of keylog file, i.e.,
     * the line starts with #
     */

    if (strlen(line) > 0 && line[0] == '#')
        return;

    gchar** split = g_strsplit(line, " ", 2);
    gchar * auth, * hex_auth_val;
    /*
     * Use wmem_xxx first, then consider g_xxx, finally seek for xxx in standard C lib.
     * See https://gitlab.com/wireshark/wireshark/-/blob/master/doc/README.wmem
     * 
     * NOTE: Memory allocated by wmem_alloc should be freed with wmem_free,
     * memory allocated by g_malloc should be freed using g_free.
     * Otherwise, it may cause Access Violation Reading exception.
     */
    gchar* key = wmem_strdup(wmem_file_scope(), "Dummy");
    
    size_t auth_len;

    if (g_strv_length(split) == 2) {
        // Auth file format: [key type] [hex-encoded key material]
        auth = split[0];
        hex_auth_val = split[1];
    }
    else {
        vmess_debug_printf("vmess keylog: invalid format");
        g_strfreev(split);
        return;
    }

    gchar* auth_val = NULL;

    from_hex(&auth_val, hex_auth_val, strlen(hex_auth_val));

    g_hash_table_insert(vmess_key_map, auth_val, key);

    g_strfreev(split);
}


static gboolean
vmess_decrypt_init(void) {
    return TRUE;
}

static void
vmess_keylog_reset(void)
{
    if (vmess_keylog_file) {
        fclose(vmess_keylog_file);
        vmess_keylog_file = NULL;
    }
}

void vmess_init(void)
{
    /* Allocate memory for key map, refer to packet-tls.c for a more complex key map management.
     * Currently, the k/v of key map are all plain strings. Therefore, the built-in g_xxx
     * funtions should be enough:)
     */
    vmess_key_map = g_hash_table_new_full(g_str_hash, g_str_equal, vmess_free, vmess_free);
    vmess_debug_flush();
}

void vmess_cleanup(void)
{
    g_hash_table_destroy(vmess_key_map);
    if (vmess_keylog_file) {
        fclose(vmess_keylog_file);
        vmess_keylog_file = NULL;
    }
}

void vmess_free(gpointer data)
{
    if (data == NULL)
        return;

    /* Note that the memory allocated by wmem_alloc should be freed
     * by wmem_free, instead of g_free.
     */
    wmem_free(wmem_file_scope(), data);
}

#ifdef VMESS_DECRYPT_DEBUG
void
vmess_debug_printf(const gchar* fmt, ...)
{
    va_list ap;

    if (!vmess_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(vmess_debug_file, fmt, ap);
    va_end(ap);
}

void
vmess_set_debug(const gchar* name) {
    static gint debug_file_must_be_closed;
    gint        use_stderr;

    use_stderr = name ? (strcmp(name, VMESS_DEBUG_USE_STDERR) == 0) : 0;

    if (debug_file_must_be_closed)
        fclose(vmess_debug_file);

    if (use_stderr)
        vmess_debug_file = stderr;
    else if (!name || (strcmp(name, "") == 0))
        vmess_debug_file = NULL;
    else
        vmess_debug_file = ws_fopen(name, "w");

    if (!use_stderr && vmess_debug_file)
        debug_file_must_be_closed = 1;
    else
        debug_file_must_be_closed = 0;

    vmess_debug_printf("Wireshark VMess debug log \n\n");
}

void
vmess_prefs_apply_cb(void) {
    vmess_set_debug(vmess_debug_file_name);
}

void
vmess_debug_flush(void)
{
    if (vmess_debug_file)
        fflush(vmess_debug_file);
}

void vmess_debug_print_hash_table(GHashTable* hash_table) {
    vmess_debug_printf("VMess Key Map size: %d\n", g_hash_table_size(hash_table));
    g_hash_table_foreach(hash_table, (GHFunc)vmess_debug_print_key_value, NULL);
}

void vmess_debug_print_key_value(gpointer key, gpointer value, gpointer user_data) {
    vmess_debug_printf("Key: %s, Value: %s\n", (char*)key, (char*)value);
}

#endif

/*
 * from_hex converts |hex_len| bytes of hex data from |in| and sets |*out| to
 * the result. |out->data| will be allocated using wmem_file_scope. Returns TRUE on
 * success.
 * 
 * Note that we manually add '\0' to the string end.
 */
static gboolean from_hex(gchar** out, const gchar* in, gsize hex_len) {
    gsize i;
    gsize size = (hex_len / 2) * sizeof(gchar);

    if (hex_len & 1)
        return FALSE;

    //*out = (gchar*)g_malloc((hex_len / 2)*sizeof(gchar));
    /* Manually add '\0' to the end. */
    *out = (gchar*)wmem_alloc(wmem_file_scope(), size + 1);
    for (i = 0; i < size; i++) {
        int a = ws_xton(in[i * 2]);
        int b = ws_xton(in[i * 2 + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        (*out)[i] = a << 4 | b; /* NOTE: Bracket-ref [] is prior to dereference * */
    }
    (*out)[i] = '\0';
    return TRUE;
}

void
proto_register_vmess(void)
{
    module_t* vmess_module;

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

    proto_vmess = proto_register_protocol(
        "VMESS Protocol", /* name        */
        "VMESS",          /* short name  */
        "vmess"           /* filter_name */
    );

    proto_register_field_array(proto_vmess, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&proto_vmess_streaming_reassembly_table,
        &addresses_ports_reassembly_table_functions);

    vmess_handle = register_dissector("vmess", dissect_vmess, proto_vmess);

#ifdef VMESS_DECRYPT_DEBUG
    vmess_module = prefs_register_protocol(proto_vmess, vmess_prefs_apply_cb);
#else
    vmess_module = prefs_register_protocol(proto_vmess, NULL);
#endif // VMESS_DECRYPT_DEBUG

    prefs_register_filename_preference(vmess_module, "keylog_file", "Key log filename",
        "The path to the file which contains a list of secrets in the following format:\n"
        "\"<key-type> = <base64-encoded-key>\" (without quotes, leading spaces and spaces around '=' are ignored).\n"
        "<key-type> is one of: AUTH, REMOTE_STATIC_PUBLIC_KEY, "
        "LOCAL_EPHEMERAL_PRIVATE_KEY or PRESHARED_KEY.",
        &pref_keylog_file, FALSE);

    prefs_register_filename_preference(vmess_module, "debug_file", "VMess debug file",
        "Redirect VMess debug to the file specified. Leave empty to disable debugging "
        "or use \"" VMESS_DEBUG_USE_STDERR "\" to redirect output to stderr.",
        &vmess_debug_file_name, TRUE);


    register_init_routine(vmess_init);
    register_cleanup_routine(vmess_cleanup);

    vmess_decryption_supported = vmess_decrypt_init();
}

void
proto_reg_handoff_vmess(void)
{
    //vmess_handle = create_dissector_handle(dissect_vmess, proto_vmess);
    //vmess_request_handle = create_dissector_handle(dissect_vmess_request, proto_vmess);
#ifdef VMESS_DECRYPT_DEBUG
    vmess_set_debug(vmess_debug_file_name);
#endif
    tls_handle = find_dissector("tls");
    dissector_add_uint("tcp.port", VMESS_TCP_PORT, vmess_handle);
}

bool
gbytearray_eq(const GByteArray* arr_1, const GByteArray* arr_2) {
    if (arr_1 == NULL && arr_2 == NULL)
        return true;

    if (arr_1 == NULL || arr_2 == NULL)
        return false;

    if (arr_1->len != arr_2->len)
        return false;

    return memcmp(arr_1->data, arr_2->data, arr_1->len) == 0;
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
            return (gint)i; /* Warning: Convert unsigned int to int */
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
    char* buffer = (char*)malloc(bufsize);
    tvb_get_raw_bytes_as_string(tvb, offset, buffer, bufsize);
    /* Strip the terminating nul for both buffer and needle */
    return mem_search(buffer, bufsize - 1, needle, 3);
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
