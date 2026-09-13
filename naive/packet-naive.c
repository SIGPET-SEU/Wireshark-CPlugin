/* packet-naive.c
 * NaiveProxy over HTTP/2 CONNECT.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <epan/conversation.h>
#include <epan/dissectors/packet-http2.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/wmem_scopes.h>

#define NAIVE_PADDING_FRAMES 8
#define NAIVE_MIN_HEADER_PADDING 30
#define NAIVE_MAX_HEADER_PADDING 61
#define NAIVE_MAX_TLS_RECORD 18432
#define NAIVE_MAX_BUFFER (1024U * 1024U)

void proto_register_naive(void);
void proto_reg_handoff_naive(void);

static int proto_naive;
static dissector_handle_t tls_handle;
static dissector_handle_t data_handle;

static int hf_naive_stream_id;
static int hf_naive_direction;
static int hf_naive_destination;
static int hf_naive_http_padding_length;
static int hf_naive_response_status;
static int hf_naive_padding_frame;
static int hf_naive_data_length;
static int hf_naive_padding_length;
static int hf_naive_padding;
static int hf_naive_tunneled_data;
static int hf_naive_reassembled_tls_length;

static int ett_naive;
static int ett_naive_padding_frame;

static expert_field ei_naive_malformed = EI_INIT;
static expert_field ei_naive_truncated = EI_INIT;
static expert_field ei_naive_unsupported_payload = EI_INIT;

static wmem_map_t *naive_streams;
static uint32_t naive_last_frame;

static const value_string direction_values[] = {
    {0, "client to server"}, {1, "server to client"}, {0, NULL}};

typedef struct {
  uint8_t padding_frames[2];
  uint32_t inner_conversation_id;
  GByteArray *tls_bytes[2];
  int8_t inner_is_tls[2];
} naive_stream_state;

static void naive_init(void) {
  naive_streams = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
}

static bool naive_header_padding_valid(const char *padding) {
  static const char symbols[] = "!#$()+<>?@[]^`{}";
  size_t length;

  if (padding == NULL)
    return false;
  length = strlen(padding);
  if (length < NAIVE_MIN_HEADER_PADDING || length > NAIVE_MAX_HEADER_PADDING)
    return false;
  for (size_t i = 0; i < 16; i++) {
    if (strchr(symbols, padding[i]) == NULL)
      return false;
  }
  for (size_t i = 16; i < length; i++) {
    if (padding[i] != '~')
      return false;
  }
  return true;
}

static bool naive_target_valid(const char *target) {
  const char *colon;
  uint32_t port = 0;

  if (target == NULL || target[0] == '\0')
    return false;
  colon = strrchr(target, ':');
  if (colon == NULL || colon == target || colon[1] == '\0')
    return false;
  if (target[0] == '[' && (colon == target + 1 || colon[-1] != ']'))
    return false;
  for (const char *p = colon + 1; *p != '\0'; p++) {
    if (*p < '0' || *p > '9')
      return false;
    port = port * 10 + (uint32_t)(*p - '0');
    if (port > 65535)
      return false;
  }
  return port != 0;
}

static char *naive_stream_key(wmem_allocator_t *scope,
                              conversation_t *conversation,
                              uint32_t stream_id) {
  return wmem_strdup_printf(scope, "%p:%" PRIu32, (void *)conversation,
                            stream_id);
}

static naive_stream_state *naive_get_state(packet_info *pinfo,
                                           uint32_t stream_id) {
  conversation_t *conversation = find_or_create_conversation(pinfo);
  char *key = naive_stream_key(wmem_packet_scope(), conversation, stream_id);
  naive_stream_state *state =
      (naive_stream_state *)wmem_map_lookup(naive_streams, key);

  if (state == NULL) {
    char *stored_key;
    uintptr_t identity = (uintptr_t)conversation;
    state = wmem_new0(wmem_file_scope(), naive_stream_state);
    state->tls_bytes[0] = g_byte_array_new();
    state->tls_bytes[1] = g_byte_array_new();
    state->inner_is_tls[0] = -1;
    state->inner_is_tls[1] = -1;
    state->inner_conversation_id =
        (uint32_t)((identity >> 4) ^ stream_id ^ (identity >> 32));
    if (state->inner_conversation_id == 0)
      state->inner_conversation_id = 1;
    stored_key = naive_stream_key(wmem_file_scope(), conversation, stream_id);
    wmem_map_insert(naive_streams, stored_key, state);
  }
  return state;
}

static bool naive_tls_record_plausible(const uint8_t *bytes, size_t length,
                                       unsigned *record_length) {
  unsigned payload_length;

  if (length < 5)
    return false;
  if (bytes[0] < 20 || bytes[0] > 24 || bytes[1] != 3 || bytes[2] > 4)
    return false;
  payload_length = ((unsigned)bytes[3] << 8) | bytes[4];
  if (payload_length > NAIVE_MAX_TLS_RECORD)
    return false;
  *record_length = payload_length + 5;
  return true;
}

static void naive_call_inner_tls(tvbuff_t *parent, packet_info *pinfo,
                                 proto_tree *tree,
                                 const naive_stream_state *state,
                                 const uint8_t *bytes, unsigned length) {
  conversation_element_t *saved_elements = pinfo->conv_elements;
  port_type saved_ptype = pinfo->ptype;
  uint8_t *copy = (uint8_t *)g_memdup2(bytes, length);
  tvbuff_t *tls_tvb = tvb_new_child_real_data(parent, copy, length, length);

  tvb_set_free_cb(tls_tvb, g_free);
  add_new_data_source(pinfo, tls_tvb, "Reassembled Naive tunnel TLS");
  conversation_set_elements_by_id(pinfo, CONVERSATION_NONE,
                                  state->inner_conversation_id);
  pinfo->ptype = PT_NONE;
  call_dissector(tls_handle, tls_tvb, pinfo, tree);
  pinfo->ptype = saved_ptype;
  pinfo->conv_elements = saved_elements;
}

static void naive_process_tunnel_bytes(tvbuff_t *parent, packet_info *pinfo,
                                       proto_tree *tree,
                                       naive_stream_state *state,
                                       unsigned direction, const uint8_t *bytes,
                                       unsigned length,
                                       proto_tree *naive_tree) {
  GByteArray *buffer = state->tls_bytes[direction];

  if (length == 0)
    return;
  if (state->inner_is_tls[direction] == 0) {
    tvbuff_t *payload =
        tvb_new_real_data((uint8_t *)g_memdup2(bytes, length), length, length);
    tvb_set_free_cb(payload, g_free);
    call_dissector(data_handle, payload, pinfo, tree);
    return;
  }
  g_byte_array_append(buffer, bytes, length);
  if (buffer->len > NAIVE_MAX_BUFFER) {
    proto_tree_add_expert(naive_tree, pinfo, &ei_naive_malformed, parent, 0,
                          tvb_captured_length(parent));
    g_byte_array_set_size(buffer, 0);
    state->inner_is_tls[direction] = 0;
    return;
  }

  while (buffer->len >= 5) {
    unsigned record_length;
    if (!naive_tls_record_plausible(buffer->data, buffer->len,
                                    &record_length)) {
      tvbuff_t *payload =
          tvb_new_real_data((uint8_t *)g_memdup2(buffer->data, buffer->len),
                            buffer->len, buffer->len);
      tvb_set_free_cb(payload, g_free);
      call_dissector(data_handle, payload, pinfo, tree);
      proto_tree_add_expert(naive_tree, pinfo, &ei_naive_unsupported_payload,
                            parent, 0, tvb_captured_length(parent));
      g_byte_array_set_size(buffer, 0);
      state->inner_is_tls[direction] = 0;
      return;
    }
    state->inner_is_tls[direction] = 1;
    if (buffer->len < record_length)
      return;
    proto_tree_add_uint(naive_tree, hf_naive_reassembled_tls_length, parent, 0,
                        0, record_length);
    naive_call_inner_tls(parent, pinfo, tree, state, buffer->data,
                         record_length);
    g_byte_array_remove_range(buffer, 0, record_length);
  }
}

static unsigned naive_add_padding_frame(tvbuff_t *tvb, proto_tree *naive_tree,
                                        unsigned offset, unsigned frame_number,
                                        unsigned data_length,
                                        unsigned padding_length) {
  unsigned total = 3 + data_length + padding_length;
  proto_item *item = proto_tree_add_uint_format(
      naive_tree, hf_naive_padding_frame, tvb, offset, total, frame_number,
      "Padding frame %u: %u data bytes, %u padding bytes", frame_number,
      data_length, padding_length);
  proto_tree *frame_tree =
      proto_item_add_subtree(item, ett_naive_padding_frame);

  proto_tree_add_item(frame_tree, hf_naive_data_length, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(frame_tree, hf_naive_padding_length, tvb, offset + 2, 1,
                      ENC_BIG_ENDIAN);
  if (data_length)
    proto_tree_add_item(frame_tree, hf_naive_tunneled_data, tvb, offset + 3,
                        data_length, ENC_NA);
  if (padding_length)
    proto_tree_add_item(frame_tree, hf_naive_padding, tvb,
                        offset + 3 + data_length, padding_length, ENC_NA);
  return total;
}

static bool dissect_naive_http2_data(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data) {
  http2_data_info_t *data_info = (http2_data_info_t *)data;
  const char *method;
  const char *padding;
  const char *target;
  const char *status;
  bool from_server;
  unsigned direction;
  unsigned offset = 0;
  unsigned length = tvb_captured_length(tvb);
  naive_stream_state *state;
  proto_item *item;
  proto_tree *naive_tree;

  if (data_info == NULL)
    return false;
  method = http2_get_header_value(pinfo, HTTP2_HEADER_METHOD, false);
  padding = http2_get_header_value(pinfo, "padding", false);
  target = http2_get_header_value(pinfo, "-connect-authority", false);
  if (target == NULL)
    target = http2_get_header_value(pinfo, HTTP2_HEADER_AUTHORITY, false);
  if (data_info->probe) {
    return method != NULL && strcmp(method, HTTP2_HEADER_METHOD_CONNECT) == 0 &&
           naive_header_padding_valid(padding) && naive_target_valid(target);
  }

  if (pinfo->num < naive_last_frame)
    naive_init();
  naive_last_frame = pinfo->num;

  from_server =
      method == NULL || strcmp(method, HTTP2_HEADER_METHOD_CONNECT) != 0;
  direction = from_server ? 1 : 0;
  if (from_server) {
    target = http2_get_header_value(pinfo, "-connect-authority", true);
    if (target == NULL)
      target = http2_get_header_value(pinfo, HTTP2_HEADER_AUTHORITY, true);
    status = http2_get_header_value(pinfo, HTTP2_HEADER_STATUS, false);
  } else {
    status = NULL;
  }
  state = naive_get_state(pinfo, data_info->stream_id);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NAIVE");
  col_set_str(pinfo->cinfo, COL_INFO,
              from_server ? "NaiveProxy tunneled response"
                          : "NaiveProxy tunneled request");
  item = proto_tree_add_item(tree, proto_naive, tvb, 0, length, ENC_NA);
  naive_tree = proto_item_add_subtree(item, ett_naive);
  proto_tree_add_uint(naive_tree, hf_naive_stream_id, tvb, 0, 0,
                      data_info->stream_id);
  proto_tree_add_uint(naive_tree, hf_naive_direction, tvb, 0, 0, direction);
  if (target != NULL)
    proto_tree_add_string(naive_tree, hf_naive_destination, tvb, 0, 0, target);
  if (padding != NULL)
    proto_tree_add_uint(naive_tree, hf_naive_http_padding_length, tvb, 0, 0,
                        (uint32_t)strlen(padding));
  if (status != NULL)
    proto_tree_add_string(naive_tree, hf_naive_response_status, tvb, 0, 0,
                          status);

  while (offset < length &&
         state->padding_frames[direction] < NAIVE_PADDING_FRAMES) {
    unsigned remaining = length - offset;
    unsigned data_length;
    unsigned padding_length;
    unsigned total;
    uint8_t *payload;

    if (remaining < 3) {
      if (data_info->end_stream) {
        proto_tree_add_expert(naive_tree, pinfo, &ei_naive_truncated, tvb,
                              offset, remaining);
        return true;
      }
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = 3 - remaining;
      return true;
    }
    data_length = tvb_get_ntohs(tvb, offset);
    padding_length = tvb_get_uint8(tvb, offset + 2);
    total = 3 + data_length + padding_length;
    if (remaining < total) {
      if (data_info->end_stream) {
        proto_tree_add_expert(naive_tree, pinfo, &ei_naive_truncated, tvb,
                              offset, remaining);
        return true;
      }
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = total - remaining;
      return true;
    }
    naive_add_padding_frame(tvb, naive_tree, offset,
                            state->padding_frames[direction] + 1, data_length,
                            padding_length);
    if (data_length) {
      payload = (uint8_t *)wmem_alloc(pinfo->pool, data_length);
      tvb_memcpy(tvb, payload, offset + 3, data_length);
      naive_process_tunnel_bytes(tvb, pinfo, tree, state, direction, payload,
                                 data_length, naive_tree);
    }
    state->padding_frames[direction]++;
    offset += total;
  }

  if (offset < length) {
    unsigned payload_length = length - offset;
    uint8_t *payload = (uint8_t *)wmem_alloc(pinfo->pool, payload_length);
    proto_tree_add_item(naive_tree, hf_naive_tunneled_data, tvb, offset,
                        payload_length, ENC_NA);
    tvb_memcpy(tvb, payload, offset, payload_length);
    naive_process_tunnel_bytes(tvb, pinfo, tree, state, direction, payload,
                               payload_length, naive_tree);
  }
  return true;
}

void proto_register_naive(void) {
  static hf_register_info hf[] = {
      {&hf_naive_stream_id,
       {"HTTP/2 Stream ID", "naive.stream_id", FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_naive_direction,
       {"Direction", "naive.direction", FT_UINT8, BASE_DEC,
        VALS(direction_values), 0, NULL, HFILL}},
      {&hf_naive_destination,
       {"CONNECT Destination", "naive.destination", FT_STRING, BASE_NONE, NULL,
        0, NULL, HFILL}},
      {&hf_naive_http_padding_length,
       {"HTTP Padding Header Length", "naive.http_padding_length", FT_UINT32,
        BASE_DEC, NULL, 0, NULL, HFILL}},
      {&hf_naive_response_status,
       {"HTTP Response Status", "naive.response.status", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL}},
      {&hf_naive_padding_frame,
       {"Padding Frame", "naive.padding_frame", FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_naive_data_length,
       {"Original Data Length", "naive.data_length", FT_UINT16, BASE_DEC, NULL,
        0, NULL, HFILL}},
      {&hf_naive_padding_length,
       {"Padding Length", "naive.padding_length", FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_naive_padding,
       {"Padding", "naive.padding", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_naive_tunneled_data,
       {"Tunneled Data", "naive.tunneled_data", FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_naive_reassembled_tls_length,
       {"Reassembled TLS Record Length", "naive.tls_record_length", FT_UINT32,
        BASE_DEC, NULL, 0, NULL, HFILL}}};
  static int *ett[] = {&ett_naive, &ett_naive_padding_frame};
  static ei_register_info ei[] = {
      {&ei_naive_malformed,
       {"naive.malformed", PI_MALFORMED, PI_ERROR, "Malformed Naive data",
        EXPFILL}},
      {&ei_naive_truncated,
       {"naive.truncated", PI_MALFORMED, PI_WARN, "Truncated Naive data",
        EXPFILL}},
      {&ei_naive_unsupported_payload,
       {"naive.unsupported_payload", PI_UNDECODED, PI_NOTE,
        "Naive tunnel payload is not TLS", EXPFILL}}};
  expert_module_t *expert_naive;

  proto_naive = proto_register_protocol("NaiveProxy", "NAIVE", "naive");
  proto_register_field_array(proto_naive, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_naive = expert_register_protocol(proto_naive);
  expert_register_field_array(expert_naive, ei, array_length(ei));
  register_init_routine(naive_init);
}

void proto_reg_handoff_naive(void) {
  tls_handle = find_dissector_add_dependency("tls", proto_naive);
  data_handle = find_dissector("data");
  heur_dissector_add("http2.data", dissect_naive_http2_data,
                     "NaiveProxy HTTP/2 CONNECT", "naive_http2_data",
                     proto_naive, HEURISTIC_ENABLE);
}
