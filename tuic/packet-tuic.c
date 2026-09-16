/* packet-tuic.c
 * TUIC v5 over QUIC.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <inttypes.h>
#include <stdint.h>

#include <epan/conversation.h>
#include <epan/dissectors/packet-quic.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/wmem_scopes.h>

#define TUIC_VERSION 0x05
#define TUIC_AUTHENTICATE 0x00
#define TUIC_CONNECT 0x01
#define TUIC_PACKET 0x02
#define TUIC_DISSOCIATE 0x03
#define TUIC_HEARTBEAT 0x04
#define TUIC_AUTH_LENGTH 50
#define TUIC_MAX_TLS_RECORD (16384U + 2048U)

void proto_register_tuic(void);
void proto_reg_handoff_tuic(void);

static int proto_tuic;
static dissector_handle_t tuic_stream_fixture_handle;
static dissector_handle_t tuic_datagram_fixture_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t data_handle;
static dissector_table_t udp_port_table;

static int hf_tuic_version;
static int hf_tuic_command;
static int hf_tuic_stream_id;
static int hf_tuic_direction;
static int hf_tuic_authentication;
static int hf_tuic_address_type;
static int hf_tuic_domain_length;
static int hf_tuic_domain;
static int hf_tuic_ipv4;
static int hf_tuic_ipv6;
static int hf_tuic_destination_port;
static int hf_tuic_session_id;
static int hf_tuic_packet_id;
static int hf_tuic_fragment_total;
static int hf_tuic_fragment_id;
static int hf_tuic_payload_length;
static int hf_tuic_payload;
static int hf_tuic_fragments;
static int hf_tuic_fragment;
static int hf_tuic_fragment_overlap;
static int hf_tuic_fragment_overlap_conflict;
static int hf_tuic_fragment_multiple_tails;
static int hf_tuic_fragment_too_long_fragment;
static int hf_tuic_fragment_error;
static int hf_tuic_fragment_count;
static int hf_tuic_reassembled_in;
static int hf_tuic_reassembled_length;
static int hf_tuic_reassembled_data;

static int ett_tuic;
static int ett_tuic_auth;
static int ett_tuic_connect;
static int ett_tuic_packet;
static int ett_tuic_fragments;
static int ett_tuic_fragment;

static expert_field ei_tuic_malformed = EI_INIT;
static expert_field ei_tuic_truncated = EI_INIT;
static expert_field ei_tuic_version = EI_INIT;
static expert_field ei_tuic_command = EI_INIT;
static expert_field ei_tuic_address = EI_INIT;
static expert_field ei_tuic_fragment = EI_INIT;

static wmem_map_t *tuic_streams;
static wmem_map_t *tuic_connections;
static reassembly_table tuic_udp_reassembly_table;

static const value_string command_values[] = {
    {TUIC_AUTHENTICATE, "Authenticate"},
    {TUIC_CONNECT, "Connect"},
    {TUIC_PACKET, "Packet"},
    {TUIC_DISSOCIATE, "Dissociate"},
    {TUIC_HEARTBEAT, "Heartbeat"},
    {0, NULL}};

static const value_string address_type_values[] = {
    {0x00, "Domain"}, {0x01, "IPv4"}, {0x02, "IPv6"},
    {0xff, "Empty"}, {0, NULL}};

static const fragment_items tuic_udp_frag_items = {
    &ett_tuic_fragment,
    &ett_tuic_fragments,
    &hf_tuic_fragments,
    &hf_tuic_fragment,
    &hf_tuic_fragment_overlap,
    &hf_tuic_fragment_overlap_conflict,
    &hf_tuic_fragment_multiple_tails,
    &hf_tuic_fragment_too_long_fragment,
    &hf_tuic_fragment_error,
    &hf_tuic_fragment_count,
    &hf_tuic_reassembled_in,
    &hf_tuic_reassembled_length,
    &hf_tuic_reassembled_data,
    "TUIC UDP fragments"};

typedef enum {
  TUIC_PARSE_OK,
  TUIC_PARSE_NEED_MORE,
  TUIC_PARSE_NOT_TUIC,
  TUIC_PARSE_MALFORMED
} tuic_parse_status;

typedef struct {
  tuic_parse_status status;
  unsigned type_offset;
  unsigned value_offset;
  unsigned value_length;
  unsigned port_offset;
  unsigned next_offset;
  uint8_t type;
  uint16_t port;
  bool empty;
} tuic_address;

typedef struct {
  tuic_parse_status status;
  tuic_address address;
  unsigned header_length;
} tuic_connect_parse;

typedef struct {
  tuic_parse_status status;
  tuic_address address;
  unsigned payload_offset;
  uint16_t session_id;
  uint16_t packet_id;
  uint8_t fragment_total;
  uint8_t fragment_id;
  uint16_t payload_length;
} tuic_packet_parse;

typedef struct {
  struct quic_info_data *quic_info;
  uint64_t stream_id;
  uint32_t inner_conversation_id;
  uint32_t request_frame;
  unsigned request_header_length;
} tuic_stream_state;

static void tuic_init(void) {
  tuic_streams = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
  tuic_connections =
      wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
}

static char *tuic_stream_key(wmem_allocator_t *scope,
                             struct quic_info_data *quic_info,
                             uint64_t stream_id) {
  return wmem_strdup_printf(scope, "%p:%" PRIu64, (void *)quic_info,
                            stream_id);
}

static bool tuic_connection_known(struct quic_info_data *quic_info) {
  return quic_info != NULL &&
         wmem_map_lookup(tuic_connections, quic_info) != NULL;
}

static void tuic_mark_connection(struct quic_info_data *quic_info) {
  if (quic_info != NULL)
    wmem_map_insert(tuic_connections, quic_info, GINT_TO_POINTER(1));
}

static tuic_address tuic_parse_address(tvbuff_t *tvb, unsigned offset) {
  tuic_address result = {TUIC_PARSE_OK, offset, 0, 0, 0, 0, 0, 0, false};
  unsigned length = tvb_captured_length(tvb);

  if (offset >= length) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  result.type = tvb_get_uint8(tvb, offset++);
  result.value_offset = offset;
  switch (result.type) {
  case 0x00:
    if (offset >= length) {
      result.status = TUIC_PARSE_NEED_MORE;
      return result;
    }
    result.value_length = tvb_get_uint8(tvb, offset++);
    result.value_offset = offset;
    if (result.value_length == 0) {
      result.status = TUIC_PARSE_MALFORMED;
      return result;
    }
    if (length < offset + result.value_length) {
      result.status = TUIC_PARSE_NEED_MORE;
      return result;
    }
    for (unsigned i = 0; i < result.value_length; i++) {
      uint8_t c = tvb_get_uint8(tvb, offset + i);
      if (c < 0x21 || c > 0x7e) {
        result.status = TUIC_PARSE_MALFORMED;
        return result;
      }
    }
    offset += result.value_length;
    break;
  case 0x01:
    result.value_length = 4;
    if (length < offset + 4) {
      result.status = TUIC_PARSE_NEED_MORE;
      return result;
    }
    offset += 4;
    break;
  case 0x02:
    result.value_length = 16;
    if (length < offset + 16) {
      result.status = TUIC_PARSE_NEED_MORE;
      return result;
    }
    offset += 16;
    break;
  case 0xff:
    result.empty = true;
    result.next_offset = offset;
    return result;
  default:
    result.status = TUIC_PARSE_MALFORMED;
    return result;
  }
  result.port_offset = offset;
  if (length < offset + 2) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  result.port = tvb_get_ntohs(tvb, offset);
  result.next_offset = offset + 2;
  if (result.port == 0)
    result.status = TUIC_PARSE_MALFORMED;
  return result;
}

static bool tuic_plausible_tls(tvbuff_t *tvb, unsigned offset) {
  unsigned length = tvb_captured_length(tvb);
  uint8_t content_type;
  uint16_t record_length;

  if (length < offset + 5)
    return false;
  content_type = tvb_get_uint8(tvb, offset);
  if (content_type < 20 || content_type > 23 ||
      tvb_get_uint8(tvb, offset + 1) != 3 ||
      tvb_get_uint8(tvb, offset + 2) > 4)
    return false;
  record_length = tvb_get_ntohs(tvb, offset + 3);
  return record_length > 0 && record_length <= TUIC_MAX_TLS_RECORD;
}

static tuic_connect_parse tuic_parse_connect(tvbuff_t *tvb,
                                             bool known_connection) {
  tuic_connect_parse result;
  unsigned length = tvb_captured_length(tvb);
  result.status = TUIC_PARSE_OK;
  result.header_length = 0;

  if (length < 1) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  if (tvb_get_uint8(tvb, 0) != TUIC_VERSION) {
    result.status = TUIC_PARSE_NOT_TUIC;
    return result;
  }
  if (length < 2) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  if (tvb_get_uint8(tvb, 1) != TUIC_CONNECT) {
    result.status = TUIC_PARSE_NOT_TUIC;
    return result;
  }
  result.address = tuic_parse_address(tvb, 2);
  if (result.address.status != TUIC_PARSE_OK || result.address.empty) {
    result.status = result.address.status == TUIC_PARSE_OK
                        ? TUIC_PARSE_MALFORMED
                        : result.address.status;
    return result;
  }
  result.header_length = result.address.next_offset;
  if (length < result.header_length + 5) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  if (!known_connection && !tuic_plausible_tls(tvb, result.header_length))
    result.status = TUIC_PARSE_NOT_TUIC;
  return result;
}

static tuic_packet_parse tuic_parse_packet(tvbuff_t *tvb, bool with_prefix) {
  tuic_packet_parse result;
  unsigned offset = with_prefix ? 2 : 0;
  unsigned length = tvb_captured_length(tvb);
  memset(&result, 0, sizeof(result));
  result.status = TUIC_PARSE_OK;

  if (with_prefix) {
    if (length < 2) {
      result.status = TUIC_PARSE_NEED_MORE;
      return result;
    }
    if (tvb_get_uint8(tvb, 0) != TUIC_VERSION ||
        tvb_get_uint8(tvb, 1) != TUIC_PACKET) {
      result.status = TUIC_PARSE_NOT_TUIC;
      return result;
    }
  }
  if (length < offset + 8) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  result.session_id = tvb_get_ntohs(tvb, offset);
  result.packet_id = tvb_get_ntohs(tvb, offset + 2);
  result.fragment_total = tvb_get_uint8(tvb, offset + 4);
  result.fragment_id = tvb_get_uint8(tvb, offset + 5);
  result.payload_length = tvb_get_ntohs(tvb, offset + 6);
  offset += 8;
  if (result.fragment_total == 0 ||
      result.fragment_id >= result.fragment_total ||
      result.payload_length == 0) {
    result.status = TUIC_PARSE_MALFORMED;
    return result;
  }
  result.address = tuic_parse_address(tvb, offset);
  if (result.address.status != TUIC_PARSE_OK) {
    result.status = result.address.status;
    return result;
  }
  if (result.fragment_id == 0 && result.address.empty) {
    result.status = TUIC_PARSE_MALFORMED;
    return result;
  }
  if (result.fragment_id > 0 && !result.address.empty) {
    result.status = TUIC_PARSE_MALFORMED;
    return result;
  }
  result.payload_offset = result.address.next_offset;
  if (length < result.payload_offset + result.payload_length) {
    result.status = TUIC_PARSE_NEED_MORE;
    return result;
  }
  if (length != result.payload_offset + result.payload_length)
    result.status = TUIC_PARSE_MALFORMED;
  return result;
}

static void tuic_add_common(proto_tree *tree, tvbuff_t *tvb, uint8_t command,
                            const quic_stream_info *stream_info) {
  proto_tree_add_item(tree, hf_tuic_version, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_uint(tree, hf_tuic_command, tvb, 1, 1, command);
  if (stream_info != NULL) {
    proto_item *stream = proto_tree_add_uint64(
        tree, hf_tuic_stream_id, tvb, 0, 0, stream_info->stream_id);
    proto_item_set_generated(stream);
    proto_item *direction = proto_tree_add_string(
        tree, hf_tuic_direction, tvb, 0, 0,
        stream_info->from_server ? "server to client" : "client to server");
    proto_item_set_generated(direction);
  }
}

static void tuic_add_address(proto_tree *tree, tvbuff_t *tvb,
                             const tuic_address *target) {
  proto_tree_add_item(tree, hf_tuic_address_type, tvb, target->type_offset, 1,
                      ENC_BIG_ENDIAN);
  if (target->empty)
    return;
  switch (target->type) {
  case 0x00:
    proto_tree_add_uint(tree, hf_tuic_domain_length, tvb,
                        target->value_offset - 1, 1, target->value_length);
    proto_tree_add_item(tree, hf_tuic_domain, tvb, target->value_offset,
                        target->value_length, ENC_ASCII | ENC_NA);
    break;
  case 0x01:
    proto_tree_add_item(tree, hf_tuic_ipv4, tvb, target->value_offset, 4,
                        ENC_BIG_ENDIAN);
    break;
  case 0x02:
    proto_tree_add_item(tree, hf_tuic_ipv6, tvb, target->value_offset, 16,
                        ENC_NA);
    break;
  }
  proto_tree_add_item(tree, hf_tuic_destination_port, tvb,
                      target->port_offset, 2, ENC_BIG_ENDIAN);
}

static void tuic_add_connect_tree(tvbuff_t *tvb, proto_tree *tree,
                                  const tuic_connect_parse *parsed,
                                  const quic_stream_info *stream_info) {
  proto_item *item = proto_tree_add_item(tree, proto_tuic, tvb, 0,
                                         parsed->header_length, ENC_NA);
  proto_tree *tuic_tree = proto_item_add_subtree(item, ett_tuic_connect);
  proto_item_append_text(item, ", Connect");
  tuic_add_common(tuic_tree, tvb, TUIC_CONNECT, stream_info);
  tuic_add_address(tuic_tree, tvb, &parsed->address);
}

static void tuic_call_inner_tls(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, unsigned offset,
                                const tuic_stream_state *state) {
  conversation_element_t *saved_elements = pinfo->conv_elements;
  port_type saved_ptype = pinfo->ptype;
  tvbuff_t *payload;

  if (offset >= tvb_captured_length(tvb))
    return;
  payload = tvb_new_subset_remaining(tvb, offset);
  conversation_set_elements_by_id(pinfo, CONVERSATION_NONE,
                                  state->inner_conversation_id);
  pinfo->ptype = PT_NONE;
  call_dissector(tls_handle, payload, pinfo, tree);
  if (pinfo->desegment_len)
    pinfo->desegment_offset += offset;
  pinfo->ptype = saved_ptype;
  pinfo->conv_elements = saved_elements;
}

static void tuic_add_auth_tree(tvbuff_t *tvb, proto_tree *tree,
                               const quic_stream_info *stream_info) {
  proto_item *item =
      proto_tree_add_item(tree, proto_tuic, tvb, 0, TUIC_AUTH_LENGTH, ENC_NA);
  proto_tree *tuic_tree = proto_item_add_subtree(item, ett_tuic_auth);
  proto_item_append_text(item, ", Authenticate");
  tuic_add_common(tuic_tree, tvb, TUIC_AUTHENTICATE, stream_info);
  proto_tree_add_item(tuic_tree, hf_tuic_authentication, tvb, 2, 48, ENC_NA);
}

static void tuic_add_packet_tree(tvbuff_t *tvb, proto_tree *tree,
                                 const tuic_packet_parse *parsed,
                                 const quic_stream_info *stream_info) {
  proto_item *item =
      proto_tree_add_item(tree, proto_tuic, tvb, 0, -1, ENC_NA);
  proto_tree *tuic_tree = proto_item_add_subtree(item, ett_tuic_packet);
  proto_item_append_text(item, ", Packet session %u", parsed->session_id);
  tuic_add_common(tuic_tree, tvb, TUIC_PACKET, stream_info);
  proto_tree_add_item(tuic_tree, hf_tuic_session_id, tvb, 2, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tuic_tree, hf_tuic_packet_id, tvb, 4, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tuic_tree, hf_tuic_fragment_total, tvb, 6, 1,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tuic_tree, hf_tuic_fragment_id, tvb, 7, 1,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tuic_tree, hf_tuic_payload_length, tvb, 8, 2,
                      ENC_BIG_ENDIAN);
  tuic_add_address(tuic_tree, tvb, &parsed->address);
  proto_tree_add_item(tuic_tree, hf_tuic_payload, tvb, parsed->payload_offset,
                      parsed->payload_length, ENC_NA);
}

static void tuic_call_udp_payload(tvbuff_t *payload, packet_info *pinfo,
                                  proto_tree *tree,
                                  const tuic_packet_parse *parsed,
                                  bool from_server) {
  conversation_element_t *saved_elements = pinfo->conv_elements;
  port_type saved_ptype = pinfo->ptype;
  uint32_t saved_srcport = pinfo->srcport;
  uint32_t saved_destport = pinfo->destport;
  uint16_t destination_port = parsed->address.port;
  uint32_t conversation_id =
      parsed->session_id ^ ((uint32_t)destination_port << 16);

  if (destination_port == 0) {
    call_dissector(data_handle, payload, pinfo, tree);
    return;
  }
  conversation_set_elements_by_id(pinfo, CONVERSATION_NONE,
                                  conversation_id ? conversation_id : 1);
  pinfo->ptype = PT_UDP;
  if (from_server)
    pinfo->srcport = destination_port;
  else
    pinfo->destport = destination_port;
  if (!dissector_try_uint(udp_port_table, destination_port, payload, pinfo,
                          tree))
    call_dissector(data_handle, payload, pinfo, tree);
  pinfo->srcport = saved_srcport;
  pinfo->destport = saved_destport;
  pinfo->ptype = saved_ptype;
  pinfo->conv_elements = saved_elements;
}

static void tuic_dissect_packet_payload(tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree,
                                        const tuic_packet_parse *parsed,
                                        bool from_server) {
  tvbuff_t *payload;
  proto_tree *tuic_tree = tree;

  if (parsed->fragment_total == 1) {
    payload = tvb_new_subset_length(tvb, parsed->payload_offset,
                                    parsed->payload_length);
    tuic_call_udp_payload(payload, pinfo, tree, parsed, from_server);
  } else {
    fragment_head *fragments;
    uint32_t reassembly_id = parsed->session_id ^
                             ((uint32_t)parsed->packet_id << 16) ^
                             (from_server ? 0x80000000U : 0);
    bool saved_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    fragments = fragment_add_seq_check(
        &tuic_udp_reassembly_table, tvb, parsed->payload_offset, pinfo,
        reassembly_id, NULL, parsed->fragment_id, parsed->payload_length,
        parsed->fragment_id + 1 < parsed->fragment_total);
    payload = process_reassembled_data(tvb, parsed->payload_offset, pinfo,
                                       "Reassembled TUIC UDP", fragments,
                                       &tuic_udp_frag_items, NULL, tuic_tree);
    pinfo->fragmented = saved_fragmented;
    if (payload)
      tuic_call_udp_payload(payload, pinfo, tree, parsed, from_server);
  }
}

static bool dissect_tuic_quic_stream(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data) {
  quic_stream_info *stream_info = (quic_stream_info *)data;
  unsigned length = tvb_captured_length(tvb);
  uint8_t stream_type;
  uint8_t command;
  char *key;
  tuic_stream_state *state;

  if (stream_info == NULL)
    return false;
  stream_type = QUIC_STREAM_TYPE(stream_info->stream_id);
  if (stream_type == QUIC_STREAM_CLIENT_BIDI) {
    key = tuic_stream_key(wmem_packet_scope(), stream_info->quic_info,
                          stream_info->stream_id);
    state = (tuic_stream_state *)wmem_map_lookup(tuic_streams, key);
    if (state == NULL) {
      tuic_connect_parse parsed;
      char *stored_key;
      if (stream_info->from_server)
        return false;
      parsed = tuic_parse_connect(
          tvb, tuic_connection_known(stream_info->quic_info));
      if (parsed.status == TUIC_PARSE_NEED_MORE && length > 0 &&
          tvb_get_uint8(tvb, 0) == TUIC_VERSION && pinfo->can_desegment) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return true;
      }
      if (parsed.status != TUIC_PARSE_OK)
        return false;
      state = wmem_new0(wmem_file_scope(), tuic_stream_state);
      state->quic_info = stream_info->quic_info;
      state->stream_id = stream_info->stream_id;
      state->request_frame = pinfo->num;
      state->request_header_length = parsed.header_length;
      state->inner_conversation_id =
          (uint32_t)(((uintptr_t)stream_info->quic_info >> 4) ^
                     stream_info->stream_id ^ (stream_info->stream_id >> 32));
      if (state->inner_conversation_id == 0)
        state->inner_conversation_id = 1;
      stored_key = tuic_stream_key(wmem_file_scope(), stream_info->quic_info,
                                   stream_info->stream_id);
      wmem_map_insert(tuic_streams, stored_key, state);
      tuic_mark_connection(stream_info->quic_info);
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
      col_set_str(pinfo->cinfo, COL_INFO, "TUIC Connect");
      tuic_add_connect_tree(tvb, tree, &parsed, stream_info);
      tuic_call_inner_tls(tvb, pinfo, tree, parsed.header_length, state);
      return true;
    }
    if (!stream_info->from_server && pinfo->num == state->request_frame) {
      tuic_connect_parse parsed = tuic_parse_connect(tvb, true);
      if (parsed.status != TUIC_PARSE_OK)
        return false;
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
      col_set_str(pinfo->cinfo, COL_INFO, "TUIC Connect");
      tuic_add_connect_tree(tvb, tree, &parsed, stream_info);
      tuic_call_inner_tls(tvb, pinfo, tree, parsed.header_length, state);
      return true;
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC tunneled TCP data");
    proto_tree_add_item(tree, proto_tuic, tvb, 0, 0, ENC_NA);
    tuic_call_inner_tls(tvb, pinfo, tree, 0, state);
    return true;
  }

  if ((stream_type & 0x02) == 0 || length < 1)
    return false;
  if (tvb_get_uint8(tvb, 0) != TUIC_VERSION)
    return false;
  if (length < 2) {
    if (pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return true;
    }
    return false;
  }
  command = tvb_get_uint8(tvb, 1);
  if (command == TUIC_AUTHENTICATE &&
      stream_type == QUIC_STREAM_CLIENT_UNI && !stream_info->from_server) {
    if (length < TUIC_AUTH_LENGTH && pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return true;
    }
    if (length != TUIC_AUTH_LENGTH)
      return false;
    tuic_mark_connection(stream_info->quic_info);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Authenticate");
    tuic_add_auth_tree(tvb, tree, stream_info);
    return true;
  }
  if (command == TUIC_PACKET) {
    tuic_packet_parse parsed = tuic_parse_packet(tvb, true);
    if (parsed.status == TUIC_PARSE_NEED_MORE && pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return true;
    }
    if (parsed.status != TUIC_PARSE_OK ||
        !tuic_connection_known(stream_info->quic_info))
      return false;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Packet stream");
    tuic_add_packet_tree(tvb, tree, &parsed, stream_info);
    tuic_dissect_packet_payload(tvb, pinfo, tree, &parsed,
                                stream_info->from_server);
    return true;
  }
  if (command == TUIC_DISSOCIATE && length == 4 &&
      tuic_connection_known(stream_info->quic_info)) {
    proto_item *item = proto_tree_add_item(tree, proto_tuic, tvb, 0, 4, ENC_NA);
    proto_tree *tuic_tree = proto_item_add_subtree(item, ett_tuic);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Dissociate");
    tuic_add_common(tuic_tree, tvb, TUIC_DISSOCIATE, stream_info);
    proto_tree_add_item(tuic_tree, hf_tuic_session_id, tvb, 2, 2,
                        ENC_BIG_ENDIAN);
    return true;
  }
  return false;
}

static bool dissect_tuic_quic_datagram(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree, void *data) {
  quic_datagram_info *datagram_info = (quic_datagram_info *)data;
  unsigned length = tvb_captured_length(tvb);
  uint8_t command;

  if (datagram_info == NULL || length < 2 ||
      tvb_get_uint8(tvb, 0) != TUIC_VERSION ||
      !tuic_connection_known(datagram_info->quic_info))
    return false;
  command = tvb_get_uint8(tvb, 1);
  if (command == TUIC_HEARTBEAT && length == 2) {
    proto_item *item = proto_tree_add_item(tree, proto_tuic, tvb, 0, 2, ENC_NA);
    proto_tree *tuic_tree = proto_item_add_subtree(item, ett_tuic);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Heartbeat");
    tuic_add_common(tuic_tree, tvb, TUIC_HEARTBEAT, NULL);
    return true;
  }
  if (command == TUIC_PACKET) {
    tuic_packet_parse parsed = tuic_parse_packet(tvb, true);
    if (parsed.status != TUIC_PARSE_OK)
      return false;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Packet datagram");
    tuic_add_packet_tree(tvb, tree, &parsed, NULL);
    tuic_dissect_packet_payload(tvb, pinfo, tree, &parsed,
                                datagram_info->from_server);
    return true;
  }
  return false;
}

static int dissect_tuic_stream_fixture(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree, void *data _U_) {
  unsigned length = tvb_captured_length(tvb);
  proto_item *item;
  proto_tree *tuic_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
  if (length >= 2 && tvb_get_uint8(tvb, 0) == TUIC_VERSION &&
      tvb_get_uint8(tvb, 1) == TUIC_CONNECT) {
    tuic_connect_parse parsed = tuic_parse_connect(tvb, false);
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Connect fixture");
    if (parsed.status == TUIC_PARSE_OK) {
      tuic_add_connect_tree(tvb, tree, &parsed, NULL);
      return length;
    }
    item = proto_tree_add_item(tree, proto_tuic, tvb, 0, length, ENC_NA);
    tuic_tree = proto_item_add_subtree(item, ett_tuic_connect);
    proto_tree_add_expert(tuic_tree, pinfo,
                          parsed.status == TUIC_PARSE_NEED_MORE
                              ? &ei_tuic_truncated
                              : &ei_tuic_address,
                          tvb, 0, length);
    return length;
  }
  if (length >= 2 && tvb_get_uint8(tvb, 0) == TUIC_VERSION &&
      tvb_get_uint8(tvb, 1) == TUIC_AUTHENTICATE) {
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Authenticate fixture");
    if (length == TUIC_AUTH_LENGTH)
      tuic_add_auth_tree(tvb, tree, NULL);
    else {
      item = proto_tree_add_item(tree, proto_tuic, tvb, 0, length, ENC_NA);
      tuic_tree = proto_item_add_subtree(item, ett_tuic_auth);
      proto_tree_add_expert(tuic_tree, pinfo, &ei_tuic_truncated, tvb, 0,
                            length);
    }
    return length;
  }
  item = proto_tree_add_item(tree, proto_tuic, tvb, 0, length, ENC_NA);
  tuic_tree = proto_item_add_subtree(item, ett_tuic);
  col_set_str(pinfo->cinfo, COL_INFO, "Malformed TUIC stream fixture");
  if (length > 0 && tvb_get_uint8(tvb, 0) != TUIC_VERSION)
    proto_tree_add_expert(tuic_tree, pinfo, &ei_tuic_version, tvb, 0, 1);
  else
    proto_tree_add_expert(tuic_tree, pinfo, &ei_tuic_command, tvb, 0, length);
  return length;
}

static int dissect_tuic_datagram_fixture(tvbuff_t *tvb, packet_info *pinfo,
                                         proto_tree *tree, void *data _U_) {
  unsigned length = tvb_captured_length(tvb);
  proto_item *item;
  proto_tree *tuic_tree;
  tuic_packet_parse parsed;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUIC");
  if (length == 2 && tvb_get_uint8(tvb, 0) == TUIC_VERSION &&
      tvb_get_uint8(tvb, 1) == TUIC_HEARTBEAT) {
    col_set_str(pinfo->cinfo, COL_INFO, "TUIC Heartbeat fixture");
    item = proto_tree_add_item(tree, proto_tuic, tvb, 0, 2, ENC_NA);
    tuic_tree = proto_item_add_subtree(item, ett_tuic);
    tuic_add_common(tuic_tree, tvb, TUIC_HEARTBEAT, NULL);
    return length;
  }
  parsed = tuic_parse_packet(tvb, true);
  col_set_str(pinfo->cinfo, COL_INFO, "TUIC Packet fixture");
  if (parsed.status == TUIC_PARSE_OK) {
    tuic_add_packet_tree(tvb, tree, &parsed, NULL);
    tuic_dissect_packet_payload(tvb, pinfo, tree, &parsed, false);
    return length;
  }
  item = proto_tree_add_item(tree, proto_tuic, tvb, 0, length, ENC_NA);
  tuic_tree = proto_item_add_subtree(item, ett_tuic_packet);
  if (length > 0 && tvb_get_uint8(tvb, 0) != TUIC_VERSION)
    proto_tree_add_expert(tuic_tree, pinfo, &ei_tuic_version, tvb, 0, 1);
  else if (parsed.status == TUIC_PARSE_NEED_MORE)
    proto_tree_add_expert(tuic_tree, pinfo, &ei_tuic_truncated, tvb, 0,
                          length);
  else
    proto_tree_add_expert(tuic_tree, pinfo, &ei_tuic_fragment, tvb, 0, length);
  return length;
}

void proto_register_tuic(void) {
  static hf_register_info hf[] = {
      {&hf_tuic_version,
       {"Version", "tuic.version", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
      {&hf_tuic_command,
       {"Command", "tuic.command", FT_UINT8, BASE_HEX, VALS(command_values),
        0, NULL, HFILL}},
      {&hf_tuic_stream_id,
       {"QUIC Stream ID", "tuic.stream_id", FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_direction,
       {"Direction", "tuic.direction", FT_STRING, BASE_NONE, NULL, 0, NULL,
        HFILL}},
      {&hf_tuic_authentication,
       {"Authentication material (hidden)", "tuic.authentication", FT_NONE,
        BASE_NONE, NULL, 0, "UUID and token intentionally not exposed",
        HFILL}},
      {&hf_tuic_address_type,
       {"Address Type", "tuic.address.type", FT_UINT8, BASE_HEX,
        VALS(address_type_values), 0, NULL, HFILL}},
      {&hf_tuic_domain_length,
       {"Domain Length", "tuic.address.domain_length", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_tuic_domain,
       {"Domain", "tuic.address.domain", FT_STRING, BASE_NONE, NULL, 0, NULL,
        HFILL}},
      {&hf_tuic_ipv4,
       {"IPv4 Address", "tuic.address.ipv4", FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_ipv6,
       {"IPv6 Address", "tuic.address.ipv6", FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_destination_port,
       {"Destination Port", "tuic.destination.port", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_tuic_session_id,
       {"UDP Session ID", "tuic.udp.session_id", FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_packet_id,
       {"UDP Packet ID", "tuic.udp.packet_id", FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_fragment_total,
       {"Fragment Total", "tuic.udp.fragment_total", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_tuic_fragment_id,
       {"Fragment ID", "tuic.udp.fragment_id", FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_payload_length,
       {"Payload Length", "tuic.payload_length", FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_payload,
       {"Payload", "tuic.payload", FT_BYTES, BASE_NONE, NULL, 0, NULL,
        HFILL}},
      {&hf_tuic_fragments,
       {"Message fragments", "tuic.fragments", FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_fragment,
       {"Message fragment", "tuic.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_tuic_fragment_overlap,
       {"Message fragment overlap", "tuic.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_tuic_fragment_overlap_conflict,
       {"Message fragment overlap conflict", "tuic.fragment.overlap.conflict",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_tuic_fragment_multiple_tails,
       {"Message has multiple tail fragments", "tuic.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_tuic_fragment_too_long_fragment,
       {"Message fragment too long", "tuic.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_tuic_fragment_error,
       {"Message defragmentation error", "tuic.fragment.error", FT_FRAMENUM,
        BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_tuic_fragment_count,
       {"Message fragment count", "tuic.fragment.count", FT_UINT32, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_tuic_reassembled_in,
       {"Reassembled in", "tuic.reassembled.in", FT_FRAMENUM, BASE_NONE,
        NULL, 0, NULL, HFILL}},
      {&hf_tuic_reassembled_length,
       {"Reassembled length", "tuic.reassembled.length", FT_UINT32, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_tuic_reassembled_data,
       {"Reassembled data", "tuic.reassembled.data", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL}}};
  static int *ett[] = {&ett_tuic, &ett_tuic_auth, &ett_tuic_connect,
                       &ett_tuic_packet, &ett_tuic_fragments,
                       &ett_tuic_fragment};
  static ei_register_info ei[] = {
      {&ei_tuic_malformed,
       {"tuic.malformed", PI_MALFORMED, PI_ERROR, "Malformed TUIC data",
        EXPFILL}},
      {&ei_tuic_truncated,
       {"tuic.truncated", PI_MALFORMED, PI_WARN, "Truncated TUIC data",
        EXPFILL}},
      {&ei_tuic_version,
       {"tuic.unsupported_version", PI_PROTOCOL, PI_ERROR,
        "Unsupported TUIC version", EXPFILL}},
      {&ei_tuic_command,
       {"tuic.unsupported_command", PI_PROTOCOL, PI_ERROR,
        "Unsupported TUIC command", EXPFILL}},
      {&ei_tuic_address,
       {"tuic.invalid_address", PI_PROTOCOL, PI_ERROR,
        "Invalid TUIC destination address", EXPFILL}},
      {&ei_tuic_fragment,
       {"tuic.invalid_fragment", PI_REASSEMBLE, PI_ERROR,
        "Invalid TUIC fragment metadata", EXPFILL}}};
  expert_module_t *expert_tuic;

  proto_tuic = proto_register_protocol("TUIC v5", "TUIC", "tuic");
  proto_register_field_array(proto_tuic, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tuic = expert_register_protocol(proto_tuic);
  expert_register_field_array(expert_tuic, ei, array_length(ei));
  register_init_routine(tuic_init);
  reassembly_table_register(&tuic_udp_reassembly_table,
                            &addresses_ports_reassembly_table_functions);
}

void proto_reg_handoff_tuic(void) {
  tuic_stream_fixture_handle = register_dissector(
      "tuic_stream", dissect_tuic_stream_fixture, proto_tuic);
  tuic_datagram_fixture_handle = register_dissector(
      "tuic_datagram", dissect_tuic_datagram_fixture, proto_tuic);
  dissector_add_for_decode_as("tcp.port", tuic_stream_fixture_handle);
  dissector_add_for_decode_as("udp.port", tuic_datagram_fixture_handle);
  tls_handle = find_dissector_add_dependency("tls", proto_tuic);
  data_handle = find_dissector("data");
  udp_port_table = find_dissector_table("udp.port");
  heur_dissector_add("quic.stream", dissect_tuic_quic_stream,
                     "TUIC v5 QUIC stream", "tuic_quic_stream", proto_tuic,
                     HEURISTIC_ENABLE);
  heur_dissector_add("quic.datagram", dissect_tuic_quic_datagram,
                     "TUIC v5 QUIC DATAGRAM", "tuic_quic_datagram",
                     proto_tuic, HEURISTIC_ENABLE);
}
