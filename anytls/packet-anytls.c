/* packet-anytls.c
 * AnyTLS over decrypted TLS.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <epan/address.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tls.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/wmem_scopes.h>

#define ANYTLS_AUTH_DIGEST_LENGTH 32
#define ANYTLS_AUTH_HEADER_LENGTH 34
#define ANYTLS_FRAME_HEADER_LENGTH 7
#define ANYTLS_MAX_AUTH_PADDING 8192
#define ANYTLS_MAX_SETTINGS_LENGTH 1024
#define ANYTLS_MAX_TLS_RECORD_LENGTH 18432

#define ANYTLS_CMD_WASTE 0
#define ANYTLS_CMD_SYN 1
#define ANYTLS_CMD_PSH 2
#define ANYTLS_CMD_FIN 3
#define ANYTLS_CMD_SETTINGS 4
#define ANYTLS_CMD_ALERT 5
#define ANYTLS_CMD_UPDATE_PADDING 6
#define ANYTLS_CMD_SYNACK 7
#define ANYTLS_CMD_HEART_REQUEST 8
#define ANYTLS_CMD_HEART_RESPONSE 9
#define ANYTLS_CMD_SERVER_SETTINGS 10

#define ANYTLS_ATYPE_IPV4 1
#define ANYTLS_ATYPE_DOMAIN 3
#define ANYTLS_ATYPE_IPV6 4

void proto_register_anytls(void);
void proto_reg_handoff_anytls(void);

static int proto_anytls;
static dissector_handle_t anytls_handle;
static dissector_handle_t anytls_stream_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t data_handle;

static int hf_anytls_direction;
static int hf_anytls_authentication;
static int hf_anytls_auth_padding_length;
static int hf_anytls_auth_padding;
static int hf_anytls_command;
static int hf_anytls_stream_id;
static int hf_anytls_payload_length;
static int hf_anytls_settings_version;
static int hf_anytls_settings_client;
static int hf_anytls_settings_padding_md5;
static int hf_anytls_alert;
static int hf_anytls_padding_scheme;
static int hf_anytls_padding;
static int hf_anytls_payload;
static int hf_anytls_address_type;
static int hf_anytls_domain_length;
static int hf_anytls_domain;
static int hf_anytls_ipv4;
static int hf_anytls_ipv6;
static int hf_anytls_destination_port;

static int ett_anytls;
static int ett_anytls_auth;
static int ett_anytls_frame;
static int ett_anytls_destination;

static expert_field ei_anytls_malformed = EI_INIT;
static expert_field ei_anytls_truncated = EI_INIT;
static expert_field ei_anytls_invalid_settings = EI_INIT;
static expert_field ei_anytls_unsupported_command = EI_INIT;
static expert_field ei_anytls_unsupported_address = EI_INIT;
static expert_field ei_anytls_unsupported_payload = EI_INIT;

static reassembly_table anytls_stream_reassembly_table;
REASSEMBLE_ITEMS_DEFINE(anytls_inner_tls, "AnyTLS inner TLS");

static wmem_map_t *anytls_streams;

static const value_string direction_values[] = {
  {0, "client to server"},
  {1, "server to client"},
  {0, NULL}
};

static const value_string command_values[] = {
  {ANYTLS_CMD_WASTE, "Waste"},
  {ANYTLS_CMD_SYN, "SYN"},
  {ANYTLS_CMD_PSH, "PSH"},
  {ANYTLS_CMD_FIN, "FIN"},
  {ANYTLS_CMD_SETTINGS, "Settings"},
  {ANYTLS_CMD_ALERT, "Alert"},
  {ANYTLS_CMD_UPDATE_PADDING, "Update Padding Scheme"},
  {ANYTLS_CMD_SYNACK, "SYN-ACK"},
  {ANYTLS_CMD_HEART_REQUEST, "Heartbeat Request"},
  {ANYTLS_CMD_HEART_RESPONSE, "Heartbeat Response"},
  {ANYTLS_CMD_SERVER_SETTINGS, "Server Settings"},
  {0, NULL}
};

static const value_string address_type_values[] = {
  {ANYTLS_ATYPE_IPV4, "IPv4"},
  {ANYTLS_ATYPE_DOMAIN, "Domain"},
  {ANYTLS_ATYPE_IPV6, "IPv6"},
  {0, NULL}
};

typedef enum {
  PREFACE_VALID,
  PREFACE_NEED_MORE,
  PREFACE_BAD_PADDING,
  PREFACE_BAD_SETTINGS
} preface_status_t;

typedef struct {
  preface_status_t status;
  unsigned needed;
  unsigned padding_length;
  unsigned settings_offset;
  unsigned settings_length;
  unsigned frames_offset;
} preface_parse_t;

typedef enum {
  DESTINATION_VALID,
  DESTINATION_NEED_MORE,
  DESTINATION_BAD_TYPE,
  DESTINATION_BAD_DOMAIN,
  DESTINATION_BAD_PORT
} destination_status_t;

typedef struct {
  destination_status_t status;
  unsigned needed;
  unsigned address_type;
  unsigned address_offset;
  unsigned address_length;
  unsigned domain_length_offset;
  unsigned port_offset;
  unsigned header_length;
} destination_parse_t;

typedef struct {
  address client_address;
  uint32_t client_port;
  uint32_t preface_frame;
  uint32_t preface_tls_seq;
} anytls_conversation_state;

typedef struct {
  uint32_t inner_conversation_id;
  streaming_reassembly_info_t *reassembly[2];
  uint64_t destination_identity;
  int8_t inner_is_tls[2];
} anytls_stream_state;

typedef struct {
  anytls_stream_state *state;
  unsigned direction;
  uint64_t payload_identity;
} anytls_stream_context;

static void
anytls_init(void)
{
  anytls_streams = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
}

static bool
settings_value_matches(tvbuff_t *tvb, unsigned value_offset,
                       unsigned value_length, const char *expected)
{
  size_t expected_length = strlen(expected);

  return value_length == expected_length &&
         tvb_memeql(tvb, value_offset, expected, (int)expected_length) == 0;
}

static bool
settings_padding_md5_valid(tvbuff_t *tvb, unsigned offset, unsigned length)
{
  if (length != 32)
    return false;
  for (unsigned i = 0; i < length; i++) {
    uint8_t byte = tvb_get_uint8(tvb, offset + i);
    if (!((byte >= '0' && byte <= '9') ||
          (byte >= 'a' && byte <= 'f') ||
          (byte >= 'A' && byte <= 'F')))
      return false;
  }
  return true;
}

static bool
settings_valid(tvbuff_t *tvb, unsigned offset, unsigned length)
{
  unsigned end = offset + length;
  unsigned line_offset = offset;
  bool has_version = false;
  bool has_padding_md5 = false;

  if (length == 0 || length > ANYTLS_MAX_SETTINGS_LENGTH)
    return false;

  while (line_offset < end) {
    unsigned line_end = line_offset;
    unsigned equals = end;

    while (line_end < end && tvb_get_uint8(tvb, line_end) != '\n') {
      uint8_t byte = tvb_get_uint8(tvb, line_end);
      if (byte < 0x20 || byte > 0x7e)
        return false;
      if (byte == '=' && equals == end)
        equals = line_end;
      line_end++;
    }
    if (equals == end || equals == line_offset)
      return false;

    if (equals - line_offset == 1 &&
        tvb_get_uint8(tvb, line_offset) == 'v' &&
        settings_value_matches(tvb, equals + 1, line_end - equals - 1, "2"))
      has_version = true;
    if (equals - line_offset == 11 &&
        tvb_memeql(tvb, line_offset, "padding-md5", 11) == 0 &&
        settings_padding_md5_valid(tvb, equals + 1,
                                   line_end - equals - 1))
      has_padding_md5 = true;

    line_offset = line_end + 1;
  }

  return has_version && has_padding_md5;
}

static preface_parse_t
parse_preface(tvbuff_t *tvb)
{
  preface_parse_t parsed = {PREFACE_VALID, 0, 0, 0, 0, 0};
  unsigned length = tvb_captured_length(tvb);
  unsigned frame_offset;
  uint8_t command;
  uint32_t stream_id;

  if (length < ANYTLS_AUTH_HEADER_LENGTH) {
    parsed.status = PREFACE_NEED_MORE;
    parsed.needed = ANYTLS_AUTH_HEADER_LENGTH;
    return parsed;
  }

  parsed.padding_length = tvb_get_ntohs(tvb, ANYTLS_AUTH_DIGEST_LENGTH);
  if (parsed.padding_length > ANYTLS_MAX_AUTH_PADDING) {
    parsed.status = PREFACE_BAD_PADDING;
    return parsed;
  }

  frame_offset = ANYTLS_AUTH_HEADER_LENGTH + parsed.padding_length;
  parsed.frames_offset = frame_offset;
  if (length < frame_offset + ANYTLS_FRAME_HEADER_LENGTH) {
    parsed.status = PREFACE_NEED_MORE;
    parsed.needed = frame_offset + ANYTLS_FRAME_HEADER_LENGTH;
    return parsed;
  }

  command = tvb_get_uint8(tvb, frame_offset);
  stream_id = tvb_get_ntohl(tvb, frame_offset + 1);
  parsed.settings_length = tvb_get_ntohs(tvb, frame_offset + 5);
  parsed.settings_offset = frame_offset + ANYTLS_FRAME_HEADER_LENGTH;
  if (command != ANYTLS_CMD_SETTINGS || stream_id != 0 ||
      parsed.settings_length == 0 ||
      parsed.settings_length > ANYTLS_MAX_SETTINGS_LENGTH) {
    parsed.status = PREFACE_BAD_SETTINGS;
    return parsed;
  }
  if (length < parsed.settings_offset + parsed.settings_length) {
    parsed.status = PREFACE_NEED_MORE;
    parsed.needed = parsed.settings_offset + parsed.settings_length;
    return parsed;
  }
  if (!settings_valid(tvb, parsed.settings_offset, parsed.settings_length)) {
    parsed.status = PREFACE_BAD_SETTINGS;
    return parsed;
  }

  return parsed;
}

static destination_parse_t
parse_destination(tvbuff_t *tvb)
{
  destination_parse_t parsed = {DESTINATION_VALID, 0, 0, 0, 0, 0, 0, 0};
  unsigned length = tvb_captured_length(tvb);
  unsigned offset = 1;

  if (length < 1) {
    parsed.status = DESTINATION_NEED_MORE;
    parsed.needed = 1;
    return parsed;
  }
  parsed.address_type = tvb_get_uint8(tvb, 0);

  switch (parsed.address_type) {
  case ANYTLS_ATYPE_IPV4:
    parsed.address_offset = offset;
    parsed.address_length = 4;
    offset += 4;
    break;
  case ANYTLS_ATYPE_IPV6:
    parsed.address_offset = offset;
    parsed.address_length = 16;
    offset += 16;
    break;
  case ANYTLS_ATYPE_DOMAIN:
    parsed.domain_length_offset = offset;
    if (length < offset + 1) {
      parsed.status = DESTINATION_NEED_MORE;
      parsed.needed = offset + 1;
      return parsed;
    }
    parsed.address_length = tvb_get_uint8(tvb, offset);
    if (parsed.address_length == 0) {
      parsed.status = DESTINATION_BAD_DOMAIN;
      return parsed;
    }
    parsed.address_offset = offset + 1;
    offset = parsed.address_offset + parsed.address_length;
    break;
  default:
    parsed.status = DESTINATION_BAD_TYPE;
    return parsed;
  }

  parsed.port_offset = offset;
  parsed.header_length = offset + 2;
  if (length < parsed.header_length) {
    parsed.status = DESTINATION_NEED_MORE;
    parsed.needed = parsed.header_length;
    return parsed;
  }
  if (tvb_get_ntohs(tvb, parsed.port_offset) == 0)
    parsed.status = DESTINATION_BAD_PORT;
  return parsed;
}

static bool
tls_record_plausible(tvbuff_t *tvb, unsigned offset)
{
  uint8_t content_type;
  uint16_t record_length;

  if (tvb_captured_length_remaining(tvb, offset) < 5)
    return false;
  content_type = tvb_get_uint8(tvb, offset);
  record_length = tvb_get_ntohs(tvb, offset + 3);
  return content_type >= 20 && content_type <= 24 &&
         tvb_get_uint8(tvb, offset + 1) == 3 &&
         tvb_get_uint8(tvb, offset + 2) <= 4 &&
         record_length > 0 &&
         record_length <= ANYTLS_MAX_TLS_RECORD_LENGTH;
}

static char *
stream_key(wmem_allocator_t *scope, conversation_t *conversation,
           uint32_t stream_id)
{
  return wmem_strdup_printf(scope, "%p:%" PRIu32, (void *)conversation,
                            stream_id);
}

static anytls_stream_state *
get_stream_state(packet_info *pinfo, uint32_t stream_id)
{
  conversation_t *conversation = find_or_create_conversation(pinfo);
  char *key = stream_key(wmem_packet_scope(), conversation, stream_id);
  anytls_stream_state *state =
      (anytls_stream_state *)wmem_map_lookup(anytls_streams, key);

  if (state == NULL) {
    uintptr_t identity = (uintptr_t)conversation;
    char *stored_key;

    state = wmem_new0(wmem_file_scope(), anytls_stream_state);
    state->reassembly[0] = streaming_reassembly_info_new();
    state->reassembly[1] = streaming_reassembly_info_new();
    state->inner_is_tls[0] = -1;
    state->inner_is_tls[1] = -1;
    state->inner_conversation_id =
        (uint32_t)((identity >> 4) ^ (identity >> 32) ^ stream_id);
    if (state->inner_conversation_id == 0)
      state->inner_conversation_id = 1;
    stored_key = stream_key(wmem_file_scope(), conversation, stream_id);
    wmem_map_insert(anytls_streams, stored_key, state);
  }
  return state;
}

static void
add_destination_tree(tvbuff_t *tvb, proto_tree *tree,
                     const destination_parse_t *parsed)
{
  proto_item *item;
  proto_tree *destination_tree = proto_tree_add_subtree_format(
      tree, tvb, 0, parsed->header_length, ett_anytls_destination, &item,
      "Destination");

  proto_tree_add_item(destination_tree, hf_anytls_address_type, tvb, 0, 1,
                      ENC_BIG_ENDIAN);
  if (parsed->address_type == ANYTLS_ATYPE_IPV4) {
    proto_tree_add_item(destination_tree, hf_anytls_ipv4, tvb,
                        parsed->address_offset, 4, ENC_BIG_ENDIAN);
  } else if (parsed->address_type == ANYTLS_ATYPE_IPV6) {
    proto_tree_add_item(destination_tree, hf_anytls_ipv6, tvb,
                        parsed->address_offset, 16, ENC_NA);
  } else {
    proto_tree_add_item(destination_tree, hf_anytls_domain_length, tvb,
                        parsed->domain_length_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(destination_tree, hf_anytls_domain, tvb,
                        parsed->address_offset, parsed->address_length,
                        ENC_UTF_8 | ENC_NA);
  }
  proto_tree_add_item(destination_tree, hf_anytls_destination_port, tvb,
                      parsed->port_offset, 2, ENC_BIG_ENDIAN);
}

static void
call_inner_tls_range(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     const anytls_stream_state *state, unsigned offset,
                     unsigned length)
{
  conversation_element_t *saved_elements = pinfo->conv_elements;
  port_type saved_ptype = pinfo->ptype;
  tvbuff_t *payload = tvb_new_subset_length(tvb, offset, length);

  conversation_set_elements_by_id(pinfo, CONVERSATION_NONE,
                                  state->inner_conversation_id);
  pinfo->ptype = PT_NONE;
  call_dissector(tls_handle, payload, pinfo, tree);
  if (pinfo->desegment_len != 0)
    pinfo->desegment_offset += offset;
  pinfo->ptype = saved_ptype;
  pinfo->conv_elements = saved_elements;
}

static void
call_inner_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               const anytls_stream_state *state, unsigned offset)
{
  unsigned length = tvb_captured_length(tvb);
  unsigned scan = offset;

  while (scan < length) {
    unsigned remaining = length - scan;
    unsigned record_length;

    if (remaining < 5)
      break;
    if (!tls_record_plausible(tvb, scan)) {
      call_inner_tls_range(tvb, pinfo, tree, state, offset, length - offset);
      return;
    }
    record_length = 5 + tvb_get_ntohs(tvb, scan + 3);
    if (remaining < record_length)
      break;
    scan += record_length;
  }

  if (scan == length) {
    call_inner_tls_range(tvb, pinfo, tree, state, offset, length - offset);
    return;
  }

  if (scan > offset)
    call_inner_tls_range(tvb, pinfo, tree, state, offset, scan - offset);
  if (pinfo->can_desegment) {
    pinfo->desegment_offset = scan;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
  }
}

static int
dissect_anytls_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      void *data)
{
  anytls_stream_context *context = (anytls_stream_context *)data;
  anytls_stream_state *state = context->state;
  unsigned direction = context->direction;
  unsigned length = tvb_captured_length(tvb);
  unsigned offset = 0;
  proto_tree *inner_tree = proto_tree_get_root(tree);

  if (direction == 0 &&
      (state->destination_identity == 0 ||
       state->destination_identity == context->payload_identity)) {
    destination_parse_t parsed = parse_destination(tvb);

    if (parsed.status == DESTINATION_NEED_MORE && pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return length;
    }
    if (parsed.status != DESTINATION_VALID) {
      expert_field *expert = parsed.status == DESTINATION_BAD_TYPE
                                 ? &ei_anytls_unsupported_address
                                 : &ei_anytls_malformed;
      proto_tree_add_expert(tree, pinfo, expert, tvb, 0, length);
      call_dissector(data_handle, tvb, pinfo, tree);
      state->inner_is_tls[direction] = 0;
      return length;
    }
    add_destination_tree(tvb, tree, &parsed);
    if (!PINFO_FD_VISITED(pinfo) && state->destination_identity == 0)
      state->destination_identity = context->payload_identity;
    offset = parsed.header_length;
  }

  if (offset >= length)
    return length;
  if (state->inner_is_tls[direction] == 1) {
    call_inner_tls(tvb, pinfo, inner_tree, state, offset);
    return length;
  }
  if (length - offset < 5) {
    if (pinfo->can_desegment) {
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    }
    return length;
  }
  if (!tls_record_plausible(tvb, offset)) {
    proto_tree_add_expert(tree, pinfo, &ei_anytls_unsupported_payload, tvb,
                          offset, length - offset);
    call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo,
                   tree);
    state->inner_is_tls[direction] = 0;
    return length;
  }

  state->inner_is_tls[direction] = 1;
  call_inner_tls(tvb, pinfo, inner_tree, state, offset);
  return length;
}

static void
add_settings_fields(tvbuff_t *tvb, proto_tree *tree, unsigned offset,
                    unsigned length)
{
  unsigned end = offset + length;
  unsigned line_offset = offset;

  while (line_offset < end) {
    unsigned line_end = line_offset;
    unsigned equals = end;
    int field = -1;

    while (line_end < end && tvb_get_uint8(tvb, line_end) != '\n') {
      if (tvb_get_uint8(tvb, line_end) == '=' && equals == end)
        equals = line_end;
      line_end++;
    }
    if (equals < line_end) {
      if (equals - line_offset == 1 &&
          tvb_get_uint8(tvb, line_offset) == 'v')
        field = hf_anytls_settings_version;
      else if (equals - line_offset == 6 &&
               tvb_memeql(tvb, line_offset, "client", 6) == 0)
        field = hf_anytls_settings_client;
      else if (equals - line_offset == 11 &&
               tvb_memeql(tvb, line_offset, "padding-md5", 11) == 0)
        field = hf_anytls_settings_padding_md5;
      if (field != -1)
        proto_tree_add_item(tree, field, tvb, equals + 1,
                            line_end - equals - 1, ENC_ASCII);
    }
    line_offset = line_end + 1;
  }
}

static bool
command_semantics_valid(uint8_t command, uint32_t stream_id)
{
  if (command > ANYTLS_CMD_SERVER_SETTINGS)
    return false;
  switch (command) {
  case ANYTLS_CMD_WASTE:
  case ANYTLS_CMD_SETTINGS:
  case ANYTLS_CMD_ALERT:
  case ANYTLS_CMD_UPDATE_PADDING:
  case ANYTLS_CMD_SERVER_SETTINGS:
    return stream_id == 0;
  case ANYTLS_CMD_SYN:
  case ANYTLS_CMD_PSH:
  case ANYTLS_CMD_FIN:
  case ANYTLS_CMD_SYNACK:
    return stream_id != 0;
  default:
    return true;
  }
}

static unsigned
dissect_frames(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               unsigned offset, unsigned direction)
{
  unsigned length = tvb_captured_length(tvb);

  while (offset < length) {
    unsigned remaining = length - offset;
    uint8_t command;
    uint32_t stream_id;
    unsigned payload_length;
    unsigned frame_length;
    proto_item *item;
    proto_tree *frame_tree;

    if (remaining < ANYTLS_FRAME_HEADER_LENGTH) {
      if (pinfo->can_desegment) {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      } else {
        proto_tree_add_expert(tree, pinfo, &ei_anytls_truncated, tvb, offset,
                              remaining);
      }
      return length;
    }

    command = tvb_get_uint8(tvb, offset);
    stream_id = tvb_get_ntohl(tvb, offset + 1);
    payload_length = tvb_get_ntohs(tvb, offset + 5);
    frame_length = ANYTLS_FRAME_HEADER_LENGTH + payload_length;
    if (remaining < frame_length) {
      if (pinfo->can_desegment) {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      } else {
        proto_tree_add_expert(tree, pinfo, &ei_anytls_truncated, tvb, offset,
                              remaining);
      }
      return length;
    }

    item = proto_tree_add_protocol_format(
        tree, proto_anytls, tvb, offset, frame_length, "AnyTLS %s, stream %u",
        val_to_str_const(command, command_values, "Unknown"), stream_id);
    frame_tree = proto_item_add_subtree(item, ett_anytls_frame);
    proto_item *direction_item =
        proto_tree_add_uint(frame_tree, hf_anytls_direction, tvb, offset, 0,
                            direction);
    proto_item_set_generated(direction_item);
    proto_tree_add_item(frame_tree, hf_anytls_command, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(frame_tree, hf_anytls_stream_id, tvb, offset + 1, 4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(frame_tree, hf_anytls_payload_length, tvb, offset + 5,
                        2, ENC_BIG_ENDIAN);

    if (!command_semantics_valid(command, stream_id)) {
      proto_tree_add_expert(frame_tree, pinfo,
                            command > ANYTLS_CMD_SERVER_SETTINGS
                                ? &ei_anytls_unsupported_command
                                : &ei_anytls_malformed,
                            tvb, offset, frame_length);
    }

    if (payload_length > 0) {
      unsigned payload_offset = offset + ANYTLS_FRAME_HEADER_LENGTH;

      switch (command) {
      case ANYTLS_CMD_SETTINGS:
      case ANYTLS_CMD_SERVER_SETTINGS:
        add_settings_fields(tvb, frame_tree, payload_offset, payload_length);
        if (!settings_valid(tvb, payload_offset, payload_length) &&
            command == ANYTLS_CMD_SETTINGS)
          proto_tree_add_expert(frame_tree, pinfo,
                                &ei_anytls_invalid_settings, tvb,
                                payload_offset, payload_length);
        break;
      case ANYTLS_CMD_WASTE:
        proto_tree_add_item(frame_tree, hf_anytls_padding, tvb, payload_offset,
                            payload_length, ENC_NA);
        break;
      case ANYTLS_CMD_ALERT:
        proto_tree_add_item(frame_tree, hf_anytls_alert, tvb, payload_offset,
                            payload_length, ENC_UTF_8 | ENC_NA);
        break;
      case ANYTLS_CMD_UPDATE_PADDING:
        proto_tree_add_item(frame_tree, hf_anytls_padding_scheme, tvb,
                            payload_offset, payload_length, ENC_UTF_8 | ENC_NA);
        break;
      case ANYTLS_CMD_PSH: {
        anytls_stream_state *state = get_stream_state(pinfo, stream_id);
        anytls_stream_context context = {
          state,
          direction,
          get_virtual_frame_num64(tvb, pinfo, payload_offset)
        };
        reassemble_streaming_data_and_call_subdissector(
            tvb, pinfo, payload_offset, payload_length, frame_tree, frame_tree,
            anytls_stream_reassembly_table, state->reassembly[direction],
            context.payload_identity, anytls_stream_handle, frame_tree,
            &context, "AnyTLS inner TLS", &anytls_inner_tls_fragment_items,
            hf_anytls_inner_tls_segment);
        break;
      }
      default:
        proto_tree_add_item(frame_tree, hf_anytls_payload, tvb, payload_offset,
                            payload_length, ENC_NA);
        break;
      }
    }
    offset += frame_length;
  }
  return length;
}

static bool
packet_from_client(packet_info *pinfo,
                   const anytls_conversation_state *state)
{
  return pinfo->srcport == state->client_port &&
         addresses_equal(&pinfo->src, &state->client_address);
}

static int
dissect_anytls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  conversation_t *conversation = find_or_create_conversation(pinfo);
  anytls_conversation_state *state =
      (anytls_conversation_state *)conversation_get_proto_data(
          conversation, proto_anytls);
  struct tlsinfo *tlsinfo = (struct tlsinfo *)data;
  uint32_t tls_seq = tlsinfo != NULL ? tlsinfo->seq : 0;
  bool from_client;
  proto_item *root_item;
  proto_tree *anytls_tree;
  unsigned offset = 0;

  if (state == NULL) {
    state = wmem_new0(wmem_file_scope(), anytls_conversation_state);
    copy_address_wmem(wmem_file_scope(), &state->client_address, &pinfo->src);
    state->client_port = pinfo->srcport;
    conversation_add_proto_data(conversation, proto_anytls, state);
  }
  from_client = packet_from_client(pinfo, state);
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AnyTLS");
  col_set_str(pinfo->cinfo, COL_INFO,
              from_client ? "AnyTLS client data" : "AnyTLS server data");

  root_item = proto_tree_add_item(tree, proto_anytls, tvb, 0, -1, ENC_NA);
  anytls_tree = proto_item_add_subtree(root_item, ett_anytls);

  if (from_client &&
      (state->preface_frame == 0 ||
       (state->preface_frame == pinfo->num &&
        state->preface_tls_seq == tls_seq))) {
    preface_parse_t parsed = parse_preface(tvb);
    proto_item *auth_item;
    proto_tree *auth_tree;

    if (parsed.status == PREFACE_NEED_MORE && pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return tvb_captured_length(tvb);
    }
    if (parsed.status != PREFACE_VALID) {
      proto_tree_add_expert(
          anytls_tree, pinfo,
          parsed.status == PREFACE_BAD_SETTINGS
              ? &ei_anytls_invalid_settings
              : &ei_anytls_malformed,
          tvb, 0, tvb_captured_length(tvb));
      return tvb_captured_length(tvb);
    }

    auth_item = proto_tree_add_none_format(
        anytls_tree, hf_anytls_authentication, tvb, 0, parsed.frames_offset,
        "Authentication preface (digest hidden), %u padding bytes",
        parsed.padding_length);
    auth_tree = proto_item_add_subtree(auth_item, ett_anytls_auth);
    proto_tree_add_item(auth_tree, hf_anytls_authentication, tvb, 0,
                        ANYTLS_AUTH_DIGEST_LENGTH, ENC_NA);
    proto_tree_add_item(auth_tree, hf_anytls_auth_padding_length, tvb,
                        ANYTLS_AUTH_DIGEST_LENGTH, 2, ENC_BIG_ENDIAN);
    if (parsed.padding_length > 0)
      proto_tree_add_item(auth_tree, hf_anytls_auth_padding, tvb,
                          ANYTLS_AUTH_HEADER_LENGTH, parsed.padding_length,
                          ENC_NA);
    if (!PINFO_FD_VISITED(pinfo)) {
      state->preface_frame = pinfo->num;
      state->preface_tls_seq = tls_seq;
    }
    offset = parsed.frames_offset;
  }

  return dissect_frames(tvb, pinfo, anytls_tree, offset,
                        from_client ? 0 : 1);
}

static bool
dissect_anytls_heur_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        void *data)
{
  preface_parse_t parsed = parse_preface(tvb);
  struct tlsinfo *tlsinfo = (struct tlsinfo *)data;

  if (parsed.status == PREFACE_NEED_MORE && pinfo->can_desegment) {
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return false;
  }
  if (parsed.status != PREFACE_VALID || tlsinfo == NULL ||
      tlsinfo->app_handle == NULL)
    return false;

  *(tlsinfo->app_handle) = anytls_handle;
  dissect_anytls(tvb, pinfo, tree, data);
  return true;
}

static int
dissect_anytls_tcp_fixture(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, void *data _U_)
{
  return dissect_anytls(tvb, pinfo, tree, NULL);
}

void
proto_register_anytls(void)
{
  static hf_register_info hf[] = {
    {&hf_anytls_direction,
     {"Direction", "anytls.direction", FT_UINT8, BASE_DEC,
      VALS(direction_values), 0x0, NULL, HFILL}},
    {&hf_anytls_authentication,
     {"Authentication digest (hidden)", "anytls.authentication", FT_NONE,
      BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_auth_padding_length,
     {"Authentication padding length", "anytls.auth_padding_length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_auth_padding,
     {"Authentication padding", "anytls.auth_padding", FT_BYTES, BASE_NONE,
      NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_command,
     {"Command", "anytls.command", FT_UINT8, BASE_DEC, VALS(command_values),
      0x0, NULL, HFILL}},
    {&hf_anytls_stream_id,
     {"Stream ID", "anytls.stream_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
      HFILL}},
    {&hf_anytls_payload_length,
     {"Payload length", "anytls.payload_length", FT_UINT16, BASE_DEC, NULL,
      0x0, NULL, HFILL}},
    {&hf_anytls_settings_version,
     {"Protocol version", "anytls.settings.version", FT_STRING, BASE_NONE,
      NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_settings_client,
     {"Client metadata", "anytls.settings.client", FT_STRING, BASE_NONE, NULL,
      0x0, NULL, HFILL}},
    {&hf_anytls_settings_padding_md5,
     {"Padding scheme MD5", "anytls.settings.padding_md5", FT_STRING,
      BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_alert,
     {"Alert", "anytls.alert", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_padding_scheme,
     {"Padding scheme", "anytls.padding_scheme", FT_STRING, BASE_NONE, NULL,
      0x0, NULL, HFILL}},
    {&hf_anytls_padding,
     {"Waste padding", "anytls.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
      HFILL}},
    {&hf_anytls_payload,
     {"Payload", "anytls.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
      HFILL}},
    {&hf_anytls_address_type,
     {"Address type", "anytls.address_type", FT_UINT8, BASE_DEC,
      VALS(address_type_values), 0x0, NULL, HFILL}},
    {&hf_anytls_domain_length,
     {"Domain length", "anytls.destination.domain_length", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_anytls_domain,
     {"Domain", "anytls.destination.domain", FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}},
    {&hf_anytls_ipv4,
     {"IPv4 destination", "anytls.destination.ipv4", FT_IPv4, BASE_NONE, NULL,
      0x0, NULL, HFILL}},
    {&hf_anytls_ipv6,
     {"IPv6 destination", "anytls.destination.ipv6", FT_IPv6, BASE_NONE, NULL,
      0x0, NULL, HFILL}},
    {&hf_anytls_destination_port,
     {"Destination port", "anytls.destination.port", FT_UINT16, BASE_DEC,
      NULL, 0x0, NULL, HFILL}},
    REASSEMBLE_INIT_HF_ITEMS(anytls_inner_tls, "AnyTLS inner TLS",
                             "anytls.inner_tls")
  };
  static int *ett[] = {
    &ett_anytls,
    &ett_anytls_auth,
    &ett_anytls_frame,
    &ett_anytls_destination,
    REASSEMBLE_INIT_ETT_ITEMS(anytls_inner_tls)
  };
  static ei_register_info ei[] = {
    {&ei_anytls_malformed,
     {"anytls.malformed", PI_MALFORMED, PI_ERROR, "Malformed AnyTLS data",
      EXPFILL}},
    {&ei_anytls_truncated,
     {"anytls.truncated", PI_MALFORMED, PI_WARN, "Truncated AnyTLS data",
      EXPFILL}},
    {&ei_anytls_invalid_settings,
     {"anytls.invalid_settings", PI_PROTOCOL, PI_WARN,
      "Invalid AnyTLS settings", EXPFILL}},
    {&ei_anytls_unsupported_command,
     {"anytls.unsupported_command", PI_UNDECODED, PI_WARN,
      "Unsupported AnyTLS command", EXPFILL}},
    {&ei_anytls_unsupported_address,
     {"anytls.unsupported_address_type", PI_PROTOCOL, PI_WARN,
      "Unsupported AnyTLS address type", EXPFILL}},
    {&ei_anytls_unsupported_payload,
     {"anytls.unsupported_stream_payload", PI_UNDECODED, PI_WARN,
      "AnyTLS stream payload is not TLS", EXPFILL}}
  };
  expert_module_t *expert_anytls;

  proto_anytls =
      proto_register_protocol("AnyTLS", "AnyTLS", "anytls");
  proto_register_field_array(proto_anytls, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_anytls = expert_register_protocol(proto_anytls);
  expert_register_field_array(expert_anytls, ei, array_length(ei));
  reassembly_table_register(&anytls_stream_reassembly_table,
                            &addresses_reassembly_table_functions);
  register_init_routine(anytls_init);
}

void
proto_reg_handoff_anytls(void)
{
  dissector_handle_t tcp_fixture_handle;

  anytls_handle =
      register_dissector("anytls", dissect_anytls, proto_anytls);
  anytls_stream_handle =
      register_dissector("anytls.stream", dissect_anytls_stream,
                         proto_anytls);
  tcp_fixture_handle =
      create_dissector_handle(dissect_anytls_tcp_fixture, proto_anytls);
  dissector_add_for_decode_as("tcp.port", tcp_fixture_handle);
  tls_handle = find_dissector_add_dependency("tls", proto_anytls);
  data_handle = find_dissector("data");
  heur_dissector_add("tls", dissect_anytls_heur_tls, "AnyTLS over TLS",
                     "anytls_tls", proto_anytls, HEURISTIC_ENABLE);
}
