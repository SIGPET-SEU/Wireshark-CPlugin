/* packet-trojan.c
 * Trojan over decrypted TLS.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdint.h>
#include <string.h>

#include <epan/address.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tls.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/wmem_scopes.h>

#define TROJAN_HASH_LENGTH 56
#define TROJAN_CRLF_LENGTH 2
#define TROJAN_COMMAND_CONNECT 1
#define TROJAN_COMMAND_UDP_ASSOCIATE 3
#define TROJAN_ATYPE_IPV4 1
#define TROJAN_ATYPE_DOMAIN 3
#define TROJAN_ATYPE_IPV6 4
#define TROJAN_TLS_RECORD_HEADER_LENGTH 5
#define TROJAN_TLS_RECORD_MAX_LENGTH 18432
#define TROJAN_MAX_BUFFER (1024U * 1024U)

void proto_register_trojan(void);
void proto_reg_handoff_trojan(void);

static int proto_trojan;
static dissector_handle_t trojan_handle;
static dissector_handle_t tls_handle;

static int hf_trojan_password_hash;
static int hf_trojan_command;
static int hf_trojan_address_type;
static int hf_trojan_domain_length;
static int hf_trojan_ipv4;
static int hf_trojan_ipv6;
static int hf_trojan_domain;
static int hf_trojan_destination_port;
static int hf_trojan_direction;
static int hf_trojan_tunnel_data;
static int hf_trojan_inner_tls_length;

static int ett_trojan;
static int ett_trojan_request;
static int ett_trojan_tunnel;

static expert_field ei_trojan_malformed_inner = EI_INIT;
static expert_field ei_trojan_unsupported_payload = EI_INIT;
static expert_field ei_trojan_unsupported_udp = EI_INIT;

static wmem_map_t *trojan_calls;

static const value_string command_values[] = {
    {TROJAN_COMMAND_CONNECT, "CONNECT"},
    {TROJAN_COMMAND_UDP_ASSOCIATE, "UDP ASSOCIATE"},
    {0, NULL}};

static const value_string address_type_values[] = {
    {TROJAN_ATYPE_IPV4, "IPv4"},
    {TROJAN_ATYPE_DOMAIN, "Domain"},
    {TROJAN_ATYPE_IPV6, "IPv6"},
    {0, NULL}};

static const value_string direction_values[] = {
    {0, "client to server"}, {1, "server to client"}, {0, NULL}};

typedef enum {
  PARSE_VALID,
  PARSE_NEED_MORE,
  PARSE_INVALID
} parse_status_t;

typedef struct {
  parse_status_t status;
  unsigned needed;
  unsigned command_offset;
  unsigned address_type_offset;
  unsigned domain_length_offset;
  unsigned address_offset;
  unsigned address_length;
  unsigned port_offset;
  unsigned header_length;
  uint8_t command;
  uint8_t address_type;
} request_parse_t;

typedef struct trojan_cached_payload {
  struct trojan_cached_payload *next;
  bool is_tls;
  unsigned length;
  uint8_t bytes[];
} trojan_cached_payload;

typedef struct {
  bool processed;
  bool malformed_inner;
  bool unsupported_payload;
  trojan_cached_payload *first_payload;
  trojan_cached_payload *last_payload;
} trojan_call_state;

typedef struct {
  address client_address;
  uint32_t client_port;
  uint16_t destination_port;
  uint32_t request_header_frame;
  uint32_t request_header_seq;
  uint32_t inner_conversation_id;
  uint8_t command;
  GByteArray *inner_bytes[2];
  int8_t inner_is_tls[2];
} trojan_conversation_t;

static void trojan_init(void) {
  trojan_calls = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
}

static bool is_hex(uint8_t value) {
  return (value >= '0' && value <= '9') ||
         (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}

static request_parse_t parse_request(tvbuff_t *tvb) {
  request_parse_t parsed = {0};
  unsigned length = tvb_captured_length(tvb);
  unsigned offset;
  unsigned available_hash = MIN(length, TROJAN_HASH_LENGTH);

#define REQUIRE_BYTES(count)                                                   \
  do {                                                                         \
    if (length < (count)) {                                                     \
      parsed.status = PARSE_NEED_MORE;                                          \
      parsed.needed = (count);                                                  \
      return parsed;                                                            \
    }                                                                          \
  } while (0)

  for (unsigned i = 0; i < available_hash; i++) {
    if (!is_hex(tvb_get_uint8(tvb, i))) {
      parsed.status = PARSE_INVALID;
      return parsed;
    }
  }
  REQUIRE_BYTES(TROJAN_HASH_LENGTH);
  REQUIRE_BYTES(TROJAN_HASH_LENGTH + TROJAN_CRLF_LENGTH);
  if (tvb_get_uint8(tvb, TROJAN_HASH_LENGTH) != '\r' ||
      tvb_get_uint8(tvb, TROJAN_HASH_LENGTH + 1) != '\n') {
    parsed.status = PARSE_INVALID;
    return parsed;
  }

  parsed.command_offset = TROJAN_HASH_LENGTH + TROJAN_CRLF_LENGTH;
  parsed.address_type_offset = parsed.command_offset + 1;
  REQUIRE_BYTES(parsed.address_type_offset + 1);
  parsed.command = tvb_get_uint8(tvb, parsed.command_offset);
  if (parsed.command != TROJAN_COMMAND_CONNECT &&
      parsed.command != TROJAN_COMMAND_UDP_ASSOCIATE) {
    parsed.status = PARSE_INVALID;
    return parsed;
  }
  parsed.address_type = tvb_get_uint8(tvb, parsed.address_type_offset);
  offset = parsed.address_type_offset + 1;

  switch (parsed.address_type) {
  case TROJAN_ATYPE_IPV4:
    parsed.address_offset = offset;
    parsed.address_length = 4;
    REQUIRE_BYTES(offset + parsed.address_length);
    offset += parsed.address_length;
    break;
  case TROJAN_ATYPE_DOMAIN:
    parsed.domain_length_offset = offset;
    REQUIRE_BYTES(offset + 1);
    parsed.address_length = tvb_get_uint8(tvb, offset);
    if (parsed.address_length == 0) {
      parsed.status = PARSE_INVALID;
      return parsed;
    }
    parsed.address_offset = offset + 1;
    REQUIRE_BYTES(parsed.address_offset + parsed.address_length);
    offset = parsed.address_offset + parsed.address_length;
    break;
  case TROJAN_ATYPE_IPV6:
    parsed.address_offset = offset;
    parsed.address_length = 16;
    REQUIRE_BYTES(offset + parsed.address_length);
    offset += parsed.address_length;
    break;
  default:
    parsed.status = PARSE_INVALID;
    return parsed;
  }

  parsed.port_offset = offset;
  REQUIRE_BYTES(offset + 2 + TROJAN_CRLF_LENGTH);
  offset += 2;
  if (tvb_get_uint8(tvb, offset) != '\r' ||
      tvb_get_uint8(tvb, offset + 1) != '\n') {
    parsed.status = PARSE_INVALID;
    return parsed;
  }
  parsed.header_length = offset + TROJAN_CRLF_LENGTH;
  return parsed;
#undef REQUIRE_BYTES
}

static bool packet_from_client(packet_info *pinfo,
                               const trojan_conversation_t *state) {
  return pinfo->srcport == state->client_port &&
         addresses_equal(&pinfo->src, &state->client_address);
}

static trojan_conversation_t *
create_state(packet_info *pinfo, conversation_t *conversation,
             const request_parse_t *parsed, uint16_t destination_port,
             uint32_t tls_seq) {
  uintptr_t identity = (uintptr_t)conversation;
  trojan_conversation_t *state =
      wmem_new0(wmem_file_scope(), trojan_conversation_t);

  copy_address_wmem(wmem_file_scope(), &state->client_address, &pinfo->src);
  state->client_port = pinfo->srcport;
  state->destination_port = destination_port;
  state->request_header_frame = pinfo->num;
  state->request_header_seq = tls_seq;
  state->command = parsed->command;
  state->inner_bytes[0] = g_byte_array_new();
  state->inner_bytes[1] = g_byte_array_new();
  state->inner_is_tls[0] = -1;
  state->inner_is_tls[1] = -1;
  state->inner_conversation_id =
      (uint32_t)((identity >> 4) ^ (identity >> 32) ^ pinfo->num ^ tls_seq);
  if (state->inner_conversation_id == 0)
    state->inner_conversation_id = 1;
  conversation_add_proto_data(conversation, proto_trojan, state);
  return state;
}

static trojan_call_state *get_call_state(packet_info *pinfo,
                                         conversation_t *conversation,
                                         unsigned direction,
                                         uint32_t tls_seq) {
  char *key = wmem_strdup_printf(wmem_packet_scope(), "%p:%u:%u:%u",
                                 (void *)conversation, pinfo->num, direction,
                                 tls_seq);
  trojan_call_state *call_state =
      (trojan_call_state *)wmem_map_lookup(trojan_calls, key);

  if (call_state == NULL && !PINFO_FD_VISITED(pinfo)) {
    char *stored_key = wmem_strdup(wmem_file_scope(), key);
    call_state = wmem_new0(wmem_file_scope(), trojan_call_state);
    wmem_map_insert(trojan_calls, stored_key, call_state);
  }
  return call_state;
}

static trojan_cached_payload *cache_payload(trojan_call_state *call_state,
                                            bool is_tls,
                                            const uint8_t *bytes,
                                            unsigned length) {
  trojan_cached_payload *payload = (trojan_cached_payload *)wmem_alloc(
      wmem_file_scope(), sizeof(*payload) + length);

  payload->next = NULL;
  payload->is_tls = is_tls;
  payload->length = length;
  memcpy(payload->bytes, bytes, length);
  if (call_state->last_payload != NULL)
    call_state->last_payload->next = payload;
  else
    call_state->first_payload = payload;
  call_state->last_payload = payload;
  return payload;
}

static bool plausible_tls_record(const uint8_t *bytes, size_t length,
                                 unsigned *record_length) {
  unsigned payload_length;

  if (length < TROJAN_TLS_RECORD_HEADER_LENGTH)
    return false;
  if (bytes[0] < 20 || bytes[0] > 24 || bytes[1] != 3 || bytes[2] > 4)
    return false;
  payload_length = ((unsigned)bytes[3] << 8) | bytes[4];
  if (payload_length > TROJAN_TLS_RECORD_MAX_LENGTH)
    return false;
  *record_length = payload_length + TROJAN_TLS_RECORD_HEADER_LENGTH;
  return true;
}

static void call_cached_payload(tvbuff_t *parent, packet_info *pinfo,
                                proto_tree *tree,
                                const trojan_conversation_t *state,
                                unsigned direction,
                                const trojan_cached_payload *payload,
                                proto_tree *trojan_tree) {
  uint8_t *copy = (uint8_t *)g_memdup2(payload->bytes, payload->length);
  tvbuff_t *child =
      tvb_new_child_real_data(parent, copy, payload->length, payload->length);

  tvb_set_free_cb(child, g_free);
  if (!payload->is_tls) {
    add_new_data_source(pinfo, child, "Reassembled Trojan tunnel data");
    call_data_dissector(child, pinfo, proto_tree_get_root(tree));
    return;
  }

  conversation_element_t *saved_elements = pinfo->conv_elements;
  port_type saved_ptype = pinfo->ptype;
  uint32_t saved_srcport = pinfo->srcport;
  uint32_t saved_destport = pinfo->destport;
  uint16_t saved_can_desegment = pinfo->can_desegment;
  int saved_desegment_offset = pinfo->desegment_offset;
  uint32_t saved_desegment_len = pinfo->desegment_len;

  add_new_data_source(pinfo, child, "Reassembled Trojan inner TLS");
  proto_item *length_item = proto_tree_add_uint(
      trojan_tree, hf_trojan_inner_tls_length, parent, 0, 0, payload->length);
  proto_item_set_generated(length_item);
  conversation_set_elements_by_id(pinfo, CONVERSATION_NONE,
                                  state->inner_conversation_id);
  pinfo->ptype = PT_NONE;
  if (direction == 0)
    pinfo->destport = state->destination_port;
  else
    pinfo->srcport = state->destination_port;
  pinfo->desegment_offset = 0;
  pinfo->desegment_len = 0;
  call_dissector(tls_handle, child, pinfo, proto_tree_get_root(tree));
  pinfo->can_desegment = saved_can_desegment;
  pinfo->desegment_offset = saved_desegment_offset;
  pinfo->desegment_len = saved_desegment_len;
  pinfo->srcport = saved_srcport;
  pinfo->destport = saved_destport;
  pinfo->ptype = saved_ptype;
  pinfo->conv_elements = saved_elements;
}

static void emit_payload(tvbuff_t *parent, packet_info *pinfo,
                         proto_tree *tree,
                         const trojan_conversation_t *state,
                         unsigned direction, trojan_call_state *call_state,
                         bool is_tls, const uint8_t *bytes, unsigned length,
                         proto_tree *trojan_tree) {
  trojan_cached_payload *payload =
      cache_payload(call_state, is_tls, bytes, length);
  call_cached_payload(parent, pinfo, tree, state, direction, payload,
                      trojan_tree);
}

static void process_tunnel_bytes(tvbuff_t *parent, packet_info *pinfo,
                                 proto_tree *tree,
                                 trojan_conversation_t *state,
                                 unsigned direction, const uint8_t *bytes,
                                 unsigned length, bool end_of_stream,
                                 proto_tree *trojan_tree,
                                 trojan_call_state *call_state) {
  GByteArray *buffer = state->inner_bytes[direction];

  if (length == 0)
    return;
  if (state->command != TROJAN_COMMAND_CONNECT ||
      state->inner_is_tls[direction] == 0) {
    emit_payload(parent, pinfo, tree, state, direction, call_state, false,
                 bytes, length, trojan_tree);
    return;
  }

  g_byte_array_append(buffer, bytes, length);
  if (buffer->len > TROJAN_MAX_BUFFER) {
    emit_payload(parent, pinfo, tree, state, direction, call_state, false,
                 buffer->data, buffer->len, trojan_tree);
    call_state->malformed_inner = true;
    proto_tree_add_expert(trojan_tree, pinfo, &ei_trojan_malformed_inner,
                          parent, 0, tvb_captured_length(parent));
    g_byte_array_set_size(buffer, 0);
    state->inner_is_tls[direction] = 0;
    return;
  }

  while (buffer->len >= TROJAN_TLS_RECORD_HEADER_LENGTH) {
    unsigned record_length;
    if (!plausible_tls_record(buffer->data, buffer->len, &record_length)) {
      emit_payload(parent, pinfo, tree, state, direction, call_state, false,
                   buffer->data, buffer->len, trojan_tree);
      call_state->unsupported_payload = true;
      proto_tree_add_expert(trojan_tree, pinfo,
                            &ei_trojan_unsupported_payload, parent, 0,
                            tvb_captured_length(parent));
      g_byte_array_set_size(buffer, 0);
      state->inner_is_tls[direction] = 0;
      return;
    }
    state->inner_is_tls[direction] = 1;
    if (buffer->len < record_length)
      return;
    emit_payload(parent, pinfo, tree, state, direction, call_state, true,
                 buffer->data, record_length, trojan_tree);
    g_byte_array_remove_range(buffer, 0, record_length);
  }

  if (end_of_stream && buffer->len > 0) {
    emit_payload(parent, pinfo, tree, state, direction, call_state, false,
                 buffer->data, buffer->len, trojan_tree);
    call_state->unsupported_payload = true;
    proto_tree_add_expert(trojan_tree, pinfo, &ei_trojan_unsupported_payload,
                          parent, 0, tvb_captured_length(parent));
    g_byte_array_set_size(buffer, 0);
    state->inner_is_tls[direction] = 0;
  }
}

static void replay_call(tvbuff_t *parent, packet_info *pinfo, proto_tree *tree,
                        const trojan_conversation_t *state,
                        unsigned direction,
                        const trojan_call_state *call_state,
                        proto_tree *trojan_tree) {
  for (const trojan_cached_payload *payload = call_state->first_payload;
       payload != NULL; payload = payload->next) {
    call_cached_payload(parent, pinfo, tree, state, direction, payload,
                        trojan_tree);
  }
  if (call_state->malformed_inner)
    proto_tree_add_expert(trojan_tree, pinfo, &ei_trojan_malformed_inner,
                          parent, 0, tvb_captured_length(parent));
  if (call_state->unsupported_payload)
    proto_tree_add_expert(trojan_tree, pinfo,
                          &ei_trojan_unsupported_payload, parent, 0,
                          tvb_captured_length(parent));
}

static proto_tree *add_request_tree(tvbuff_t *tvb, proto_tree *tree,
                                    const request_parse_t *parsed) {
  proto_item *item = proto_tree_add_item(tree, proto_trojan, tvb, 0,
                                         parsed->header_length, ENC_NA);
  proto_tree *request_tree = proto_item_add_subtree(item, ett_trojan_request);

  proto_tree_add_item(request_tree, hf_trojan_password_hash, tvb, 0,
                      TROJAN_HASH_LENGTH, ENC_ASCII | ENC_NA);
  proto_tree_add_item(request_tree, hf_trojan_command, tvb,
                      parsed->command_offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(request_tree, hf_trojan_address_type, tvb,
                      parsed->address_type_offset, 1, ENC_BIG_ENDIAN);
  if (parsed->address_type == TROJAN_ATYPE_IPV4) {
    proto_tree_add_item(request_tree, hf_trojan_ipv4, tvb,
                        parsed->address_offset, 4, ENC_BIG_ENDIAN);
  } else if (parsed->address_type == TROJAN_ATYPE_IPV6) {
    proto_tree_add_item(request_tree, hf_trojan_ipv6, tvb,
                        parsed->address_offset, 16, ENC_NA);
  } else {
    proto_tree_add_item(request_tree, hf_trojan_domain_length, tvb,
                        parsed->domain_length_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(request_tree, hf_trojan_domain, tvb,
                        parsed->address_offset, parsed->address_length,
                        ENC_UTF_8 | ENC_NA);
  }
  proto_tree_add_item(request_tree, hf_trojan_destination_port, tvb,
                      parsed->port_offset, 2, ENC_BIG_ENDIAN);
  return request_tree;
}

static proto_tree *add_tunnel_tree(tvbuff_t *tvb, proto_tree *tree,
                                   unsigned offset, unsigned direction) {
  unsigned length = tvb_captured_length(tvb) - offset;
  proto_item *item =
      proto_tree_add_item(tree, proto_trojan, tvb, offset, length, ENC_NA);
  proto_tree *tunnel_tree = proto_item_add_subtree(item, ett_trojan_tunnel);
  proto_item *direction_item = proto_tree_add_uint(
      tunnel_tree, hf_trojan_direction, tvb, offset, 0, direction);

  proto_item_set_generated(direction_item);
  if (length > 0)
    proto_tree_add_item(tunnel_tree, hf_trojan_tunnel_data, tvb, offset,
                        length, ENC_NA);
  return tunnel_tree;
}

static int dissect_trojan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          void *data) {
  conversation_t *conversation = find_or_create_conversation(pinfo);
  trojan_conversation_t *state = (trojan_conversation_t *)
      conversation_get_proto_data(conversation, proto_trojan);
  struct tlsinfo *tlsinfo = (struct tlsinfo *)data;
  uint32_t tls_seq = tlsinfo != NULL ? tlsinfo->seq : 0;
  unsigned offset = 0;
  unsigned direction;
  request_parse_t parsed;
  proto_tree *tunnel_tree;
  trojan_call_state *call_state;
  bool replay;

  if (state == NULL) {
    parsed = parse_request(tvb);
    if (parsed.status != PARSE_VALID)
      return 0;
    state = create_state(pinfo, conversation, &parsed,
                         tvb_get_ntohs(tvb, parsed.port_offset), tls_seq);
  }
  direction = packet_from_client(pinfo, state) ? 0 : 1;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trojan");
  col_set_str(pinfo->cinfo, COL_INFO,
              direction == 0 ? "Trojan tunneled request"
                             : "Trojan tunneled response");

  if (direction == 0 && state->request_header_frame == pinfo->num &&
      state->request_header_seq == tls_seq) {
    parsed = parse_request(tvb);
    if (parsed.status != PARSE_VALID)
      return tvb_captured_length(tvb);
    add_request_tree(tvb, tree, &parsed);
    offset = parsed.header_length;
    if (state->command == TROJAN_COMMAND_UDP_ASSOCIATE) {
      proto_tree_add_expert_format(tree, pinfo, &ei_trojan_unsupported_udp,
                                   tvb, parsed.command_offset, 1,
                                   "Trojan UDP ASSOCIATE payload framing is "
                                   "not implemented");
    }
  }

  tunnel_tree = add_tunnel_tree(tvb, tree, offset, direction);
  call_state = get_call_state(pinfo, conversation, direction, tls_seq);
  if (call_state == NULL)
    return tvb_captured_length(tvb);
  replay = PINFO_FD_VISITED(pinfo) || call_state->processed;
  if (replay) {
    replay_call(tvb, pinfo, tree, state, direction, call_state, tunnel_tree);
    return tvb_captured_length(tvb);
  }

  if (offset < tvb_captured_length(tvb)) {
    unsigned length = tvb_captured_length(tvb) - offset;
    uint8_t *bytes = (uint8_t *)wmem_alloc(pinfo->pool, length);
    tvb_memcpy(tvb, bytes, offset, length);
    process_tunnel_bytes(tvb, pinfo, tree, state, direction, bytes, length,
                         tlsinfo != NULL && tlsinfo->end_of_stream,
                         tunnel_tree, call_state);
  }
  call_state->processed = true;
  return tvb_captured_length(tvb);
}

static bool dissect_trojan_heur_tls(tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, void *data) {
  request_parse_t parsed = parse_request(tvb);
  struct tlsinfo *tlsinfo = (struct tlsinfo *)data;

  if (parsed.status == PARSE_NEED_MORE && pinfo->can_desegment) {
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return false;
  }
  if (parsed.status != PARSE_VALID || tlsinfo == NULL ||
      tlsinfo->app_handle == NULL)
    return false;

  *(tlsinfo->app_handle) = trojan_handle;
  dissect_trojan(tvb, pinfo, tree, data);
  return true;
}

void proto_register_trojan(void) {
  static hf_register_info hf[] = {
      {&hf_trojan_password_hash,
       {"Password Hash", "trojan.password_hash", FT_STRING, BASE_NONE, NULL,
        0, NULL, HFILL}},
      {&hf_trojan_command,
       {"Command", "trojan.command", FT_UINT8, BASE_DEC, VALS(command_values),
        0, NULL, HFILL}},
      {&hf_trojan_address_type,
       {"Address Type", "trojan.address_type", FT_UINT8, BASE_DEC,
        VALS(address_type_values), 0, NULL, HFILL}},
      {&hf_trojan_domain_length,
       {"Domain Length", "trojan.destination.domain_length", FT_UINT8,
        BASE_DEC, NULL, 0, NULL, HFILL}},
      {&hf_trojan_ipv4,
       {"IPv4 Destination", "trojan.destination.ipv4", FT_IPv4, BASE_NONE,
        NULL, 0, NULL, HFILL}},
      {&hf_trojan_ipv6,
       {"IPv6 Destination", "trojan.destination.ipv6", FT_IPv6, BASE_NONE,
        NULL, 0, NULL, HFILL}},
      {&hf_trojan_domain,
       {"Domain Destination", "trojan.destination.domain", FT_STRING,
        BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_trojan_destination_port,
       {"Destination Port", "trojan.destination.port", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_trojan_direction,
       {"Direction", "trojan.direction", FT_UINT8, BASE_DEC,
        VALS(direction_values), 0, NULL, HFILL}},
      {&hf_trojan_tunnel_data,
       {"Tunnel Data", "trojan.tunnel_data", FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_trojan_inner_tls_length,
       {"Reassembled Inner TLS Record Length", "trojan.inner_tls.length",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}}};
  static int *ett[] = {&ett_trojan, &ett_trojan_request,
                       &ett_trojan_tunnel};
  static ei_register_info ei[] = {
      {&ei_trojan_malformed_inner,
       {"trojan.inner_tls.malformed", PI_MALFORMED, PI_ERROR,
        "Malformed or excessive inner TLS buffering", EXPFILL}},
      {&ei_trojan_unsupported_payload,
       {"trojan.unsupported_payload", PI_UNDECODED, PI_NOTE,
        "Trojan CONNECT payload is not TLS", EXPFILL}},
      {&ei_trojan_unsupported_udp,
       {"trojan.unsupported_udp", PI_UNDECODED, PI_WARN,
        "Trojan UDP ASSOCIATE payload framing is not implemented", EXPFILL}}};
  expert_module_t *expert_trojan;

  proto_trojan =
      proto_register_protocol("Trojan Protocol", "Trojan", "trojan");
  proto_register_field_array(proto_trojan, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_trojan = expert_register_protocol(proto_trojan);
  expert_register_field_array(expert_trojan, ei, array_length(ei));
  register_init_routine(trojan_init);
}

void proto_reg_handoff_trojan(void) {
  trojan_handle = register_dissector("trojan", dissect_trojan, proto_trojan);
  tls_handle = find_dissector_add_dependency("tls", proto_trojan);
  heur_dissector_add("tls", dissect_trojan_heur_tls, "Trojan over TLS",
                     "trojan_tls", proto_trojan, HEURISTIC_ENABLE);
}
