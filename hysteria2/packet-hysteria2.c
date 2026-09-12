/* packet-hysteria2.c
 * Hysteria 2 over QUIC, including Salamander obfuscation.
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
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>
#include <epan/wmem_scopes.h>
#include <wsutil/wsgcrypt.h>

#define HY2_TCP_REQUEST_ID 0x401
#define HY2_SALAMANDER_SALT_LEN 8
#define HY2_SALAMANDER_HASH_LEN 32
#define HY2_MAX_ADDRESS_LEN 512
#define HY2_MAX_PADDING_LEN (1U << 20)

void proto_register_hysteria2(void);
void proto_reg_handoff_hysteria2(void);

static int proto_hysteria2;
static dissector_handle_t hysteria2_handle;
static dissector_handle_t hy2_tcp_fixture_handle;
static dissector_handle_t hy2_udp_fixture_handle;
static dissector_handle_t quic_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t data_handle;
static dissector_table_t udp_port_table;

static int hf_hy2_salamander_salt;
static int hf_hy2_tcp_request_id;
static int hf_hy2_address_length;
static int hf_hy2_address;
static int hf_hy2_destination_port;
static int hf_hy2_padding_length;
static int hf_hy2_padding;
static int hf_hy2_response_status;
static int hf_hy2_response_message_length;
static int hf_hy2_response_message;
static int hf_hy2_udp_session_id;
static int hf_hy2_udp_packet_id;
static int hf_hy2_udp_fragment_id;
static int hf_hy2_udp_fragment_count;
static int hf_hy2_udp_payload;
static int hf_hy2_fragments;
static int hf_hy2_fragment;
static int hf_hy2_fragment_overlap;
static int hf_hy2_fragment_overlap_conflict;
static int hf_hy2_fragment_multiple_tails;
static int hf_hy2_fragment_too_long_fragment;
static int hf_hy2_fragment_error;
static int hf_hy2_fragment_count;
static int hf_hy2_reassembled_in;
static int hf_hy2_reassembled_length;
static int hf_hy2_reassembled_data;

static int ett_hy2;
static int ett_hy2_salamander;
static int ett_hy2_tcp_request;
static int ett_hy2_tcp_response;
static int ett_hy2_udp;
static int ett_hy2_fragments;
static int ett_hy2_fragment;

static expert_field ei_hy2_malformed = EI_INIT;
static expert_field ei_hy2_truncated = EI_INIT;
static expert_field ei_hy2_bad_address = EI_INIT;
static expert_field ei_hy2_bad_status = EI_INIT;
static expert_field ei_hy2_bad_fragment = EI_INIT;
static expert_field ei_hy2_key_file = EI_INIT;

static const char *pref_salamander_key_file;
static wmem_map_t *hy2_streams;
static wmem_map_t *hy2_connections;
static wmem_map_t *hy2_obfs_endpoints;
static reassembly_table hy2_udp_reassembly_table;

static const value_string response_status_values[] = {
    {0, "OK"}, {1, "Error"}, {0, NULL}};

static const fragment_items hy2_udp_frag_items = {
    &ett_hy2_fragment,
    &ett_hy2_fragments,
    &hf_hy2_fragments,
    &hf_hy2_fragment,
    &hf_hy2_fragment_overlap,
    &hf_hy2_fragment_overlap_conflict,
    &hf_hy2_fragment_multiple_tails,
    &hf_hy2_fragment_too_long_fragment,
    &hf_hy2_fragment_error,
    &hf_hy2_fragment_count,
    &hf_hy2_reassembled_in,
    &hf_hy2_reassembled_length,
    &hf_hy2_reassembled_data,
    "Hysteria 2 UDP fragments"};

typedef enum {
  HY2_PARSE_OK,
  HY2_PARSE_NEED_MORE,
  HY2_PARSE_NOT_HY2,
  HY2_PARSE_MALFORMED
} hy2_parse_status;

typedef struct {
  hy2_parse_status status;
  uint64_t value;
  unsigned length;
} hy2_varint;

typedef struct {
  hy2_parse_status status;
  unsigned needed;
  unsigned address_offset;
  unsigned address_length;
  unsigned padding_length_offset;
  unsigned padding_offset;
  unsigned padding_length;
  unsigned header_length;
  uint16_t destination_port;
} hy2_tcp_request_parse;

typedef struct {
  hy2_parse_status status;
  unsigned needed;
  unsigned message_offset;
  unsigned message_length;
  unsigned padding_length_offset;
  unsigned padding_offset;
  unsigned padding_length;
  unsigned header_length;
  uint8_t response_status;
} hy2_tcp_response_parse;

typedef struct {
  hy2_parse_status status;
  unsigned address_length_offset;
  unsigned address_offset;
  unsigned address_length;
  unsigned payload_offset;
  uint32_t session_id;
  uint16_t packet_id;
  uint8_t fragment_id;
  uint8_t fragment_count;
  uint16_t destination_port;
} hy2_udp_parse;

typedef struct {
  struct quic_info_data *quic_info;
  uint64_t stream_id;
  uint32_t inner_conversation_id;
  unsigned request_header_length;
  unsigned response_header_length;
} hy2_stream_state;

static void hy2_init(void) {
  hy2_streams = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
  hy2_connections =
      wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
  hy2_obfs_endpoints = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
}

static hy2_varint hy2_get_varint(tvbuff_t *tvb, unsigned offset) {
  hy2_varint result = {HY2_PARSE_OK, 0, 0};
  unsigned available = tvb_captured_length_remaining(tvb, offset);
  uint8_t first;

  if (available < 1) {
    result.status = HY2_PARSE_NEED_MORE;
    return result;
  }
  first = tvb_get_uint8(tvb, offset);
  result.length = 1U << (first >> 6);
  if (available < result.length) {
    result.status = HY2_PARSE_NEED_MORE;
    return result;
  }
  result.value = first & 0x3f;
  for (unsigned i = 1; i < result.length; i++)
    result.value = (result.value << 8) | tvb_get_uint8(tvb, offset + i);
  return result;
}

static bool hy2_parse_target(tvbuff_t *tvb, unsigned offset, unsigned length,
                             uint16_t *port) {
  int colon = -1;
  uint32_t port_value = 0;
  unsigned port_digits = 0;

  if (length < 3 || length > HY2_MAX_ADDRESS_LEN)
    return false;
  for (unsigned i = 0; i < length; i++) {
    uint8_t c = tvb_get_uint8(tvb, offset + i);
    if (c < 0x21 || c > 0x7e)
      return false;
    if (c == ':')
      colon = (int)i;
  }
  if (colon <= 0 || (unsigned)colon + 1 >= length)
    return false;
  if (tvb_get_uint8(tvb, offset) == '[' &&
      ((unsigned)colon < 2 || tvb_get_uint8(tvb, offset + colon - 1) != ']'))
    return false;
  for (unsigned i = (unsigned)colon + 1; i < length; i++) {
    uint8_t c = tvb_get_uint8(tvb, offset + i);
    if (c < '0' || c > '9' || ++port_digits > 5)
      return false;
    port_value = port_value * 10 + (c - '0');
  }
  if (port_value == 0 || port_value > 65535)
    return false;
  *port = (uint16_t)port_value;
  return true;
}

static hy2_tcp_request_parse hy2_parse_tcp_request(tvbuff_t *tvb) {
  hy2_tcp_request_parse result = {HY2_PARSE_OK, 0, 0, 0, 0, 0, 0, 0, 0};
  hy2_varint field;
  unsigned offset = 0;
  unsigned length = tvb_captured_length(tvb);

  field = hy2_get_varint(tvb, offset);
  if (field.status != HY2_PARSE_OK) {
    result.status = field.status;
    result.needed = 2;
    return result;
  }
  if (field.value != HY2_TCP_REQUEST_ID) {
    result.status = HY2_PARSE_NOT_HY2;
    return result;
  }
  offset += field.length;
  field = hy2_get_varint(tvb, offset);
  if (field.status != HY2_PARSE_OK) {
    result.status = field.status;
    result.needed = offset + 1;
    return result;
  }
  offset += field.length;
  if (field.value == 0 || field.value > HY2_MAX_ADDRESS_LEN) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  result.address_offset = offset;
  result.address_length = (unsigned)field.value;
  if (length < offset + result.address_length) {
    result.status = HY2_PARSE_NEED_MORE;
    result.needed = offset + result.address_length;
    return result;
  }
  if (!hy2_parse_target(tvb, offset, result.address_length,
                        &result.destination_port)) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  offset += result.address_length;
  result.padding_length_offset = offset;
  field = hy2_get_varint(tvb, offset);
  if (field.status != HY2_PARSE_OK) {
    result.status = field.status;
    result.needed = offset + 1;
    return result;
  }
  if (field.value > HY2_MAX_PADDING_LEN) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  offset += field.length;
  result.padding_offset = offset;
  result.padding_length = (unsigned)field.value;
  if (length < offset + result.padding_length) {
    result.status = HY2_PARSE_NEED_MORE;
    result.needed = offset + result.padding_length;
    return result;
  }
  result.header_length = offset + result.padding_length;
  return result;
}

static hy2_tcp_response_parse hy2_parse_tcp_response(tvbuff_t *tvb) {
  hy2_tcp_response_parse result = {HY2_PARSE_OK, 0, 0, 0, 0, 0, 0, 0, 0};
  hy2_varint field;
  unsigned offset = 0;
  unsigned length = tvb_captured_length(tvb);

  if (length < 1) {
    result.status = HY2_PARSE_NEED_MORE;
    result.needed = 1;
    return result;
  }
  result.response_status = tvb_get_uint8(tvb, offset++);
  if (result.response_status > 1) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  field = hy2_get_varint(tvb, offset);
  if (field.status != HY2_PARSE_OK) {
    result.status = field.status;
    result.needed = offset + 1;
    return result;
  }
  offset += field.length;
  if (field.value > HY2_MAX_ADDRESS_LEN) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  result.message_offset = offset;
  result.message_length = (unsigned)field.value;
  if (length < offset + result.message_length) {
    result.status = HY2_PARSE_NEED_MORE;
    result.needed = offset + result.message_length;
    return result;
  }
  offset += result.message_length;
  result.padding_length_offset = offset;
  field = hy2_get_varint(tvb, offset);
  if (field.status != HY2_PARSE_OK) {
    result.status = field.status;
    result.needed = offset + 1;
    return result;
  }
  if (field.value > HY2_MAX_PADDING_LEN) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  offset += field.length;
  result.padding_offset = offset;
  result.padding_length = (unsigned)field.value;
  if (length < offset + result.padding_length) {
    result.status = HY2_PARSE_NEED_MORE;
    result.needed = offset + result.padding_length;
    return result;
  }
  result.header_length = offset + result.padding_length;
  return result;
}

static hy2_udp_parse hy2_parse_udp(tvbuff_t *tvb) {
  hy2_udp_parse result = {HY2_PARSE_OK, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  hy2_varint field;
  unsigned offset = 8;
  unsigned length = tvb_captured_length(tvb);

  if (length < 9) {
    result.status = HY2_PARSE_NEED_MORE;
    return result;
  }
  result.session_id = tvb_get_ntohl(tvb, 0);
  result.packet_id = tvb_get_ntohs(tvb, 4);
  result.fragment_id = tvb_get_uint8(tvb, 6);
  result.fragment_count = tvb_get_uint8(tvb, 7);
  if (result.fragment_count == 0 ||
      result.fragment_id >= result.fragment_count) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  result.address_length_offset = offset;
  field = hy2_get_varint(tvb, offset);
  if (field.status != HY2_PARSE_OK) {
    result.status = field.status;
    return result;
  }
  offset += field.length;
  if (field.value == 0 || field.value > HY2_MAX_ADDRESS_LEN ||
      length < offset + field.value) {
    result.status = field.value > HY2_MAX_ADDRESS_LEN ? HY2_PARSE_MALFORMED
                                                      : HY2_PARSE_NEED_MORE;
    return result;
  }
  result.address_offset = offset;
  result.address_length = (unsigned)field.value;
  if (!hy2_parse_target(tvb, offset, result.address_length,
                        &result.destination_port)) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  result.payload_offset = offset + result.address_length;
  if (result.payload_offset >= length) {
    result.status = HY2_PARSE_MALFORMED;
    return result;
  }
  return result;
}

static char *hy2_stream_key(wmem_allocator_t *scope,
                            struct quic_info_data *quic_info,
                            uint64_t stream_id) {
  return wmem_strdup_printf(scope, "%p:%" PRIu64, (void *)quic_info, stream_id);
}

static char *hy2_endpoint_key(wmem_allocator_t *scope, packet_info *pinfo) {
  char *src = address_to_str(scope, &pinfo->src);
  char *dst = address_to_str(scope, &pinfo->dst);
  return wmem_strdup_printf(scope, "%s:%u>%s:%u", src, pinfo->srcport, dst,
                            pinfo->destport);
}

static void hy2_mark_obfs_endpoint(packet_info *pinfo) {
  char *key = hy2_endpoint_key(wmem_file_scope(), pinfo);
  wmem_map_insert(hy2_obfs_endpoints, key, GINT_TO_POINTER(1));
}

static bool hy2_is_obfs_endpoint(packet_info *pinfo) {
  char *key = hy2_endpoint_key(wmem_packet_scope(), pinfo);
  return wmem_map_lookup(hy2_obfs_endpoints, key) != NULL;
}

static bool hy2_read_salamander_key(char **key, gsize *key_length) {
  GError *error = NULL;

  *key = NULL;
  *key_length = 0;
  if (pref_salamander_key_file == NULL || pref_salamander_key_file[0] == '\0')
    return false;
  if (!g_file_get_contents(pref_salamander_key_file, key, key_length, &error)) {
    g_clear_error(&error);
    return false;
  }
  while (*key_length > 0 &&
         ((*key)[*key_length - 1] == '\n' || (*key)[*key_length - 1] == '\r'))
    (*key_length)--;
  if (*key_length == 0) {
    g_free(*key);
    *key = NULL;
    return false;
  }
  return true;
}

static bool hy2_plausible_quic_initial(const uint8_t *data, unsigned length) {
  uint32_t version;
  unsigned dcid_length;
  unsigned scid_offset;

  if (length < 7 || (data[0] & 0xc0) != 0xc0)
    return false;
  version = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
            ((uint32_t)data[3] << 8) | data[4];
  if (version != 0x00000001 && version != 0x6b3343cf)
    return false;
  dcid_length = data[5];
  if (dcid_length > QUIC_MAX_CID_LENGTH || length < 7 + dcid_length)
    return false;
  scid_offset = 6 + dcid_length;
  return data[scid_offset] <= QUIC_MAX_CID_LENGTH &&
         length >= scid_offset + 1 + data[scid_offset];
}

static int dissect_hy2_salamander(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, void *data _U_) {
  char *key;
  gsize key_length;
  unsigned length = tvb_captured_length(tvb);
  unsigned clear_length;
  uint8_t salt[HY2_SALAMANDER_SALT_LEN];
  uint8_t digest[HY2_SALAMANDER_HASH_LEN];
  uint8_t *hash_input;
  uint8_t *clear;
  tvbuff_t *clear_tvb;
  proto_item *item;
  proto_tree *hy2_tree;

  if (length <= HY2_SALAMANDER_SALT_LEN ||
      !hy2_read_salamander_key(&key, &key_length))
    return 0;
  tvb_memcpy(tvb, salt, 0, sizeof(salt));
  hash_input = g_malloc(key_length + sizeof(salt));
  memcpy(hash_input, key, key_length);
  memcpy(hash_input + key_length, salt, sizeof(salt));
  gcry_md_hash_buffer(GCRY_MD_BLAKE2B_256, digest, hash_input,
                      key_length + sizeof(salt));
  g_free(hash_input);
  g_free(key);

  clear_length = length - HY2_SALAMANDER_SALT_LEN;
  clear = g_malloc(clear_length);
  for (unsigned i = 0; i < clear_length; i++)
    clear[i] = tvb_get_uint8(tvb, HY2_SALAMANDER_SALT_LEN + i) ^
               digest[i % HY2_SALAMANDER_HASH_LEN];
  clear_tvb = tvb_new_child_real_data(tvb, clear, clear_length, clear_length);
  tvb_set_free_cb(clear_tvb, g_free);
  add_new_data_source(pinfo, clear_tvb, "Salamander deobfuscated QUIC");

  item = proto_tree_add_item(tree, proto_hysteria2, tvb, 0,
                             HY2_SALAMANDER_SALT_LEN, ENC_NA);
  hy2_tree = proto_item_add_subtree(item, ett_hy2_salamander);
  proto_item_append_text(item, ", Salamander");
  proto_tree_add_item(hy2_tree, hf_hy2_salamander_salt, tvb, 0,
                      HY2_SALAMANDER_SALT_LEN, ENC_NA);
  hy2_mark_obfs_endpoint(pinfo);
  call_dissector(quic_handle, clear_tvb, pinfo, tree);
  return length;
}

static bool dissect_hy2_salamander_heur(tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, void *data _U_) {
  char *key;
  gsize key_length;
  unsigned length = tvb_captured_length(tvb);
  uint8_t salt[HY2_SALAMANDER_SALT_LEN];
  uint8_t digest[HY2_SALAMANDER_HASH_LEN];
  uint8_t *hash_input;
  uint8_t *clear;
  bool plausible;

  if (length <= HY2_SALAMANDER_SALT_LEN ||
      !hy2_read_salamander_key(&key, &key_length))
    return false;
  tvb_memcpy(tvb, salt, 0, sizeof(salt));
  hash_input = g_malloc(key_length + sizeof(salt));
  memcpy(hash_input, key, key_length);
  memcpy(hash_input + key_length, salt, sizeof(salt));
  gcry_md_hash_buffer(GCRY_MD_BLAKE2B_256, digest, hash_input,
                      key_length + sizeof(salt));
  g_free(hash_input);
  g_free(key);
  clear = g_malloc(length - HY2_SALAMANDER_SALT_LEN);
  for (unsigned i = 0; i < length - HY2_SALAMANDER_SALT_LEN; i++)
    clear[i] = tvb_get_uint8(tvb, HY2_SALAMANDER_SALT_LEN + i) ^
               digest[i % HY2_SALAMANDER_HASH_LEN];
  plausible =
      hy2_plausible_quic_initial(clear, length - HY2_SALAMANDER_SALT_LEN);
  g_free(clear);
  if (!plausible)
    return false;
  conversation_set_dissector(find_or_create_conversation(pinfo),
                             hysteria2_handle);
  dissect_hy2_salamander(tvb, pinfo, tree, NULL);
  return true;
}

static void hy2_request_tree(tvbuff_t *tvb, proto_tree *tree,
                             const hy2_tcp_request_parse *parsed) {
  proto_item *item = proto_tree_add_item(tree, proto_hysteria2, tvb, 0,
                                         parsed->header_length, ENC_NA);
  proto_tree *hy2_tree = proto_item_add_subtree(item, ett_hy2_tcp_request);
  unsigned marker_length = hy2_get_varint(tvb, 0).length;
  hy2_varint address_length = hy2_get_varint(tvb, marker_length);
  hy2_varint padding_length =
      hy2_get_varint(tvb, parsed->padding_length_offset);

  proto_item_append_text(item, ", TCP request");
  proto_tree_add_uint64(hy2_tree, hf_hy2_tcp_request_id, tvb, 0, marker_length,
                        HY2_TCP_REQUEST_ID);
  proto_tree_add_uint64(hy2_tree, hf_hy2_address_length, tvb, marker_length,
                        address_length.length, parsed->address_length);
  proto_tree_add_item(hy2_tree, hf_hy2_address, tvb, parsed->address_offset,
                      parsed->address_length, ENC_ASCII | ENC_NA);
  proto_tree_add_uint(hy2_tree, hf_hy2_destination_port, tvb, 0, 0,
                      parsed->destination_port);
  proto_tree_add_uint64(hy2_tree, hf_hy2_padding_length, tvb,
                        parsed->padding_length_offset, padding_length.length,
                        parsed->padding_length);
  if (parsed->padding_length)
    proto_tree_add_item(hy2_tree, hf_hy2_padding, tvb, parsed->padding_offset,
                        parsed->padding_length, ENC_NA);
}

static void hy2_response_tree(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree,
                              const hy2_tcp_response_parse *parsed) {
  proto_item *item = proto_tree_add_item(tree, proto_hysteria2, tvb, 0,
                                         parsed->header_length, ENC_NA);
  proto_tree *hy2_tree = proto_item_add_subtree(item, ett_hy2_tcp_response);
  hy2_varint message_length = hy2_get_varint(tvb, 1);
  hy2_varint padding_length =
      hy2_get_varint(tvb, parsed->padding_length_offset);

  proto_item_append_text(item, ", TCP response");
  proto_tree_add_item(hy2_tree, hf_hy2_response_status, tvb, 0, 1,
                      ENC_BIG_ENDIAN);
  if (parsed->response_status > 1)
    proto_tree_add_expert(hy2_tree, pinfo, &ei_hy2_bad_status, tvb, 0, 1);
  proto_tree_add_uint64(hy2_tree, hf_hy2_response_message_length, tvb, 1,
                        message_length.length, parsed->message_length);
  if (parsed->message_length)
    proto_tree_add_item(hy2_tree, hf_hy2_response_message, tvb,
                        parsed->message_offset, parsed->message_length,
                        ENC_UTF_8 | ENC_NA);
  proto_tree_add_uint64(hy2_tree, hf_hy2_padding_length, tvb,
                        parsed->padding_length_offset, padding_length.length,
                        parsed->padding_length);
  if (parsed->padding_length)
    proto_tree_add_item(hy2_tree, hf_hy2_padding, tvb, parsed->padding_offset,
                        parsed->padding_length, ENC_NA);
}

static void hy2_call_inner_tls(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, unsigned offset,
                               const hy2_stream_state *state) {
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

static bool dissect_hy2_quic_stream(tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, void *data) {
  quic_stream_info *stream_info = (quic_stream_info *)data;
  char *lookup_key;
  hy2_stream_state *state;
  unsigned payload_offset = 0;

  if (stream_info == NULL ||
      QUIC_STREAM_TYPE(stream_info->stream_id) != QUIC_STREAM_CLIENT_BIDI)
    return false;
  lookup_key = hy2_stream_key(wmem_packet_scope(), stream_info->quic_info,
                              stream_info->stream_id);
  state = (hy2_stream_state *)wmem_map_lookup(hy2_streams, lookup_key);
  if (state == NULL) {
    hy2_tcp_request_parse parsed;
    char *stored_key;

    if (stream_info->from_server || stream_info->offset != 0)
      return false;
    parsed = hy2_parse_tcp_request(tvb);
    if (parsed.status == HY2_PARSE_NEED_MORE &&
        (tvb_captured_length(tvb) > 0 && tvb_get_uint8(tvb, 0) == 0x44) &&
        hy2_is_obfs_endpoint(pinfo) && pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return true;
    }
    if (parsed.status != HY2_PARSE_OK)
      return false;
    state = wmem_new0(wmem_file_scope(), hy2_stream_state);
    state->quic_info = stream_info->quic_info;
    state->stream_id = stream_info->stream_id;
    state->request_header_length = parsed.header_length;
    state->inner_conversation_id =
        (uint32_t)(((uintptr_t)stream_info->quic_info >> 4) ^
                   stream_info->stream_id ^ (stream_info->stream_id >> 32));
    if (state->inner_conversation_id == 0)
      state->inner_conversation_id = 1;
    stored_key = hy2_stream_key(wmem_file_scope(), stream_info->quic_info,
                                stream_info->stream_id);
    wmem_map_insert(hy2_streams, stored_key, state);
    wmem_map_insert(hy2_connections, stream_info->quic_info,
                    GINT_TO_POINTER(1));
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYSTERIA2");
    col_set_str(pinfo->cinfo, COL_INFO, "Hysteria 2 TCP request");
    hy2_request_tree(tvb, tree, &parsed);
    payload_offset = parsed.header_length;
  } else if (stream_info->from_server && state->response_header_length == 0 &&
             stream_info->offset == 0) {
    hy2_tcp_response_parse parsed = hy2_parse_tcp_response(tvb);
    if (parsed.status == HY2_PARSE_NEED_MORE && pinfo->can_desegment) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return true;
    }
    if (parsed.status != HY2_PARSE_OK) {
      proto_tree_add_expert(tree, pinfo, &ei_hy2_malformed, tvb, 0,
                            tvb_captured_length(tvb));
      return true;
    }
    state->response_header_length = parsed.header_length;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYSTERIA2");
    col_set_str(pinfo->cinfo, COL_INFO, "Hysteria 2 TCP response");
    hy2_response_tree(tvb, pinfo, tree, &parsed);
    payload_offset = parsed.header_length;
  } else {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYSTERIA2");
    col_set_str(pinfo->cinfo, COL_INFO, "Hysteria 2 tunneled TCP data");
    proto_tree_add_item(tree, proto_hysteria2, tvb, 0, 0, ENC_NA);
  }

  hy2_call_inner_tls(tvb, pinfo, tree, payload_offset, state);
  return true;
}

static void hy2_call_udp_payload(tvbuff_t *payload, packet_info *pinfo,
                                 proto_tree *tree, const hy2_udp_parse *parsed,
                                 bool from_server) {
  conversation_element_t *saved_elements = pinfo->conv_elements;
  port_type saved_ptype = pinfo->ptype;
  uint32_t saved_srcport = pinfo->srcport;
  uint32_t saved_destport = pinfo->destport;
  uint32_t conversation_id =
      parsed->session_id ^ ((uint32_t)parsed->destination_port << 16);

  conversation_set_elements_by_id(pinfo, CONVERSATION_NONE,
                                  conversation_id ? conversation_id : 1);
  pinfo->ptype = PT_UDP;
  if (from_server)
    pinfo->srcport = parsed->destination_port;
  else
    pinfo->destport = parsed->destination_port;
  if (!dissector_try_uint(udp_port_table, parsed->destination_port, payload,
                          pinfo, tree))
    call_dissector(data_handle, payload, pinfo, tree);
  pinfo->srcport = saved_srcport;
  pinfo->destport = saved_destport;
  pinfo->ptype = saved_ptype;
  pinfo->conv_elements = saved_elements;
}

static bool dissect_hy2_quic_datagram(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, void *data) {
  quic_datagram_info *datagram_info = (quic_datagram_info *)data;
  hy2_udp_parse parsed;
  proto_item *item;
  proto_tree *hy2_tree;
  tvbuff_t *payload;
  unsigned payload_length;

  if (datagram_info == NULL)
    return false;
  parsed = hy2_parse_udp(tvb);
  if (parsed.status != HY2_PARSE_OK)
    return false;
  if (!hy2_is_obfs_endpoint(pinfo) &&
      wmem_map_lookup(hy2_connections, datagram_info->quic_info) == NULL)
    return false;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYSTERIA2");
  col_set_str(pinfo->cinfo, COL_INFO, "Hysteria 2 UDP message");
  item = proto_tree_add_item(tree, proto_hysteria2, tvb, 0, -1, ENC_NA);
  hy2_tree = proto_item_add_subtree(item, ett_hy2_udp);
  proto_item_append_text(item, ", UDP session %u", parsed.session_id);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_session_id, tvb, 0, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_packet_id, tvb, 4, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_fragment_id, tvb, 6, 1,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_fragment_count, tvb, 7, 1,
                      ENC_BIG_ENDIAN);
  hy2_varint address_length = hy2_get_varint(tvb, parsed.address_length_offset);
  proto_tree_add_uint64(hy2_tree, hf_hy2_address_length, tvb,
                        parsed.address_length_offset, address_length.length,
                        parsed.address_length);
  proto_tree_add_item(hy2_tree, hf_hy2_address, tvb, parsed.address_offset,
                      parsed.address_length, ENC_ASCII | ENC_NA);
  proto_tree_add_uint(hy2_tree, hf_hy2_destination_port, tvb, 0, 0,
                      parsed.destination_port);
  payload_length = tvb_captured_length_remaining(tvb, parsed.payload_offset);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_payload, tvb, parsed.payload_offset,
                      payload_length, ENC_NA);

  if (parsed.fragment_count == 1) {
    payload = tvb_new_subset_remaining(tvb, parsed.payload_offset);
    hy2_call_udp_payload(payload, pinfo, tree, &parsed,
                         datagram_info->from_server);
  } else {
    fragment_head *fragments;
    uint32_t reassembly_id = parsed.session_id ^
                             ((uint32_t)parsed.packet_id << 16) ^
                             (datagram_info->from_server ? 0x80000000U : 0);
    bool saved_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    fragments = fragment_add_seq_check(
        &hy2_udp_reassembly_table, tvb, parsed.payload_offset, pinfo,
        reassembly_id, NULL, parsed.fragment_id, payload_length,
        parsed.fragment_id + 1 < parsed.fragment_count);
    payload = process_reassembled_data(tvb, parsed.payload_offset, pinfo,
                                       "Reassembled Hysteria 2 UDP", fragments,
                                       &hy2_udp_frag_items, NULL, hy2_tree);
    pinfo->fragmented = saved_fragmented;
    if (payload)
      hy2_call_udp_payload(payload, pinfo, tree, &parsed,
                           datagram_info->from_server);
  }
  return true;
}

static int dissect_hy2_tcp_fixture(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void *data _U_) {
  hy2_tcp_request_parse parsed = hy2_parse_tcp_request(tvb);
  unsigned length = tvb_captured_length(tvb);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYSTERIA2");
  col_set_str(pinfo->cinfo, COL_INFO, "Hysteria 2 TCP request fixture");
  if (parsed.status == HY2_PARSE_OK) {
    hy2_request_tree(tvb, tree, &parsed);
    return length;
  }
  proto_item *item =
      proto_tree_add_item(tree, proto_hysteria2, tvb, 0, length, ENC_NA);
  proto_tree *hy2_tree = proto_item_add_subtree(item, ett_hy2_tcp_request);
  if (parsed.status == HY2_PARSE_NEED_MORE)
    proto_tree_add_expert(hy2_tree, pinfo, &ei_hy2_truncated, tvb, length, 0);
  else if (parsed.status == HY2_PARSE_MALFORMED)
    proto_tree_add_expert(hy2_tree, pinfo, &ei_hy2_bad_address, tvb, 0, length);
  else
    proto_tree_add_expert(hy2_tree, pinfo, &ei_hy2_malformed, tvb, 0, length);
  return length;
}

static int dissect_hy2_udp_fixture(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void *data _U_) {
  hy2_udp_parse parsed = hy2_parse_udp(tvb);
  unsigned length = tvb_captured_length(tvb);
  proto_item *item;
  proto_tree *hy2_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYSTERIA2");
  col_set_str(pinfo->cinfo, COL_INFO, "Hysteria 2 UDP message fixture");
  item = proto_tree_add_item(tree, proto_hysteria2, tvb, 0, length, ENC_NA);
  hy2_tree = proto_item_add_subtree(item, ett_hy2_udp);
  if (parsed.status != HY2_PARSE_OK) {
    expert_field *expert = parsed.status == HY2_PARSE_NEED_MORE
                               ? &ei_hy2_truncated
                               : &ei_hy2_bad_fragment;
    proto_tree_add_expert(hy2_tree, pinfo, expert, tvb, 0, length);
    return length;
  }
  proto_tree_add_item(hy2_tree, hf_hy2_udp_session_id, tvb, 0, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_packet_id, tvb, 4, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_fragment_id, tvb, 6, 1,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_fragment_count, tvb, 7, 1,
                      ENC_BIG_ENDIAN);
  hy2_varint address_length = hy2_get_varint(tvb, parsed.address_length_offset);
  proto_tree_add_uint64(hy2_tree, hf_hy2_address_length, tvb,
                        parsed.address_length_offset, address_length.length,
                        parsed.address_length);
  proto_tree_add_item(hy2_tree, hf_hy2_address, tvb, parsed.address_offset,
                      parsed.address_length, ENC_ASCII | ENC_NA);
  proto_tree_add_uint(hy2_tree, hf_hy2_destination_port, tvb, 0, 0,
                      parsed.destination_port);
  proto_tree_add_item(hy2_tree, hf_hy2_udp_payload, tvb, parsed.payload_offset,
                      tvb_captured_length_remaining(tvb, parsed.payload_offset),
                      ENC_NA);
  if (parsed.fragment_count > 1) {
    fragment_head *fragments;
    bool saved_fragmented = pinfo->fragmented;
    uint32_t reassembly_id =
        parsed.session_id ^ ((uint32_t)parsed.packet_id << 16);
    pinfo->fragmented = true;
    fragments = fragment_add_seq_check(
        &hy2_udp_reassembly_table, tvb, parsed.payload_offset, pinfo,
        reassembly_id, NULL, parsed.fragment_id,
        tvb_captured_length_remaining(tvb, parsed.payload_offset),
        parsed.fragment_id + 1 < parsed.fragment_count);
    tvbuff_t *reassembled = process_reassembled_data(
        tvb, parsed.payload_offset, pinfo, "Reassembled Hysteria 2 UDP fixture",
        fragments, &hy2_udp_frag_items, NULL, hy2_tree);
    pinfo->fragmented = saved_fragmented;
    if (reassembled)
      proto_tree_add_item(hy2_tree, hf_hy2_udp_payload, reassembled, 0,
                          tvb_captured_length(reassembled), ENC_NA);
  }
  return length;
}

void proto_register_hysteria2(void) {
  static hf_register_info hf[] = {
      {&hf_hy2_salamander_salt,
       {"Salamander Salt", "hysteria2.salamander.salt", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL}},
      {&hf_hy2_tcp_request_id,
       {"TCP Request ID", "hysteria2.tcp.request_id", FT_UINT64, BASE_HEX, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_address_length,
       {"Address Length", "hysteria2.address.length", FT_UINT64, BASE_DEC, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_address,
       {"Address", "hysteria2.address", FT_STRING, BASE_NONE, NULL, 0, NULL,
        HFILL}},
      {&hf_hy2_destination_port,
       {"Destination Port", "hysteria2.destination.port", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_hy2_padding_length,
       {"Padding Length", "hysteria2.padding.length", FT_UINT64, BASE_DEC, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_padding,
       {"Padding", "hysteria2.padding", FT_BYTES, BASE_NONE, NULL, 0, NULL,
        HFILL}},
      {&hf_hy2_response_status,
       {"Response Status", "hysteria2.tcp.response.status", FT_UINT8, BASE_DEC,
        VALS(response_status_values), 0, NULL, HFILL}},
      {&hf_hy2_response_message_length,
       {"Message Length", "hysteria2.tcp.response.message_length", FT_UINT64,
        BASE_DEC, NULL, 0, NULL, HFILL}},
      {&hf_hy2_response_message,
       {"Message", "hysteria2.tcp.response.message", FT_STRING, BASE_NONE, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_udp_session_id,
       {"UDP Session ID", "hysteria2.udp.session_id", FT_UINT32, BASE_DEC, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_udp_packet_id,
       {"UDP Packet ID", "hysteria2.udp.packet_id", FT_UINT16, BASE_DEC, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_udp_fragment_id,
       {"Fragment ID", "hysteria2.udp.fragment_id", FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL}},
      {&hf_hy2_udp_fragment_count,
       {"Fragment Count", "hysteria2.udp.fragment_count", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL}},
      {&hf_hy2_udp_payload,
       {"UDP Payload", "hysteria2.udp.payload", FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_hy2_fragments,
       {"Message fragments", "hysteria2.fragments", FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_hy2_fragment,
       {"Message fragment", "hysteria2.fragment", FT_FRAMENUM, BASE_NONE, NULL,
        0, NULL, HFILL}},
      {&hf_hy2_fragment_overlap,
       {"Message fragment overlap", "hysteria2.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_hy2_fragment_overlap_conflict,
       {"Message fragment overlap conflict",
        "hysteria2.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_hy2_fragment_multiple_tails,
       {"Message has multiple tail fragments",
        "hysteria2.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL}},
      {&hf_hy2_fragment_too_long_fragment,
       {"Message fragment too long", "hysteria2.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_hy2_fragment_error,
       {"Message defragmentation error", "hysteria2.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL}},
      {&hf_hy2_fragment_count,
       {"Message fragment count", "hysteria2.fragment.count", FT_UINT32,
        BASE_DEC, NULL, 0, NULL, HFILL}},
      {&hf_hy2_reassembled_in,
       {"Reassembled in", "hysteria2.reassembled.in", FT_FRAMENUM, BASE_NONE,
        NULL, 0, NULL, HFILL}},
      {&hf_hy2_reassembled_length,
       {"Reassembled length", "hysteria2.reassembled.length", FT_UINT32,
        BASE_DEC, NULL, 0, NULL, HFILL}},
      {&hf_hy2_reassembled_data,
       {"Reassembled data", "hysteria2.reassembled.data", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL}}};
  static int *ett[] = {&ett_hy2,
                       &ett_hy2_salamander,
                       &ett_hy2_tcp_request,
                       &ett_hy2_tcp_response,
                       &ett_hy2_udp,
                       &ett_hy2_fragments,
                       &ett_hy2_fragment};
  static ei_register_info ei[] = {
      {&ei_hy2_malformed,
       {"hysteria2.malformed", PI_MALFORMED, PI_ERROR,
        "Malformed Hysteria 2 data", EXPFILL}},
      {&ei_hy2_truncated,
       {"hysteria2.truncated", PI_MALFORMED, PI_WARN,
        "Truncated Hysteria 2 data", EXPFILL}},
      {&ei_hy2_bad_address,
       {"hysteria2.invalid_address", PI_PROTOCOL, PI_ERROR,
        "Invalid Hysteria 2 target address", EXPFILL}},
      {&ei_hy2_bad_status,
       {"hysteria2.invalid_status", PI_PROTOCOL, PI_ERROR,
        "Invalid Hysteria 2 response status", EXPFILL}},
      {&ei_hy2_bad_fragment,
       {"hysteria2.invalid_fragment", PI_REASSEMBLE, PI_ERROR,
        "Invalid Hysteria 2 fragment metadata", EXPFILL}},
      {&ei_hy2_key_file,
       {"hysteria2.key_file_error", PI_SECURITY, PI_ERROR,
        "Unable to read Salamander key file", EXPFILL}}};
  expert_module_t *expert_hy2;
  module_t *hy2_module;

  proto_hysteria2 =
      proto_register_protocol("Hysteria 2", "HYSTERIA2", "hysteria2");
  proto_register_field_array(proto_hysteria2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_hy2 = expert_register_protocol(proto_hysteria2);
  expert_register_field_array(expert_hy2, ei, array_length(ei));
  hy2_module = prefs_register_protocol(proto_hysteria2, NULL);
  prefs_register_filename_preference(
      hy2_module, "salamander_key_file", "Salamander key file",
      "Private file containing the Salamander password on its first line.",
      &pref_salamander_key_file, false);
  register_init_routine(hy2_init);
  reassembly_table_register(&hy2_udp_reassembly_table,
                            &addresses_ports_reassembly_table_functions);
}

void proto_reg_handoff_hysteria2(void) {
  hysteria2_handle =
      register_dissector("hysteria2", dissect_hy2_salamander, proto_hysteria2);
  hy2_tcp_fixture_handle = register_dissector(
      "hysteria2_tcp_request", dissect_hy2_tcp_fixture, proto_hysteria2);
  hy2_udp_fixture_handle = register_dissector(
      "hysteria2_udp_message", dissect_hy2_udp_fixture, proto_hysteria2);
  dissector_add_for_decode_as("tcp.port", hy2_tcp_fixture_handle);
  dissector_add_for_decode_as("udp.port", hy2_udp_fixture_handle);
  quic_handle = find_dissector_add_dependency("quic", proto_hysteria2);
  tls_handle = find_dissector_add_dependency("tls", proto_hysteria2);
  data_handle = find_dissector("data");
  udp_port_table = find_dissector_table("udp.port");
  heur_dissector_add("udp", dissect_hy2_salamander_heur,
                     "Hysteria 2 Salamander", "hysteria2_salamander",
                     proto_hysteria2, HEURISTIC_ENABLE);
  heur_dissector_add("quic.stream", dissect_hy2_quic_stream,
                     "Hysteria 2 TCP stream", "hysteria2_quic_stream",
                     proto_hysteria2, HEURISTIC_ENABLE);
  heur_dissector_add("quic.datagram", dissect_hy2_quic_datagram,
                     "Hysteria 2 UDP message", "hysteria2_quic_datagram",
                     proto_hysteria2, HEURISTIC_ENABLE);
}
