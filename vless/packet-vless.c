/* packet-vless.c
 * VLESS v0 over decrypted TLS.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/address.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/wmem_scopes.h>
#include <epan/dissectors/packet-tls.h>

#define VLESS_VERSION_0 0
#define VLESS_COMMAND_TCP 1
#define VLESS_ATYPE_IPV4 1
#define VLESS_ATYPE_DOMAIN 2
#define VLESS_ATYPE_IPV6 3
#define TLS_RECORD_HEADER_LENGTH 5
#define TLS_RECORD_MAX_LENGTH 18432

void proto_register_vless(void);
void proto_reg_handoff_vless(void);

static int proto_vless;
static dissector_handle_t vless_handle;
static dissector_handle_t tls_handle;

static reassembly_table vless_inner_tls_reassembly_table;
REASSEMBLE_ITEMS_DEFINE(vless_inner_tls, "VLESS inner TLS");

static int hf_vless_version;
static int hf_vless_uuid;
static int hf_vless_addons_length;
static int hf_vless_addons;
static int hf_vless_command;
static int hf_vless_destination_port;
static int hf_vless_address_type;
static int hf_vless_domain_length;
static int hf_vless_ipv4;
static int hf_vless_ipv6;
static int hf_vless_domain;
static int hf_vless_response_version;
static int hf_vless_response_addons_length;
static int hf_vless_response_addons;

static int ett_vless;
static int ett_vless_request;
static int ett_vless_response;

static expert_field ei_vless_malformed = EI_INIT;
static expert_field ei_vless_truncated = EI_INIT;
static expert_field ei_vless_unsupported_version = EI_INIT;
static expert_field ei_vless_unsupported_command = EI_INIT;
static expert_field ei_vless_unsupported_address = EI_INIT;

static const char *pref_expected_uuid;

static const value_string command_values[] = {
	{ VLESS_COMMAND_TCP, "TCP" },
	{ 2, "UDP" },
	{ 3, "Mux" },
	{ 0, NULL }
};

static const value_string address_type_values[] = {
	{ VLESS_ATYPE_IPV4, "IPv4" },
	{ VLESS_ATYPE_DOMAIN, "Domain" },
	{ VLESS_ATYPE_IPV6, "IPv6" },
	{ 0, NULL }
};

typedef enum {
	PARSE_VALID,
	PARSE_NEED_MORE,
	PARSE_BAD_VERSION,
	PARSE_BAD_COMMAND,
	PARSE_BAD_ADDRESS,
	PARSE_BAD_DOMAIN,
	PARSE_BAD_INNER_TLS,
	PARSE_UUID_MISMATCH
} parse_status_t;

typedef struct {
	parse_status_t status;
	unsigned needed;
	unsigned bad_offset;
	unsigned addons_length;
	unsigned command_offset;
	unsigned port_offset;
	unsigned address_type_offset;
	unsigned address_offset;
	unsigned address_length;
	unsigned domain_length_offset;
	unsigned header_length;
} request_parse_t;

typedef struct {
	address client_address;
	uint32_t client_port;
	uint32_t request_header_frame;
	uint32_t response_header_frame;
	uint32_t request_header_seq;
	uint32_t response_header_seq;
	streaming_reassembly_info_t *request_reassembly;
	streaming_reassembly_info_t *response_reassembly;
} vless_conversation_t;

static bool
hex_nibble(char c, uint8_t *value)
{
	if (c >= '0' && c <= '9') {
		*value = (uint8_t)(c - '0');
		return true;
	}
	if (c >= 'a' && c <= 'f') {
		*value = (uint8_t)(c - 'a' + 10);
		return true;
	}
	if (c >= 'A' && c <= 'F') {
		*value = (uint8_t)(c - 'A' + 10);
		return true;
	}
	return false;
}

/* 0 means unset, 1 valid, -1 invalid. */
static int
expected_uuid_bytes(uint8_t value[16])
{
	unsigned digits = 0;
	uint8_t high = 0;

	if (pref_expected_uuid == NULL || pref_expected_uuid[0] == '\0')
		return 0;

	for (const char *p = pref_expected_uuid; *p != '\0'; p++) {
		uint8_t nibble;
		if (*p == '-')
			continue;
		if (!hex_nibble(*p, &nibble) || digits >= 32)
			return -1;
		if ((digits & 1) == 0)
			high = (uint8_t)(nibble << 4);
		else
			value[digits / 2] = (uint8_t)(high | nibble);
		digits++;
	}
	return digits == 32 ? 1 : -1;
}

static bool
plausible_tls_record(tvbuff_t *tvb, unsigned offset)
{
	uint8_t content_type = tvb_get_uint8(tvb, offset);
	uint8_t major = tvb_get_uint8(tvb, offset + 1);
	uint8_t minor = tvb_get_uint8(tvb, offset + 2);
	uint16_t record_length = tvb_get_ntohs(tvb, offset + 3);

	return content_type >= 20 && content_type <= 23 &&
		major == 3 && minor <= 4 &&
		record_length > 0 && record_length <= TLS_RECORD_MAX_LENGTH;
}

static request_parse_t
parse_request(tvbuff_t *tvb)
{
	request_parse_t result = { PARSE_VALID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned length = tvb_captured_length(tvb);
	unsigned offset;
	uint8_t address_kind;
	uint8_t expected_uuid[16];
	int uuid_state;

#define REQUIRE_BYTES(count) do { \
	if (length < (count)) { \
		result.status = PARSE_NEED_MORE; \
		result.needed = (count); \
		return result; \
	} \
} while (0)

	REQUIRE_BYTES(18);
	if (tvb_get_uint8(tvb, 0) != VLESS_VERSION_0) {
		result.status = PARSE_BAD_VERSION;
		return result;
	}
	uuid_state = expected_uuid_bytes(expected_uuid);
	if (uuid_state < 0 ||
		(uuid_state > 0 && tvb_memeql(tvb, 1, expected_uuid, 16) != 0)) {
		result.status = PARSE_UUID_MISMATCH;
		result.bad_offset = 1;
		return result;
	}

	result.addons_length = tvb_get_uint8(tvb, 17);
	offset = 18 + result.addons_length;
	REQUIRE_BYTES(offset + 4);

	result.command_offset = offset;
	if (tvb_get_uint8(tvb, offset) != VLESS_COMMAND_TCP) {
		result.status = PARSE_BAD_COMMAND;
		result.bad_offset = offset;
		return result;
	}
	result.port_offset = offset + 1;
	result.address_type_offset = offset + 3;
	address_kind = tvb_get_uint8(tvb, result.address_type_offset);
	offset += 4;

	switch (address_kind) {
	case VLESS_ATYPE_IPV4:
		result.address_offset = offset;
		result.address_length = 4;
		REQUIRE_BYTES(offset + 4);
		offset += 4;
		break;
	case VLESS_ATYPE_DOMAIN:
		result.domain_length_offset = offset;
		REQUIRE_BYTES(offset + 1);
		result.address_length = tvb_get_uint8(tvb, offset);
		if (result.address_length == 0) {
			result.status = PARSE_BAD_DOMAIN;
			result.bad_offset = offset;
			return result;
		}
		result.address_offset = offset + 1;
		REQUIRE_BYTES(result.address_offset + result.address_length);
		offset = result.address_offset + result.address_length;
		break;
	case VLESS_ATYPE_IPV6:
		result.address_offset = offset;
		result.address_length = 16;
		REQUIRE_BYTES(offset + 16);
		offset += 16;
		break;
	default:
		result.status = PARSE_BAD_ADDRESS;
		result.bad_offset = result.address_type_offset;
		return result;
	}

	result.header_length = offset;
	REQUIRE_BYTES(offset + TLS_RECORD_HEADER_LENGTH);
	if (!plausible_tls_record(tvb, offset)) {
		result.status = PARSE_BAD_INNER_TLS;
		result.bad_offset = offset;
		return result;
	}
	REQUIRE_BYTES(offset + TLS_RECORD_HEADER_LENGTH + tvb_get_ntohs(tvb, offset + 3));
	return result;
#undef REQUIRE_BYTES
}

static void
request_tree_add(tvbuff_t *tvb, proto_tree *tree, const request_parse_t *parsed)
{
	proto_item *root_item;
	proto_tree *vless_tree;
	unsigned header_length = parsed->header_length;
	uint8_t address_kind;

	if (header_length == 0)
		header_length = MIN(tvb_captured_length(tvb), parsed->needed);
	root_item = proto_tree_add_item(tree, proto_vless, tvb, 0, header_length, ENC_NA);
	vless_tree = proto_item_add_subtree(root_item, ett_vless_request);
	proto_tree_add_item(vless_tree, hf_vless_version, tvb, 0, 1, ENC_BIG_ENDIAN);
	if (tvb_captured_length(tvb) < 18)
		return;
	proto_tree_add_item(vless_tree, hf_vless_uuid, tvb, 1, 16, ENC_NA);
	proto_tree_add_item(vless_tree, hf_vless_addons_length, tvb, 17, 1, ENC_BIG_ENDIAN);
	if (parsed->addons_length > 0)
		proto_tree_add_item(vless_tree, hf_vless_addons, tvb, 18, parsed->addons_length, ENC_NA);
	proto_tree_add_item(vless_tree, hf_vless_command, tvb, parsed->command_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(vless_tree, hf_vless_destination_port, tvb, parsed->port_offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(vless_tree, hf_vless_address_type, tvb, parsed->address_type_offset, 1, ENC_BIG_ENDIAN);
	address_kind = tvb_get_uint8(tvb, parsed->address_type_offset);
	if (address_kind == VLESS_ATYPE_IPV4) {
		proto_tree_add_item(vless_tree, hf_vless_ipv4, tvb, parsed->address_offset, 4, ENC_BIG_ENDIAN);
	} else if (address_kind == VLESS_ATYPE_IPV6) {
		proto_tree_add_item(vless_tree, hf_vless_ipv6, tvb, parsed->address_offset, 16, ENC_NA);
	} else if (address_kind == VLESS_ATYPE_DOMAIN) {
		proto_tree_add_item(vless_tree, hf_vless_domain_length, tvb, parsed->domain_length_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(vless_tree, hf_vless_domain, tvb, parsed->address_offset,
			parsed->address_length, ENC_UTF_8 | ENC_NA);
	}
}

static void
request_expert_add(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	const request_parse_t *parsed)
{
	expert_field *expert = &ei_vless_malformed;
	const char *message = "Malformed VLESS request";
	unsigned offset = parsed->bad_offset;

	switch (parsed->status) {
	case PARSE_NEED_MORE:
		expert = &ei_vless_truncated;
		message = "Truncated VLESS request header";
		offset = tvb_captured_length(tvb);
		break;
	case PARSE_BAD_VERSION:
		expert = &ei_vless_unsupported_version;
		message = "Unsupported VLESS request version";
		break;
	case PARSE_BAD_COMMAND:
		expert = &ei_vless_unsupported_command;
		message = "Unsupported VLESS command (only TCP is implemented)";
		break;
	case PARSE_BAD_ADDRESS:
		expert = &ei_vless_unsupported_address;
		message = "Unsupported VLESS address type";
		break;
	case PARSE_BAD_DOMAIN:
		message = "VLESS domain address is empty";
		break;
	case PARSE_BAD_INNER_TLS:
		message = "VLESS request is not followed by a plausible TLS record";
		break;
	case PARSE_UUID_MISMATCH:
		message = "VLESS UUID does not match the configured expectation";
		break;
	case PARSE_VALID:
		return;
	}
	proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset,
		offset < tvb_captured_length(tvb) ? 1 : 0, "%s", message);
}

static void
call_inner_tls_streaming(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	streaming_reassembly_info_t *reassembly_info, unsigned offset, uint32_t tls_seq)
{
	port_type saved_ptype;
	int length;
	uint64_t payload_id;

	if (offset >= tvb_captured_length(tvb))
		return;

	length = tvb_reported_length_remaining(tvb, offset);
	/* Frame numbers keep this monotonic across the capture, while the outer
	 * decrypted-stream sequence distinguishes coalesced TLS records. */
	payload_id = ((uint64_t)pinfo->num << 32) | tls_seq;
	saved_ptype = pinfo->ptype;
	pinfo->ptype = PT_NONE;
	reassemble_streaming_data_and_call_subdissector(tvb, pinfo, offset, length,
		tree, proto_tree_get_root(tree), vless_inner_tls_reassembly_table,
		reassembly_info, payload_id, tls_handle, proto_tree_get_root(tree), NULL,
		"VLESS inner TLS", &vless_inner_tls_fragment_items,
		hf_vless_inner_tls_segment);
	pinfo->ptype = saved_ptype;
}

static int
dissect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	vless_conversation_t *state, uint32_t tls_seq)
{
	request_parse_t parsed = parse_request(tvb);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLESS");
	col_set_str(pinfo->cinfo, COL_INFO, "VLESS TCP request");
	if (parsed.status == PARSE_NEED_MORE && pinfo->can_desegment) {
		pinfo->desegment_offset = 0;
		pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
		return tvb_captured_length(tvb);
	}
	if (parsed.status != PARSE_VALID) {
		request_tree_add(tvb, tree, &parsed);
		request_expert_add(tvb, pinfo, tree, &parsed);
		return tvb_captured_length(tvb);
	}

	request_tree_add(tvb, tree, &parsed);
	state->request_header_frame = pinfo->num;
	state->request_header_seq = tls_seq;
	call_inner_tls_streaming(tvb, pinfo, tree, state->request_reassembly,
		parsed.header_length, tls_seq);
	return tvb_captured_length(tvb);
}

static int
dissect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	vless_conversation_t *state, uint32_t tls_seq)
{
	unsigned length = tvb_captured_length(tvb);
	unsigned addons_length;
	unsigned header_length;
	proto_item *root_item;
	proto_tree *response_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLESS");
	col_set_str(pinfo->cinfo, COL_INFO, "VLESS response");
	if (length < 2) {
		if (pinfo->can_desegment) {
			pinfo->desegment_offset = 0;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return length;
		}
		proto_tree_add_expert_format(tree, pinfo, &ei_vless_truncated, tvb,
			length, 0, "Truncated VLESS response header");
		return length;
	}

	addons_length = tvb_get_uint8(tvb, 1);
	header_length = 2 + addons_length;
	if (length < header_length) {
		if (pinfo->can_desegment) {
			pinfo->desegment_offset = 0;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return length;
		}
		proto_tree_add_expert_format(tree, pinfo, &ei_vless_truncated, tvb,
			length, 0, "Truncated VLESS response addons");
		return length;
	}

	root_item = proto_tree_add_item(tree, proto_vless, tvb, 0, header_length, ENC_NA);
	response_tree = proto_item_add_subtree(root_item, ett_vless_response);
	proto_tree_add_item(response_tree, hf_vless_response_version, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(response_tree, hf_vless_response_addons_length, tvb, 1, 1, ENC_BIG_ENDIAN);
	if (addons_length > 0)
		proto_tree_add_item(response_tree, hf_vless_response_addons, tvb, 2, addons_length, ENC_NA);
	if (tvb_get_uint8(tvb, 0) != VLESS_VERSION_0) {
		proto_tree_add_expert_format(response_tree, pinfo, &ei_vless_unsupported_version,
			tvb, 0, 1, "Unsupported VLESS response version");
		return length;
	}

	state->response_header_frame = pinfo->num;
	state->response_header_seq = tls_seq;
	call_inner_tls_streaming(tvb, pinfo, tree, state->response_reassembly,
		header_length, tls_seq);
	return length;
}

static bool
packet_from_client(packet_info *pinfo, const vless_conversation_t *state)
{
	return pinfo->srcport == state->client_port &&
		addresses_equal(&pinfo->src, &state->client_address);
}

static int
dissect_vless(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	conversation_t *conversation = find_or_create_conversation(pinfo);
	vless_conversation_t *state = (vless_conversation_t *)
		conversation_get_proto_data(conversation, proto_vless);
	struct tlsinfo *tlsinfo = (struct tlsinfo *)data;
	uint32_t tls_seq = tlsinfo != NULL ? tlsinfo->seq : 0;
	bool from_client;

	if (state == NULL) {
		state = wmem_new0(wmem_file_scope(), vless_conversation_t);
		copy_address_wmem(wmem_file_scope(), &state->client_address, &pinfo->src);
		state->client_port = pinfo->srcport;
		conversation_add_proto_data(conversation, proto_vless, state);
		state->request_reassembly = streaming_reassembly_info_new();
		state->response_reassembly = streaming_reassembly_info_new();
	}
	from_client = packet_from_client(pinfo, state);

	if (from_client && (state->request_header_frame == 0 ||
		(state->request_header_frame == pinfo->num &&
		 state->request_header_seq == tls_seq)))
		return dissect_request(tvb, pinfo, tree, state, tls_seq);
	if (!from_client && (state->response_header_frame == 0 ||
		(state->response_header_frame == pinfo->num &&
		 state->response_header_seq == tls_seq)))
		return dissect_response(tvb, pinfo, tree, state, tls_seq);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLESS");
	col_set_str(pinfo->cinfo, COL_INFO,
		from_client ? "VLESS tunneled request data" : "VLESS tunneled response data");
	proto_tree_add_item(tree, proto_vless, tvb, 0, 0, ENC_NA);
	call_inner_tls_streaming(tvb, pinfo, tree,
		from_client ? state->request_reassembly : state->response_reassembly,
		0, tls_seq);
	return tvb_captured_length(tvb);
}

static bool
dissect_vless_heur_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	request_parse_t parsed = parse_request(tvb);
	struct tlsinfo *tlsinfo = (struct tlsinfo *)data;

	if (parsed.status == PARSE_NEED_MORE && pinfo->can_desegment) {
		pinfo->desegment_offset = 0;
		pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
		return false;
	}
	if (parsed.status != PARSE_VALID || tlsinfo == NULL || tlsinfo->app_handle == NULL)
		return false;

	*(tlsinfo->app_handle) = vless_handle;
	dissect_vless(tvb, pinfo, tree, data);
	return true;
}

void
proto_register_vless(void)
{
	static hf_register_info hf[] = {
		{ &hf_vless_version,
			{ "Version", "vless.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_uuid,
			{ "User UUID", "vless.uuid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_addons_length,
			{ "Addons Length", "vless.addons_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_addons,
			{ "Addons", "vless.addons", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_command,
			{ "Command", "vless.command", FT_UINT8, BASE_DEC, VALS(command_values), 0x0, NULL, HFILL } },
		{ &hf_vless_destination_port,
			{ "Destination Port", "vless.destination.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_address_type,
			{ "Address Type", "vless.address_type", FT_UINT8, BASE_DEC, VALS(address_type_values), 0x0, NULL, HFILL } },
		{ &hf_vless_domain_length,
			{ "Domain Length", "vless.destination.domain_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_ipv4,
			{ "IPv4 Destination", "vless.destination.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_ipv6,
			{ "IPv6 Destination", "vless.destination.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_domain,
			{ "Domain Destination", "vless.destination.domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_response_version,
			{ "Response Version", "vless.response.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_response_addons_length,
			{ "Response Addons Length", "vless.response.addons_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_vless_response_addons,
			{ "Response Addons", "vless.response.addons", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		REASSEMBLE_INIT_HF_ITEMS(vless_inner_tls, "VLESS inner TLS", "vless.inner_tls")
	};
	static int *ett[] = {
		&ett_vless,
		&ett_vless_request,
		&ett_vless_response,
		REASSEMBLE_INIT_ETT_ITEMS(vless_inner_tls)
	};
	static ei_register_info ei[] = {
		{ &ei_vless_malformed,
			{ "vless.malformed", PI_MALFORMED, PI_ERROR, "Malformed VLESS data", EXPFILL } },
		{ &ei_vless_truncated,
			{ "vless.truncated", PI_MALFORMED, PI_WARN, "Truncated VLESS data", EXPFILL } },
		{ &ei_vless_unsupported_version,
			{ "vless.unsupported_version", PI_PROTOCOL, PI_WARN, "Unsupported VLESS version", EXPFILL } },
		{ &ei_vless_unsupported_command,
			{ "vless.unsupported_command", PI_UNDECODED, PI_WARN, "Unsupported VLESS command", EXPFILL } },
		{ &ei_vless_unsupported_address,
			{ "vless.unsupported_address_type", PI_PROTOCOL, PI_WARN, "Unsupported VLESS address type", EXPFILL } }
	};
	expert_module_t *expert_vless;
	module_t *vless_module;

	proto_vless = proto_register_protocol("VLESS v0", "VLESS", "vless");
	proto_register_field_array(proto_vless, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	reassembly_table_register(&vless_inner_tls_reassembly_table,
		&addresses_ports_reassembly_table_functions);
	expert_vless = expert_register_protocol(proto_vless);
	expert_register_field_array(expert_vless, ei, array_length(ei));
	vless_module = prefs_register_protocol(proto_vless, NULL);
	prefs_register_string_preference(vless_module, "expected_uuid",
		"Expected UUID",
		"Optional canonical UUID or 32 hexadecimal digits used only to tighten heuristic matching.",
		&pref_expected_uuid);
}

void
proto_reg_handoff_vless(void)
{
	vless_handle = register_dissector("vless", dissect_vless, proto_vless);
	dissector_add_for_decode_as("tcp.port", vless_handle);
	tls_handle = find_dissector_add_dependency("tls", proto_vless);
	heur_dissector_add("tls", dissect_vless_heur_tls, "VLESS v0 over TLS",
		"vless_tls", proto_vless, HEURISTIC_ENABLE);
}
