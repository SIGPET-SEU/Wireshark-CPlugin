# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

set_module_info(hysteria2 0 1 0 0)

set(DISSECTOR_SRC
	packet-hysteria2.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(hysteria2 epan)
target_link_libraries(hysteria2 epan)
install_plugin(hysteria2 epan)

CHECKAPI(
	NAME hysteria2
	SWITCHES --group dissectors-prohibited --group dissectors-restricted
	SOURCES ${DISSECTOR_SRC}
)
