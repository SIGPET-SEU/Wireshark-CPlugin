# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

set_module_info(naive 0 1 0 0)

set(DISSECTOR_SRC
	packet-naive.c
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

add_wireshark_plugin_library(naive epan)
target_link_libraries(naive epan)
install_plugin(naive epan)

CHECKAPI(
	NAME naive
	SWITCHES --group dissectors-prohibited --group dissectors-restricted
	SOURCES ${DISSECTOR_SRC}
)
