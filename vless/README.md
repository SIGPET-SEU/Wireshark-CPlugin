# VLESS v0 over TLS dissector

This Wireshark 4.4 plugin recognizes VLESS v0 request headers inside decrypted
TLS application data. It deliberately uses an enabled TLS heuristic instead of
claiming TCP/443.

The heuristic validates the complete TCP request header and the complete first
tunneled TLS record. Once matched, it assigns the TLS session application
handle to VLESS. Request and response headers can span outer TLS records.
After recognition, tunneled bytes are fed through Wireshark's streaming
reassembly helper with independent request and response state. This preserves
inner TLS records that span multiple decrypted outer TLS records. The
reassembled stream is passed to the stock TLS dissector through a distinct
PT_NONE conversation, so ALPN can select HTTP/1.1 or HTTP/2 without modifying
either application dissector.

Wireshark 4.4.2 needs the version-specific patch in ../wireshark-patches.
It prevents the TCP/443 HTTP fallback while a TLS heuristic has a pending
reassembly request.

Implemented request fields:

- version and UUID
- addons length and bytes
- TCP command
- destination port
- IPv4, IPv6, or domain destination

The response version, addons length, and addons are also decoded. UDP, XUDP,
multiplexing, Vision, WebSocket, and VLESS Encryption are outside this
experiment.

An optional vless.expected_uuid string preference accepts canonical UUID text
or 32 hexadecimal digits. When set, only that UUID is accepted by the
heuristic. It is unset by default.

Useful display filters include vless, vless.inner_tls.reassembled.in,
vless.command == 1,
vless.destination.port == 443, vless.address_type == 2, and
vless.response.version == 0.

Configure from the Wireshark source root with:

    cmake -S . -B ../build -G Ninja \
      -DBUILD_wireshark=OFF -DBUILD_tshark=ON -DENABLE_PLUGINS=ON \
      -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/Wireshark-CPlugin/vless
    cmake --build ../build --target tshark vless
