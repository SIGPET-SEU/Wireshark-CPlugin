# TUIC v5 dissector

This Wireshark 4.4.2 epan plugin recognizes TUIC v5 inside decrypted QUIC
without claiming UDP/8446 or any other port. It parses Authenticate, Connect,
Packet, Dissociate, and Heartbeat commands; domain, IPv4, IPv6, and empty
addresses; and native or stream-carried UDP packets. Fragmented UDP messages
use Wireshark's reassembly API.

Authenticate UUID and token bytes are deliberately represented only as opaque
authentication material. The plugin never registers them as printable fields.
A Connect stream is identified from the complete v5 header and a plausible
inner TLS record. The reverse direction has no TUIC response header, so state
is keyed by opaque QUIC connection identity plus stream ID. Inner TLS uses an
isolated conversation and supports records split across QUIC STREAM frames.

The Wireshark source patch in `../wireshark-patches/` supplies the
`quic.stream` and `quic.datagram` heuristic hooks used by this plugin. The
hooks run before the connection-level ALPN fallback, preserving unrelated
HTTP/3 streams.

Configure and build the CLI-only target with:

```sh
cmake -S ~/proxy/wireshark-dev/wireshark \
  -B ~/proxy/wireshark-dev/build \
  -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/Wireshark-CPlugin/tuic
cmake --build ~/proxy/wireshark-dev/build --target tshark tuic -j4
```

Run private live captures and credential-free parser fixtures with:

```sh
~/proxy/bin/tuic-capture curl --http2
~/proxy/bin/tuic-capture firefox https://www.google.com/
~/proxy/bin/tuic-capture curl --udp-dns example.com
~/proxy/research-tools/tests/test_tuic.sh
```
