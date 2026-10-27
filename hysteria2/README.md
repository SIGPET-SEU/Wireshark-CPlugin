# Hysteria 2 dissector

This Wireshark 4.4.2 plugin dissects Hysteria 2 TCP proxy streams and UDP
messages carried by QUIC. It also unwraps the optional Salamander layer before
calling Wireshark's QUIC dissector.

The Wireshark source patch in `../wireshark-patches/` adds heuristic hooks for
decrypted QUIC stream and DATAGRAM payloads. The plugin does not claim a port.

For Salamander captures, set `hysteria2.salamander_key_file` to a private file
whose first line is the obfuscation password. QUIC and tunneled TLS decryption
use the standard `tls.keylog_file` NSS key log preference.

Gecko obfuscation is not implemented in this initial version.
