# AnyTLS dissector

This Wireshark 4.4.2 epan plugin recognizes AnyTLS v2 inside decrypted outer
TLS without claiming a port. It validates the authentication preface followed
by the client Settings frame, parses multiplexing frames and destinations, and
reassembles each tunneled byte stream independently before handing it to TLS.
Each stream and direction has independent state. Complete inner TLS records
are framed before dispatch so records split across AnyTLS PSH frames are
reassembled without mixing control frames, padding, or concurrent streams.

The authentication digest is deliberately not exposed as a field. Supported
stream destinations are IPv4, IPv6, and domain names. The initial scope is TCP
proxy streams carrying TLS; non-TLS stream payloads are reported as
unsupported data.

Configure the existing CLI build with:

```sh
cmake -S ~/proxy/wireshark-dev/wireshark \
  -B ~/proxy/wireshark-dev/build \
  -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/Wireshark-CPlugin/anytls
cmake --build ~/proxy/wireshark-dev/build --target tshark anytls -j4
```

Use the capture helper in the research-tools repository for private live
captures and combined outer/inner TLS key logging:

```sh
~/proxy/bin/anytls-capture curl --http2
~/proxy/bin/anytls-capture firefox https://www.google.com/
~/proxy/research-tools/tests/test_anytls.sh
```
