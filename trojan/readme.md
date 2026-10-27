# Trojan dissector

This plugin dissects Trojan application data after Wireshark decrypts the
outer TLS session. It validates the complete Trojan request header, tracks the
tunnel in both directions, reconstructs inner TLS records, and passes them to
Wireshark's built-in TLS dissector using an isolated conversation.

TCP `CONNECT` is supported. `UDP ASSOCIATE` requests are identified, but their
datagram framing is intentionally left undecoded.

## Wireshark 4.4.2 patches

Apply both patches before building:

1. `wireshark-4.4.2-tls-heuristic-desegment.patch` lets a decrypted-TLS
   heuristic wait for a fragmented Trojan header without selecting a
   port-based fallback prematurely.
2. `wireshark-4.4.2-tls-explicit-conversation.patch` lets the nested TLS
   dissector use a conversation independent from the outer TLS session.

## Build

Place this repository under `plugins/epan/Wireshark-CPlugin` and configure the
Wireshark build with:

```sh
cmake -S ../wireshark -B ../build \
  -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/Wireshark-CPlugin/trojan
cmake --build ../build --target tshark trojan
```

On Windows, build the `wireshark` target as well and run the executable from
the configured build directory.

## TLS keys

The outer TLS secrets must come from the Trojan client, such as a sing-box
build with `SSLKEYLOGFILE` support. For tunneled HTTPS, collect the inner TLS
secrets from the application (for example curl with its own `SSLKEYLOGFILE`).
Wireshark may read a file containing both sets of NSS key-log lines.

Useful filters include `trojan`, `trojan.command == 1`,
`trojan.destination.port == 443`, `trojan.destination.domain`,
`trojan.direction`, and `trojan.inner_tls.length`.
