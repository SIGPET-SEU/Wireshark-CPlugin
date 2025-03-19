# Wireshark Dissector for Shadowsocks

## Reference

- [Shadowsocks (Python Version)](https://github.com/shadowsocks/shadowsocks/tree/master)
- [Shadowsocks (Go Version)](https://github.com/shadowsocks/shadowsocks-go)
- Clash
- [Shadowsocks Documentation](https://shadowsocks.org/doc/aead.html)
- [Wireshark Developer's Guide - Chapter 9. Packet Dissection](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html)

## Usage

We assume that you have compiled this dissector successfully and installed it in Wireshark.

### 1. Connect to A Shadowsocks Server OR Open A PCAP File

Whichever way you choose, it is necessary to know the configuration of the target Shadowsocks server, including the **password**, **AEAD method**, and the **port number**.

### 2. Set Protocol Preferences

`Edit` -> `Preference` -> `Protocols` -> `Shadowsocks` ->

- **Cipher type:** The AEAD method used by the Shadowsocks server. Possible values are:
  - aes-128-gcm
  - aes-192-gcm
  - aes-256-gcm
  - chacha20-ietf-poly1305
  - xchacha20-ietf-poly1305
- **Shadowsocks password:** The password set by the Shadowsocks server.
- **Shadowsocks TCP port:** The port number that the Shadowsocks server listens on.

### 3. Start Capturing

## TODO

- [x] Identify Shadowsocks traffic (by the port number)
- [x] Preferences panel
- [x] Detect and parse the salt
- [x] Create an AEAD decryptor
- [x] Associate the nonce with the packet
- [x] Decrypt the payload
- [x] Setup a FSM to specify the type of packets and call the corresponding dissectors (right way?)
- [ ] Register more header fields to dissect the decrypted payload
- [ ] ...
