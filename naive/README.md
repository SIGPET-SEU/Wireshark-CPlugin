# NaiveProxy dissector

This Wireshark 4.4 plugin recognizes NaiveProxy from the decoded HTTP/2 request
structure: `CONNECT`, a valid `-connect-authority`, and the protocol's mandatory
randomized `padding` header. It does not bind NaiveProxy to a port.

For each HTTP/2 stream it removes the first eight Naive padding frames in each
direction, reassembles TLS records across DATA frames, and invokes the stock TLS
dissector in an isolated conversation. With secrets for both layers, HTTPS is
shown as `TCP -> TLS -> HTTP/2 -> NaiveProxy -> TLS -> HTTP/1.1 or HTTP/2`.

The plugin deliberately does not display `Proxy-Authorization`. Its supported
scope is TCP tunnelling over HTTP/2; QUIC/HTTP/3 and generic non-TLS tunneled
protocol dissection are outside the initial research scope.
