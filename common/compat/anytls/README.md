# AnyTLS stream concurrency compatibility

Client/session sources are copied from github.com/anytls/sing-anytls v0.0.11.
`UPSTREAM.json` records original file hashes; the upstream license is retained.
Padding, pipe, skiplist and util continue to use the same pinned public module.

The upstream stream's `dieErr` interface was read by application Read/Write
while the session receive goroutine wrote it on FIN. Publish the immutable
close error through an atomic pointer. Frame layout, padding and session pool
behavior are unchanged. Both server and outbound use the same fixed stream
implementation, including the existing outbound metadata rewrite.

The private inbound service retains its earlier FIN/error cleanup and dynamic
user/lifecycle changes. Independent public-client wire tests run normally;
race tests use this fixed client to avoid attributing the public client's own
close race to the Xray server.
