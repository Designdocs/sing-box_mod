# Fork notes — read before updating the kernel

This fork (`Designdocs/sing-box_mod`, branch `dev-next`) carries the private
Naive feature on top of `upstream` (`wyx2685/sing-box_mod`, itself a fork of
`SagerNet/sing-box`). It also retains the AnyTLS lifecycle fixes described
below. An upstream merge that loses the Naive feature will silently break the ArtstationX browser extension: the extension
keeps "connecting" and then rolls back to a direct connection, because its
tunnel verification never succeeds.

## What the feature is

The `naive` inbound serves **two kinds of client on one port with one user
list**, told apart by the naive `Padding` request header:

- **Padded (real naive) clients** are served exactly as upstream serves them.
  Every branch added by this fork is gated on the header being *absent*, so
  third-party naive clients (official naiveproxy, sing-box naive outbound,
  v2rayN, …) are unaffected.
- **Plain HTTPS proxy clients** (a browser, `curl -x https://…`) get a
  standard RFC 9110 forward proxy: CONNECT tunnels with no padding frames,
  absolute-URI forwarding for `http://` origins, Basic auth against the same
  users.

Plain clients are additionally **probe-resistant**: an unauthenticated plain
request is answered `404` with no challenge, CONNECT included, so a scanner
without credentials sees an empty web server and never learns a proxy is
there. The single exception is the client's own **probe host**:

```
first 16 hex chars of sha256("<username>:<password>") + ".invalid"
```

A request for it earns the `407 Basic` challenge a browser needs before it
will ever send credentials; once authenticated it is answered `204` and is
never routed. The browser primes its credential cache with exactly one such
request and then sends `Proxy-Authorization` pre-emptively on every CONNECT.

## Files that carry it

| File | State |
| --- | --- |
| `protocol/naive/probe_host.go` | **new** — probe-host derivation and index |
| `protocol/naive/inbound_plain.go` | **new** — plain-client proxy request handling |
| `protocol/naive/inbound_plain_test.go` | **new** — the whole safety net |
| `protocol/naive/inbound.go` | **modified** — `ServeHTTP` dispatch, `probeHosts` field |
| `protocol/naive/inbound_conn.go` | **modified** — plain/padded constructors and unconditional HTTP/2 flushing |

The two *modified* files are the only ones an upstream merge can conflict on.
Never resolve such a conflict by taking upstream's side wholesale: that
deletes the dispatch and the `padded` parameter while the new files keep
compiling against them, and the build breaks in a way that looks unrelated.

## Updating the kernel

1. `git fetch upstream && git merge upstream/dev-next` (or rebase).
2. Resolve conflicts in `inbound.go` / `inbound_conn.go` by **keeping both
   sides**: upstream's naive changes plus this fork's plain-client branches.
3. Run the safety net — it is the whole verification, since Actions are
   disabled on this fork to save runner minutes:

   ```
   GOEXPERIMENT=jsonv2 go test -tags "sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -p 1 -count=1 ./protocol/naive/
   ```

   All tests must pass. Two of them (`TestNaiveClientReachingAProbeHostStillGetsTheTunnel`,
   `TestNaiveClientWithoutCredentialsIsStillDroppedSilently`) exist purely to
   prove the naive path is untouched; if they fail, the merge changed
   behaviour for third-party naive clients.
4. Re-pin N2X (`V2bX后端备份/N2X`) to the new commit and rebuild:

   ```
   GOPROXY=direct go mod edit -replace github.com/sagernet/sing-box=github.com/Designdocs/sing-box_mod@<commit>
   GOPROXY=direct go mod tidy
   ```

   Then redeploy the nodes — a node running an older build has none of this.

## Cross-repo contract: do not change the derivation

`probeHostFor` is duplicated, by necessity, in the browser extension at
`X-APP/browser-extension/src/core/proxy/probe_host.js`. The two must agree
exactly or no browser can ever authenticate. Both sides pin the same vector:

```
user:secret -> 92592125f3859823.invalid
```

Server side that is `TestProbeHostDerivationIsPinned`. Changing the hash,
the truncation length or the suffix is a protocol break that requires
shipping both sides together.

## Official stable migration (2026-10-26)

The fork now merges official SagerNet/sing-box v1.14.4 at
`c005f35300ce76427dc285481ec5695f5b179cd2`, preserving the previous fork
history (including `77c9325` and the AnyTLS memory fixes in `3686e55b`).
The configured wyx2685 upstream remains frozen at `8d054dcd`.

Upstream's Scope lifecycle owns each dynamic inbound through a separate
cancellable scope. Remove closes that scope; failed replacement preserves
the existing node, and removed scopes do not accumulate in the box cleanup
list. Naive continues to rebuild on user changes, including closing hijacked
HTTP/1 tunnels. Its probe-host derivation, plain/padded dispatch, buffered
hijack data and HTTP/2 flush behavior are pinned by the existing tests.

N2X per-node inbound sniff, destination override, domain strategy and UDP
domain-unmapping options retain their previous pre-routing execution path,
with an end-to-end sniff/resolve/buffered-request regression.

Runtime user changes publish immutable authentication snapshots. Each routed
TCP/UDP session carries a credential identity rather than a mutable list
index, passes a revocation gate, and closes when that identity is removed.
VMess keeps its replay filter across user changes and can start refreshing
legacy keys when a legacy user is added after startup.

`internal/compat/UPSTREAMS.md` records the minimal source compatibility copies
for services whose upstream authentication maps assume startup-only updates.
Their wire formats remain upstream's; N2X interoperability tests use the public
upstream clients. Vision TLS field pointers retain allocation provenance via
`unsafe.Add`, validated under race/checkptr. The unchanged public upstream
Vision client still needs its wire test outside race/checkptr.

The AnyTLS session/failed-stream cleanup is retained with an idempotent close
and the new Scope entry point. REALITY now follows official v1.14.4's utls
backend, retains Xver and original base64 keys/short IDs, and is exercised by
real VLESS/Vision, Trojan and AnyTLS handshakes. Xray's local TLS bridge adds
the shared sing interface's handshake-timeout accessors.

Local integration requires Go 1.27.3, GOEXPERIMENT=jsonv2 and N2X's go.work.
Published remote module pins remain a separate release step; do not discard
this workspace or build with GOWORK=off expecting these local changes.
