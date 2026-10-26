# Server compatibility sources

These packages preserve the upstream wire implementations while adding safe
runtime user updates required by N2X. The clients continue to use upstream
modules; no client protocol or authentication format changes.

- singvmess: github.com/sagernet/sing-vmess v0.2.9-0.20261019223527-a0c58542bd9d
- singquic: hysteria, hysteria2 and tuic from github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4

Licenses are preserved beside the sources. Local changes are authentication
snapshot publication, concurrent user revocation support, VMess legacy-user
refresh lifecycle, and allocation-safe Vision TLS buffer field pointers. Keep those patches
separate from future upstream wire changes and retain upstream tests.
