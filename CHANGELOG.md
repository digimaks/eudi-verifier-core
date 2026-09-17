# Changelog

Notable changes, newest first. Releases are git tags; this file says what each tag contains.

## v0.1.0 — initial public release

**The wallet-facing OpenID4VP verifier: it serves the signed request, receives the wallet's response, and runs the ten-step verification pipeline that produces the verdict.**

It speaks HTTPS in-process, because OpenID4VP requires a real `https://` request URI. It verifies
mdoc/mDL (ISO/IEC 18013-5) and SD-JWT VC credentials: structural parse, issuer authenticity against a
trust anchor, digest integrity, revocation, device binding, User binding, query fulfilment. The
verified result is handed on encrypted, and the attribute values are deleted here — this service never
becomes the place where wallet attributes accumulate.

`SPECREFS.md` states which edition of each specification the clause numbers in the source refer to.

### Running it

The image entrypoint is `["/server", "web"]`, with `["/server", "health"]` as the healthcheck
command — a compose or orchestrator file that also passes `command: ["web"]` would append a second
argument. Every setting is an environment variable with a safe default where one is possible; the
README lists them, and any secret can be supplied as `<NAME>_FILE` pointing at a mounted file instead.

### What it needs

Go **1.27.0** to build. Libraries at this release:

`go-oid4vp` v0.0.8 · `go-mdoc` v0.1.2 · `go-sdjwt` v0.0.8 · `go-dcql` v0.0.2 ·
`go-statuslist` v0.1.5 · `go-eudi-crypto` v0.0.8 · `go-eudi-rpcert` v0.0.6 · `go-eudi-trust` v0.1.2 ·
`go-verifier-helpers` v0.0.4 · `go-platform-kit` v1.11.3 · `azugo.io/azugo` + `azugo.io/core` v0.38.1
