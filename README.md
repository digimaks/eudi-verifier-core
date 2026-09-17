# eudi-verifier-core

The **wallet-facing** service of an EU Digital Identity Wallet **Relying Party (Verifier)** — the OpenID4VP 1.0 endpoint a wallet actually talks to. It serves the signed Request Object, accepts the wallet's presentation response, runs the **ten-step verification pipeline** over it, and forwards the verified result to whoever requested the presentation — then deletes every trace of the attribute values.

The same binary runs in two deployment shapes, chosen entirely by **configuration** (there is no dual-mode code):

- **Standalone Relying Party** — the operator *is* the RP: one registration identity, one access certificate, one registered client (itself).
- **Relying Party Intermediary** (ARF Topic 52) — the operator verifies on behalf of many onboarded RPs; each session carries the specific client's registration data so the wallet shows the end user *which* client is asking.

eudi-verifier-core itself is agnostic to which mode it is in — it verifies whatever session it is handed. Attribute values are **forwarded once, then deleted**: they never touch PostgreSQL and never appear in a log, trace, metric, or error message (GDPR / data minimisation).

Its HTTP surface is OpenID4VP-shaped for wallets, plus a token-guarded, cluster-internal session API that a session-authoring service (e.g. a management API) calls to create verification sessions. It renders no human UI.

---

## Where it sits

`eudi-verifier-core` is one service in a small set. It is the only one a wallet ever reaches. It reads a warm trust cache maintained by a background worker, is driven by a session-authoring API (which owns the tenant relationship and result delivery), and shares one Valkey and one PostgreSQL with its siblings. The diagram below is the full intermediary deployment; in standalone-RP mode the "Relying Party backend" and the authoring API collapse into the operator's own system.

The client gets the verified result from the session/management API in either of two ways — it **polls** the API for the session result (always available), and/or the API **pushes** a signed webhook (optional, if the client configured one). `eudi-verifier-core` is agnostic to this: it only writes the encrypted result to the handoff queue; the management API owns both delivery paths.

```mermaid
flowchart LR
    Wallet["EUDI Wallet<br/>(holder's device)"]

    subgraph Fleet["verifier deployment"]
        direction TB
        MA["session/management API<br/>tenant API · result poll + webhooks"]
        VC["eudi-verifier-core<br/>(this service)"]
        TCW["trust-cache worker<br/>keeps the cache warm"]
        VK[(Valkey<br/>sessions · handoff queue · trust cache)]
        PG[(PostgreSQL<br/>session metadata + reports<br/>— NO attribute values)]
    end

    TA["Trust-anchor / Trust List service<br/>(external)"]
    RP["Relying Party backend"]

    RP -- "create session (REST)" --> MA
    MA -- "POST /internal/v1/sessions" --> VC
    Wallet -- "GET request.jwt<br/>POST response" --> VC
    VC -- "read-only" --> VK
    VC -- "procedures only" --> PG
    MA -- "consume handoff queue<br/>+ redeem response_code" --> VK
    RP -- "poll for result (GET)" --> MA
    MA -. "signed webhook — optional" .-> RP
    TCW -- "materialize anchors + status lists" --> VK
    TA --> TCW
```

Division of labour: the session/management API owns the tenant relationship, session *authoring*, result delivery (client polling plus optional webhook push + retries), and rate limiting. `eudi-verifier-core` owns everything the *wallet* touches — request signing, response processing, and the cryptographic verdict. The two meet at the token-guarded `POST /internal/v1/sessions` transport and the encrypted Valkey handoff queue.

---

## HTTP surface

Wallet endpoints render **OpenID4VP error shapes**, never a generic problem envelope — the wallet boundary is not the public-error boundary. Everything else uses the internal problem envelope.

| Method + path | Purpose | Notes |
|---|---|---|
| `GET /wallet/{sessionID}/request.jwt` | Serve the signed Request Object (JAR) by reference | `application/oauth-authz-req+jwt`; **single-use** (RFC 9101, OpenID4VP §5.10). `{sessionID}` here is the real engine-minted id |
| `POST /wallet/{sessionID}/response` | `direct_post.jwt` response endpoint → `{redirect_uri}` JSON | One-time consume → decrypt → ten-step pipeline (OpenID4VP §8.2). `{sessionID}` here is an **opaque routing token**, not the real id (see [Routing tokens](#routing-tokens-no-session-id-in-a-url)) |
| `GET /.well-known/verifier-jwks.json` | Operator public keys | The `webhook-signing` EC public key, so consumers can verify the detached-JWS webhook (`Cache-Control: max-age=300`) |
| `GET /healthz` | Liveness | 200 whenever the process is up |
| `GET /readyz` | Readiness (fail-closed) | 503 with the failing components listed if Postgres, Valkey, required issuer-anchor freshness, or the upstream trust snapshot is degraded |
| `GET /metrics` | Prometheus / VictoriaMetrics registry | |
| `POST /internal/v1/sessions` | Cluster-internal session create | **Only registered when an internal API token is configured** — fail closed by absence. Bearer auth, hashed + constant-time |
| `DELETE /internal/v1/sessions/{sessionID}` | Kill the wallet-facing Valkey session | Idempotent (always 204) |
| `GET /internal/v1/sessions/{sessionID}/report` | The stored verification report, verbatim | Same bearer gate. The only surface carrying a failed check's own account of WHY it failed: the wallet gets a public error code, the client-facing report carries the code without the detail. Cluster-internal on purpose — the detail names our own infrastructure (list addresses, library error text), which is for operators, not for a relying party. A session with no report is 404, never an empty 200 |
| `GET /internal/v1/trust-status` | Trust-identity diagnostics | Same bearer gate. Names the trust snapshot this verifier enforces — overall (`snapshotId`, LOTL sequence, upstream-stale, pending-bootstrap) and per anchor type (`snapshotId`, `fetchedAt`, `validUntil`, `fresh`) — read from the same cache records `/readyz` consumes. An identity the cache cannot provide is absent from the body, never guessed. Deliberately a route, not health (identity would grow the health body with the trust set) and not metrics (an id must never be a metric label) |

The three presentation flows — **same-device**, **cross-device**, and **DCAPI** (Digital Credentials API) — all resolve to the same `POST .../response` pipeline. DCAPI differs only in delivery: its request is an embedded signed `dc_api.jwt` member (never a `request_uri`), and its session carries no `response_uri` claim at all — the response returns via the browser, correlated by origin + nonce (OpenID4VP Annex A).

`expected_origins` is validated **in the route**, alongside the DCQL query and for the same reason — the caller must be able to tell a bad request from a broken service. It is required and non-empty for DCAPI, rejected outright for the redirect-based flows (where it means nothing and silently accepting it would suggest an origin restriction that is not in force), and every entry must be a bare web origin: `https`, a host, and no path, query, fragment or userinfo. An absent list is a missing-parameter error (400); a malformed one is an invalid-parameter error (422). Both are plain built-in parameter errors rather than new taxonomy codes, matching the query check above them. The engine enforces the same rules again when it assembles the session — the route check exists so the failure is *classified*, not so the engine can stop checking.

The response endpoint returned to the caller is an opaque routing token minted before the session id exists, so it can be published to a browser page without exposing the engine's session identifier.

---

## Architecture

One application object (`App` in [`app.go`](app.go)) wires every dependency at startup and **fails closed** on any misconfiguration — a broken access-certificate profile, an unreadable key, or a bad credential-trust map stops the process from starting. The composed libraries are all framework-free `go-eudi-*` modules; cryptographic policy (allowed curves and algorithms) lives only in the crypto library — there are no algorithm string literals anywhere else.

```mermaid
flowchart TB
    subgraph App["App (app.go) — built once by New()"]
        direction TB
        Init["init(): setup → redaction → Valkey/PG →<br/>keys → access cert → OpenID4VP engine → verifiers →<br/>pipeline → handoff sink → anchor source"]
    end

    subgraph Routes["routes/ — HTTP handlers"]
        W["wallet.go<br/>request.jwt · response"]
        I["internal.go<br/>/internal/v1/sessions"]
        H["health · readyz · jwks"]
    end

    subgraph Libs["composed go-eudi-* libraries (framework-free)"]
        ENG["OpenID4VP Engine<br/>(stateless)"]
        SD["SD-JWT VC Verifier"]
        MD["mdoc Verifier"]
        SL["status-list Checker"]
        TR["trust AnchorSource"]
        RC["access-cert profile"]
        CR["crypto<br/>KeyProvider + policy"]
    end

    subgraph Pipe["internal/pipeline — ten ordered checks"]
        P["Engine.Run()<br/>short-circuits on first fail"]
    end

    subgraph State["state (shared)"]
        VK[(Valkey<br/>sessions · tokens · handoff · trust cache)]
        PG[(PostgreSQL<br/>session metadata + reports)]
    end

    Routes --> App
    W -- "Process()" --> P
    I -- "Creator.Create" --> ENG
    P --> SD & MD & SL & TR
    App --> ENG & SD & MD & SL & TR & RC & CR
    App -- "sessions · handoff queue · status-refs · trust reads" --> VK
    App -- "session metadata + reports (procedures only)" --> PG
```

---

## Session lifecycle, end to end

A cross-device flow, from session creation to deleted result. Same-device adds a `redirect_uri` back to the browser and mints an OpenID4VP §8.2 `response_code`; DCAPI returns via the browser instead of a `response_uri`.

```mermaid
sequenceDiagram
    participant MA as management API
    participant VC as eudi-verifier-core
    participant ENG as OpenID4VP Engine
    participant VK as Valkey
    participant PG as PostgreSQL
    participant W as Wallet
    participant RP as Relying Party

    MA->>VC: POST /internal/v1/sessions (bearer)
    VC->>VC: Creator.Create — mint opaque routing token
    VC->>+ENG: engine.NewSession(RequestSpec)
    ENG-->>-VC: sess (engine-minted ID) + invocation
    VC->>VK: SET vc:session:{id} (protocol only)<br/>SET vc:respondtoken:{token} → {id}
    VC->>PG: session.create (metadata, claim-name domain)
    VC-->>MA: 201 {request_uri, response_uri, invocation, expires_at}

    Note over W: wallet opens the QR / universal link
    W->>VC: GET /wallet/{id}/request.jwt
    VC->>VK: MarkRequestObjectServed (single-use)
    VC-->>W: signed Request Object (JAR, x5c = access-cert chain)

    W->>VC: POST /wallet/{token}/response (direct_post.jwt)
    VC->>VK: resolve token → {id}, ConsumeOnce (atomic)
    VC->>VC: run ten-step pipeline
    alt verified
        VC->>PG: SaveReport (claim NAMES only) · SetStatus verified
        VC->>VK: SET vc:handoff:payload (result JWE)<br/> LPUSH queue (only if webhook)
        VC->>VC: zero attribute values in memory
        VC-->>W: {redirect_uri?} (same-device) / {}
    else failed
        VC->>PG: SaveReport · SetStatus failed
        VC->>VK: DELETE session (forward report-only, no values)
        VC-->>W: OpenID4VP error shape
    end

    MA->>VK: consume vc:handoff:queue (decrypt result)
    alt webhook configured
        MA-->>RP: signed webhook (result JWE)
    else client polls (always available)
        RP->>MA: GET /sessions/{id} → result
    end
```

---

## The ten-step verification pipeline

`internal/pipeline` is an **ordered, short-circuiting** chain (ARF §6.6.3). Every step implements one interface; every *executed* step writes one row to the persisted verification report; the first failure stops the chain and records exactly which step failed and why. A skipped check is always *visible* in the report, never silently passed.

```go
type Check interface {
    Name() string // matches the verification-report check enum
    Run(ctx context.Context, pc *PipelineContext) (CheckResult, error)
}
```

```mermaid
flowchart TB
    S(["POST .../response<br/>consumed once"]) --> C1

    C1["1 · response_integrity<br/>ProcessResponse (decrypt, vp_token, state)"]
    C2["2 · parse<br/>SD-JWT / mdoc structural parse"]
    C3["3 · issuer_authenticity<br/>resolve issuer key + verify signature"]
    C4["4 · data_integrity<br/>digests / disclosures"]
    C5["5 · revocation<br/>status list (per policy)"]
    C6["6 · device_binding<br/>KB-JWT / DeviceAuth"]
    C7["7 · user_binding<br/>trust-wallet-auth (requires 6)"]
    C8["8 · query_fulfilment<br/>DCQL match"]
    C9["9 · combined_checks<br/>per-credential independence"]
    C10["10 · assemble_forward<br/>result → handoff, then DELETE"]

    C1 --> C2 --> C3 --> C4 --> C5 --> C6 --> C7 --> C8 --> C9 --> C10
    C10 --> OK(["verified → report + encrypted handoff"])

    C1 & C2 & C3 & C4 & C5 & C6 & C7 & C8 & C9 -. "first fail<br/>short-circuits" .-> F(["failed → report-only<br/>(no values), session deleted"])
```

| # | Check enum | What it verifies | Spec anchor |
|---|---|---|---|
| 1 | `response_integrity` | JWE decrypt, `vp_token`, state binding | OpenID4VP §8.2 |
| 2 | `parse` | SD-JWT VC / mdoc structural parse | credential formats |
| 3 | `issuer_authenticity` | issuer key resolution + signature verify | ARF §6.6.3.6 |
| 4 | `data_integrity` | digest / disclosure integrity | ISO 18013-5 §9.1.2 / SD-JWT |
| 5 | `revocation` | status-list check per client policy | ARF §6.6.3.7 |
| 6 | `device_binding` | KB-JWT (SD-JWT) / DeviceAuth (mdoc) | ARF §6.6.3.8 |
| 7 | `user_binding` | trust-wallet-auth mode (asserts 6 passed) | ARF §6.6.3.9 |
| 8 | `query_fulfilment` | DCQL match | OpenID4VP §6 |
| 9 | `combined_checks` | per-credential independence | ARF Topic 18 |
| 10 | `assemble_forward` | result → handoff queue, then delete | — |

**One verify call, attributed to the right step.** The SD-JWT and mdoc verifiers each do structural parse + digest integrity + holder/device binding in a *single* call — they expose no per-step boundary. `internal/pipeline/errclass.go` is the one table that maps every typed error from both libraries (via `errors.Is`) back to the step that owns it: parse errors → step 2, digest/disclosure/collision → step 4, binding-class errors → step 6, credential validity-window → step 3, a certificate outside its own validity window (the signer's, or one on its path) → step 3 as `err:credential:issuer-cert-expired`, else issuer-untrusted → step 3. There is no second verify call anywhere. Each step is proven to fail *alone* by the fault-injection matrix in [`routes/matrix_test.go`](routes/matrix_test.go), driven by the synthetic-PKI test wallet.

### Per-client policy (steps 5 / 6)

Policy is a snapshot stored on the session at creation and **echoed into the report**, so every deviation from the fail-closed default is auditable. Each relaxation is an explicit `*bool` — `nil` means the safe default.

| Field | Default | Effect when set false |
|---|---|---|
| `revocation_fail_closed` | `true` | An unresolvable revocation status is *not* fatal (recorded as `skipped`, never silently passed) |
| `short_lived_exemption` | `true` | Credentials with < 24h validity may skip revocation (ARF §6.6.3.7) |
| `require_device_binding_sdjwt` | `true` | SD-JWT VC KB-JWT binding not required (ARF §6.6.3.8) |

---

## Routing tokens: no session id in a URL

The OpenID4VP engine mints the session ID internally and validates the response URL *before* that id exists — so the response URL can never contain the real id. `sessions.Creator` mints its own opaque token first, builds the response URL from that token, then indexes `vc:respondtoken:{token} → session id` once the engine returns. The response handler resolves token → id before touching any other session state. The result: a real session id never appears in a wallet-facing URL, and the response endpoint suppresses request logging where ids would otherwise reach a log line.

```mermaid
flowchart LR
    Create["Creator.Create"] -->|"mint token"| T["opaque routing token"]
    T -->|"response_uri built from token"| ENG["engine.NewSession"]
    ENG -->|"returns real session ID"| IDX["SET vc:respondtoken:{token} → {id}"]
    W["Wallet POST /wallet/{token}/response"] -->|"resolve"| IDX
    IDX -->|"real id"| PIPE["pipeline over real session"]
```

---

## Forward-and-delete: the result handoff

Verified attribute values exist only transiently in `eudi-verifier-core` memory and only inside one **JWE** (ECDH-ES + A256GCM, encrypted to the operator handoff key) buffered in Valkey under a hard TTL. The payload is always buffered so the result can be polled; the delivery-queue entry (`vc:handoff:queue`) that drives the webhook push is written **only** when the session has a webhook configured (poll-only sessions skip it). The consuming service is the sole reader; it hands the result to the client — served to a **poll** request and/or pushed as an **optional signed webhook** (with retries). `eudi-verifier-core` never retries, never reads its own payloads back, and **never writes an attribute value to PostgreSQL**. After handoff (success *or* failure), attribute-carrying memory is best-effort zeroed on every return path.

```mermaid
flowchart LR
    P["pipeline step 10<br/>Finalize"] -->|"encrypt result → JWE"| Q["SET vc:handoff:payload:{id} (always)<br/>LPUSH vc:handoff:queue (only if webhook)<br/>(TTL ≤ 24h hard cap)"]
    P -->|"defer Zero()"| Z["zero values in memory<br/>(every return path)"]
    Q --> MA["consuming service<br/>reads once → poll and/or webhook"]
    P -->|"same-device success only"| SC["SET vc:respcode:{code} → {id}<br/>(§8.2 redemption)"]
```

Disposal is flow- and outcome-aware: a **same-device success** re-saves the (protocol-only) session so the consuming service can redeem the `response_code` — without touching the sticky `:consumed` marker, so replay is still rejected at `ConsumeOnce` (OpenID4VP §12.1). Every other case (cross-device / DCAPI success, and *any* failure) deletes the session outright. The verified-deletion guarantee is enforced by [`routes/deletion_test.go`](routes/deletion_test.go), which greps a real in-memory Valkey + Postgres for a canary claim value after handoff.

---

## Trust and fail-closed behaviour

Trust anchors and status lists come **only** through the Valkey cache that the trust-cache worker keeps warm — never the system cert pool, never inline PEM, never a direct trust-list fetch. `internal/anchors` bridges that cache to the trust `AnchorSource`; `internal/statuscache` bridges it to the status-list checker. Both fail closed:

```mermaid
flowchart TD
    R["revocation / issuer check"] --> Q{"cache fresh?"}
    Q -->|"fresh anchor + status"| V["verify against pinned chain"]
    Q -->|"key expired / absent"| A["err:trust:anchor-unavailable (503)"]
    Q -->|"anchor type has no key<br/>for this issuer's territory"| U["err:credential:issuer-untrusted (422)"]
    V -->|"chain ok"| PASS["pass"]
    V -->|"chain broken"| U
```

`/readyz` reports degraded (503) when Postgres or Valkey is unreachable, when any **required issuer anchor type** (`pid_provider`, `qeaa_provider`, `pub_eaa_provider`, `eaa_provider`) is stale, or when the upstream trust snapshot signals a pending bootstrap. An anchor-grace setting adds tolerance to the readiness check **only** — never to a verification decision.

**Credential-type → anchor classification is config-driven.** A built-in default maps each `vct` / `docType` to its issuer anchor types (PID → `pid_provider`, else `qeaa`/`pub_eaa`/`eaa`); status-signer types are derived from them. Override or extend it at deploy time with a credential-trust JSON setting (parsed once at startup; bad JSON fails startup). Onboarding a new credential type is configuration, not a recompile.

---

## State and data model

**No attribute value is ever persisted.** PostgreSQL holds session metadata and verification reports in the claim-**name**-only domain, accessed exclusively through `SECURITY DEFINER` procedures via a JSONB envelope — the service never touches tables directly, and its database role has `EXECUTE`-only grants.

Valkey keys written / read by this service (all TTL-bounded — no cache-forever key exists). When `VALKEY_KEY_PREFIX` is set every key below is stored as `<prefix>:<key>`; the names themselves are the contract shared with the worker and the management API and never change:

| Key | Value | Role |
|---|---|---|
| `vc:session:{id}` | session JSON (nonce/state/query/ephemeral key — **protocol only**) | write |
| `vc:session:{id}:served` | request-object single-use marker | write |
| `vc:session:{id}:consumed` | sticky one-time-consume marker (§12.1 replay guard) | write |
| `vc:respondtoken:{token}` | → real session id (routing-token index) | write |
| `vc:respcode:{code}` | → session id (§8.2 response_code; consumer GETDELs once) | write |
| `vc:handoff:queue` + `vc:handoff:payload:{id}` | encrypted result JWE (payload always; queue entry only if a webhook is configured) | write |
| `trust:statuslist:refs` | ZSET of referenced status-list URIs (popularity signal) | write (worker prefetches from it) |
| `trust:anchors:*` · `trust:freshness:*` · `trust:statuslist:*` | trust anchors, freshness, cached status lists | **read-only** (written by the worker) |

---

## Keys

Three operator keys, supplied as PEM files, referenced everywhere by fixed key IDs:

| Key ID | Purpose |
|---|---|
| `request-signing` | Request Object (JAR) signing; its public key **must** equal the access-certificate leaf's key, and the configured client DNS name must be a SAN dNSName of that leaf |
| `handoff-enc` | Encrypts the result JWE to the operator handoff key |
| `webhook-signing` | Detached-JWS webhook signature; published at `/.well-known/verifier-jwks.json` |

The access-certificate chain is profile-validated once at startup (ETSI TS 119 411-8 §4.2.2); a broken profile stops the process.

### Key generation

`handoff-enc` is a self-generated operator key — no CA, no CSR. It is an **EC P-256** key (the HAIP 1.0 / ECCG baseline) used for `ECDH-ES` key agreement. `openssl genpkey` emits a PKCS#8 PEM, which the key loader accepts (a SEC1 `-----BEGIN EC PRIVATE KEY-----` file works too); a non-EC or non-allow-listed curve is rejected at startup, fail-closed.

```bash
# handoff-enc — EC P-256 private key, PKCS#8 PEM.
# Point HANDOFF_ENC_KEY_FILE at this file.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out handoff-enc.key.pem
```

> **Note — this key is shared with `eudi-api-management`.** It is one operator secret, not two. Generate it **once** and mount the **same** file into both services: `eudi-verifier-core` encrypts the result JWE to it, and `eudi-api-management` decrypts with it. If the two files differ, decryption fails closed — an undecryptable payload is an error, never an empty success. Keep the file out of version control and supply it as a mounted secret.

---

## Configuration

Standard fleet env (`SERVER_URLS`, `SERVICE_NAME`, `ENVIRONMENT`, `LOG_*`, `METRICS_ENABLED`, `OTEL_*`) comes from the shared base configuration, plus:

| Env var | Default | Meaning |
|---|---|---|
| `POSTGRES_DSN` | — (required) | PostgreSQL DSN; connects as the EXECUTE-only `verifier_core_public` role. Secret: supports the `POSTGRES_DSN_FILE` convention (an explicit plain `POSTGRES_DSN` still overrides it) |
| `VALKEY_URL` | — (required) | Shared Valkey/Redis URL: `redis://` or `rediss://` (TLS), optional `user[:password]@`, `/N` database index, `?skip_verify=true` on `rediss://` |
| `VALKEY_PASSWORD` | *(unset)* | Password for the Valkey user; overrides one embedded in `VALKEY_URL`. Also readable via the `VALKEY_PASSWORD_FILE` indirection so a platform can mount it. Secret — never logged |
| `VALKEY_KEY_PREFIX` | *(unset)* | Prepended as `<prefix>:` to every Valkey key this service reads or writes (a trailing `:` in the value is tolerated). Required when the instance confines the user's ACL to a key pattern; **must equal the trust-cache worker's and the management API's**, or the trust keys read as absent and `/readyz` stays not-ready |
| `PUBLIC_BASE_URL` | — (required) | Externally reachable base of this service — `request_uri` / `response_uri` are minted under it |
| `CLIENT_DNS_NAME` | — (required) | FQDN; must be a SAN dNSName of the access-certificate leaf (`x509_san_dns` client id) |
| `UNIVERSAL_LINK_BASE` | — (required) | Base for the wallet universal-link invocation |
| `REQUEST_SIGNING_KEY_FILE` | — (required) | PEM path — JAR signing key (must match the access-cert leaf) |
| `HANDOFF_ENC_KEY_FILE` | — (required) | PEM path — result-JWE encryption key |
| `WEBHOOK_SIGNING_KEY_FILE` | — (required) | PEM path — webhook signing key |
| `WRPAC_CHAIN_FILE` | — (required) | PEM path — access-certificate chain (leaf first) |
| `SESSION_TTL` | `5m` | Session lifetime |
| `RESPONSE_CODE_TTL` | `5m` | §8.2 `response_code` redemption window |
| `HANDOFF_TTL` | `6h` | Result-JWE TTL — **clamped to a 24h hard cap** |
| `MAX_RESPONSE_BODY_BYTES` | `1 MiB` | Response body cap (checked before any parse) |
| `ANCHOR_GRACE` | `0` | Extra tolerance on anchor `valid_until` for `/readyz` **only** — never for verification |
| `CREDENTIAL_TRUST_JSON` | — (empty ⇒ built-in default) | Credential-type → anchor override (parsed once; bad JSON fails startup) |
| `INTERNAL_API_TOKEN` | — (empty ⇒ surface not registered) | Bearer token guarding `/internal/v1/*`; unset = the surface is absent (fail closed). Secret: supports the `INTERNAL_API_TOKEN_FILE` convention |
| `CORS_ORIGINS` | — (empty ⇒ no cross-origin caller answered) | Semicolon-separated browser origins (`scheme://host[:port]`, no path, no wildcard) allowed to call this service cross-origin. Needed **only** for the browser-mediated DC API flow, where the relying party's page posts the wallet's answer from its own origin |
| `DCAPI_REQUEST_MODE` | `signed` | Deployment ceiling on browser-based presentation requests: `signed`, `unsigned` or `both`. An unrecognised value fails startup |
| `ISSUER_VALIDITY_MODEL` | `chain` | When the issuer's certificate chain must be valid: `chain` = on the day the credential was signed (what ISO/IEC 18013-5 requires for the signer certificate, and the only value under which wallets keep working after an issuer rotates a document signer), `shell` = right now (stricter; refuses credentials signed before the last rotation). Enforced in both and not configurable: the credential's own window against now, and that the signing date falls inside the signer certificate's own window. An unrecognised value fails startup; the effective model is printed at startup |
| `RESPONSE_ENCRYPTION_CURVE` | `P-256` | Ephemeral response-encryption key curve advertised in `client_metadata` |
| `RESPONSE_ENCRYPTION_ALG` | `ECDH-ES` | JWE key-agreement algorithm advertised on the ephemeral JWK |
| `RESPONSE_ENCRYPTION_ENCVALUES` | `A128GCM` | Comma-separated `encrypted_response_enc_values_supported`. A **declaration of what this deployment accepts** — the wallet picks one from it, so a wallet implementing none of the listed values refuses the request before consent. Values outside the allow-list fail startup |

**TLS is selected by the URL scheme.** `rediss://…` connects over TLS; `redis://…` does not. `skip_verify=true` only relaxes certificate verification on a `rediss://` URL — on a `redis://` URL the client rejects it outright (`redis: unexpected option: skip_verify`) rather than silently upgrading the connection. Earlier Azugo versions did treat `skip_verify=true` as an implicit request for TLS; that side-effect is fixed from **Azugo v0.37** onwards, so a TLS endpoint must always be addressed as `rediss://`.

**Signed vs unsigned browser requests.** A signed request carries this verifier's certificate chain and registration data, so the wallet can authenticate the relying party through a trust framework on top of the web origin the browser asserts. An unsigned request carries neither — the calling origin is the whole of the verifier's identity ([OID4VP §A.2] / [OID4VP §A.3.2]). Both are permitted, and [HAIP §5.2] requires a verifier to support at least one; which one belongs in a given deployment is not a code decision. Where relying-party registration is the basis of trust — the EU wallet case — unsigned discards all of it, which is why the default is `signed`.

`DCAPI_REQUEST_MODE` is a **ceiling, not an instruction**. `signed` and `unsigned` fix the mode for every client. Only `both` consults a client's own registered choice (eudi-api-registration's `PUT /api/clients/{id}/dcapi-request-mode`), and a client that has not chosen still gets signed. So under `signed`, a client registered as unsigned is issued signed requests anyway: a per-client setting can narrow one client, never widen the deployment. The effective mode is stated in one line at startup, because under the fixed modes nothing else records it — only `both` leaves the decision in a client's stored policy where it can be read back later.

Two things hold in **both** modes, and are not part of the trade-off. The origin a response arrives from is checked against the session's expected origins by this service regardless of what the wallet was told ([OID4VP §14.9]) — an unsigned request simply never shows the wallet that list, so the wallet cannot check it too. And the Key Binding audience is the calling origin prefixed with `origin:` ([OID4VP §A.4], which states this holds "even for signed requests"), never the Client Identifier — the mdoc handover binds the same origin.

**The browser flow needs two origin lists to agree, and they answer different questions.** `CORS_ORIGINS` decides whether a browser is allowed to make the call at all — it is deployment-wide, and an origin missing from it fails in the browser with nothing in this service's logs. The client's `allowedOrigins` in the registry decides whether an origin is authorised for *that* client's session — an origin missing from it is refused here, with a named error. Keep the deployment list a superset of every registered client's origins. The allowed request header is fixed at `Content-Type` (the DC API response body is JSON) and credentials are never allowed.

`response_encryption` and `vp_formats` are config-file-only overrides (nested structs, no env binding). They default to the HAIP 1.0 / ECCG v2.0 baseline (P-256, ECDH-ES, A128GCM; ES256; COSE ES256 = -7). The engine still validates every value against the crypto allow-list at construction — any non-allow-listed value is rejected.

---

## Metrics

Served on `/metrics`. Every label value comes from a **closed set** (the check-name enum × outcome enum, or the fixed anchor-type taxonomy) — never a session id, never wallet-derived input.

| Metric | Labels | Meaning |
|---|---|---|
| `verifier_core_pipeline_check_total` | `check`, `outcome` (`pass`\|`fail`\|`skipped`) | Per-check outcome counter |
| `verifier_core_pipeline_duration_seconds` | — | Full-pipeline latency histogram |
| `verifier_core_anchor_staleness_seconds` | `type` | Seconds until each anchor type's cache expiry (negative = already stale) |

### Diagnosing a failed verification

One `warn` line per **failed** verification (never per request, and nothing on a healthy flow) names
the check that failed and its cause:

```
verification failed  check=revocation  code=err:revocation:unavailable
  cause="statuslist: status list token signature verification failed: ecdsa: verification error"
  status_list_uri=https://status.example/statuslist/lv/pid/abc123
```

The public error code covers many distinct causes — a status list that could not be fetched, one
signed by a key that does not resolve, one whose token is past its freshness window — so the cause
text is the part that says which. It is quoted from the verifying library and safe to log: the report
is value-free by construction, carrying claim names and never claim values.

The **list URI** is logged; the **entry index** inside that list never is. A list is shared by many
credentials, while the index within it identifies one, so recording it would turn a diagnostic into a
correlatable handle for a holder.

The same account is available on demand, without reading logs or the database, at
`GET /internal/v1/sessions/{sessionID}/report`.

---

## Directory layout

```
eudi-verifier-core/
├── app.go, config.go, reasons.go, redaction.go   — App container, config, error taxonomy, PII redaction
├── testing.go                                     — //go:build testhelpers test harness (TestApp, SeedTestTrust)
├── cmd/server/                                    — CLI entrypoint (web, health subcommands)
├── routes/                                        — HTTP handlers
│   ├── wallet.go        — request.jwt · response (OpenID4VP shapes)
│   ├── processor_pipeline.go — response → ten-step pipeline
│   ├── internal.go      — /internal/v1/sessions (create/delete/report, token-guarded)
│   ├── jwks.go, health.go, readyz.go             — well-known + probes
│   └── router.go        — route registration (internal surface fail-closed by absence)
└── internal/
    ├── pipeline/        — the ten ordered checks + engine, report, errclass, specrefs
    ├── sessions/        — Creator (3 stores per Create) + routing-token index
    ├── sessiondb/       — session-schema SECURITY DEFINER procedure calls
    ├── valkeystore/     — session store (single-use / one-time consume)
    ├── statuscache/     — status-list cache + ref recorder over Valkey
    ├── anchors/         — trust-cache → AnchorSource bridge (fail-closed)
    ├── policy/          — per-client verification policy snapshot
    ├── handoff/         — encrypted result queue
    ├── obs/             — pipeline metrics + per-check spans
    └── testwallet/      — synthetic-PKI fault-injecting wallet (15 fault modes)
```

---

## Development

`testing.go` is `//go:build testhelpers`-gated so the production binary's dependency closure excludes the in-memory Valkey/test dependencies. **Any** command that touches `_test.go` files must carry the tag — always use the Makefile targets, never bare `go test`:

```bash
cd eudi-verifier-core
make build        # prod build — no tag; matches the Dockerfile + shipped binary
make test         # go test -tags testhelpers -race ./...   (CI: cgo available)
make test-fast    # same, no -race (local dev without cgo)
make vet          # go vet -tags testhelpers ./...   (vet type-checks _test.go too)
make lint         # golangci-lint run --build-tags testhelpers

# Fuzz the untrusted-input parser boundary:
go test -tags testhelpers -run '^$' -fuzz '^FuzzWalletResponse$' -fuzztime 30s ./routes/
```

The unit suite runs entirely against in-process fakes: an in-memory Valkey, a fake session store for Postgres, and `internal/testwallet` (a synthetic-PKI wallet that produces both valid *and* selectively-broken presentations) as the input source — no Docker or network dependency. `TestApp` / `SeedTestTrust` build a fully wired `App` with an in-memory trust harness.

---

## Security invariants

- **No attribute value anywhere durable** — forwarded once (encrypted), then deleted; never in PostgreSQL, logs, traces, metrics, or error text. Redaction is extended before any pipeline code can log a claim.
- **Fail closed** — expired/absent anchor cache, unknown status format, unverifiable chain, or bad config all fail with a precise problem code; every relaxation is an explicit per-client policy flag, visible in the report.
- **Crypto policy centralized** — allowed curves/algorithms live only in the crypto library (ECCG allow-lists); no algorithm literals elsewhere.
- **Trust anchors only via the cache** fed by the trust-cache worker — never the system cert pool or inline PEM.
- **Untrusted-input parsers are fuzzed** and must not panic on malformed input.
- **No session id in a wallet-facing URL** (routing tokens); single-use / one-time-consume enforced atomically (OpenID4VP §5.10 / §8.2 / §12.1).

---

## Known limitations

- **Wallet-facing error granularity is deliberately coarse.** A verification that runs to a decision and refuses reaches the wallet as `400 invalid_request`, with the description distinguishing a credential the verifier will not accept (`credential not accepted`) from a response that did not hold up (`presentation could not be verified`) — enough for an operator to tell a trust-data gap from a broken presentation, without turning the endpoint into a probing oracle for *which* check failed. The precise `err:domain:reason` stays in the persisted report and the session's `failure.code`. A genuine fault of the verifier's own — unreachable trust anchors, failed result handoff, an internal pipeline error — is still `500 server_error` and leaks nothing.

- **A wallet that declines is a third outcome, not a failed presentation.** If the wallet posts an OpenID4VP error response to the response endpoint instead of a presentation, nothing was ever presented: the run is recorded as `err:presentation:wallet-declined` and the wallet is answered `400 invalid_request` with the description `wallet reported an error`. The wallet's own `error_description` — the only account of why it refused, since nothing on this side can reconstruct it — is preserved in the persisted report's check detail, capped and treated as untrusted text. It is not echoed back to the wallet, which already knows what it sent. Reporting a decline as `presentation could not be verified` describes something that did not happen, and hides the one fact that explains it.
- **`vp_formats` / `response_encryption`** are config-file-only (no per-leaf env binding yet).
- The DCAPI response path shares the already-fuzzed OpenID4VP parser; a dedicated DCAPI fuzz seed is a nice-to-have, and the HTTP server's max request body size is not yet aligned with `MAX_RESPONSE_BODY_BYTES`.
- **Wallet-attestation verification** (WIA/KA/WUA) is out of scope by ARF design (§6.6.3.11): the RP cannot directly verify the wallet unit and relies on the issuer having done so at issuance; wallet-unit revocation is transitive via credential revocation (step 5).
- **Single-node key/value store only — no Redis Cluster.** The service connects to one Redis-protocol endpoint (`VALKEY_URL`) with the standard single-node go-redis client and uses only ordinary commands (`SET`/`GET`/`SETNX`/`GETDEL`/`LPUSH`/`ZADD`/`EXPIRE`) — no Valkey-specific commands, no cross-slot transactions or Lua. So a **non-clustered Redis OSS** instance works interchangeably with Valkey; the `VALKEY_URL` name is historical. **Redis Cluster is not supported** (the client is not cluster-aware, and the fleet-shared cache written by the trust-cache worker assumes single-slot keys).

## License

EUPL-1.2 — see [`LICENSE`](LICENSE).
