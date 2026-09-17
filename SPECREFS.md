# Pinned specification versions

Every normative citation in this repository is written in the form `[source §clause]`. This
file says which edition of each source those clause numbers refer to, so a reader can open the
right document. Where a specification is paywalled or still a draft, that is stated rather
than glossed.

| Spec | Version pinned | Sections used |
|---|---|---|
| OpenID for Verifiable Presentations (OpenID4VP) | 1.0 (final) — <https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html> | §5 (authorization request — request object by value or by reference), §5.2 (`nonce`: a fresh, cryptographically random value with sufficient entropy per request), §5.9.3 (the `x509_san_dns` Client Identifier Prefix), §5.10 (Request URI method `post`), §5.10.1 (the Request URI **response** content type `application/oauth-authz-req+jwt`), §6 and §6.1 (DCQL query; `require_cryptographic_holder_binding`), §7 (claims path pointer), §8.1 (`vp_token` keyed by credential query id), §8.2 (response mode `direct_post`; the `redirect_uri` return parameter and the response code it carries), §8.3 (encrypted responses, `direct_post.jwt`), §13.3 (the response-endpoint / frontend design this service implements), §14.2 (session fixation — the Response URI MUST carry a fresh Response Code into the redirect and MUST require the frontend to present it), §14.9 (the Verifier MUST NOT rely on the Wallet to enforce its constraints and MUST perform its own checks — the basis for checking the response origin ourselves), §A and §A.2 / §A.3.1 / §A.3.2 (W3C Digital Credentials API; signed and unsigned requests), §A.4 (key binding audience is the calling origin, prefixed `origin:`, even for signed requests), §B.2 (mdoc session transcript handovers) |
| EUDI Wallet Architecture and Reference Framework (ARF) | **2.9** — the edition these citations were written against. Release 3.0.0 is a major version and a text-level re-check is outstanding; see the note below. <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework> | §6.6.3 (the relying-party verification sequence this service implements as a ten-step pipeline), §6.6.3.6 (issuer authenticity — signature and chaining to a trust anchor obtained from a LoTE or Trusted List; the clause does **not** cover the credential's validity window), §6.6.3.7 (revocation, and the exemption for short-lived attestations), §6.6.3.8 (device binding), §6.6.3.9 (user binding) |
| ISO/IEC 18013-5 | :2021 — paywalled, not reproduced here | §8.3 (`DeviceResponse` structure — the structural parse), §9.1.2 (mobile security object value digests against the disclosed issuer-signed items), §9.1.3 (device authentication over the session transcript), §9.3.1 (inspection procedure for issuer data authentication — step 5's requirement that the signing date lie inside the signer certificate's validity period, which is why the issuer certificate path is judged at the credential's signing time by default) |
| ETSI EN 319 102-1 — procedures for creation and validation of AdES digital signatures | V1.4.1 — <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf> | §5.2.6.4 (the two X.509 validity models, shell and chain, and the requirement that the model be stated as an explicit validation constraint — the source of this service's `ISSUER_VALIDITY_MODEL` values). Cited for its vocabulary and that requirement only: it governs signature validation, where a signature outlives its certificate on the strength of a time-stamp, which a wallet credential does not carry |
| ISO/IEC TS 18013-7 | :2024 — paywalled, not reproduced here | The session transcript for OpenID4VP, reached through OpenID4VP Annex B.2 |
| Selective Disclosure for JWTs (SD-JWT) | RFC 9901 — <https://www.rfc-editor.org/rfc/rfc9901.html> | §4 (the tilde-delimited combined serialization and the trailing position of the key binding JWT), §4.3 (key binding JWT), §7.1 (verification of the SD-JWT — the `_sd` digest check). Verification itself is delegated to the SD-JWT library |
| SD-JWT-based Verifiable Credentials (SD-JWT VC) | draft-ietf-oauth-sd-jwt-vc — **an Internet-Draft with no stable edition to pin.** This service targets what its SD-JWT library implements; EU reference implementations cite a later revision | §3 (`vct`, `iss`, `cnf`, `status`), media type `dc+sd-jwt` |
| Token Status List | **draft-ietf-oauth-status-list-21** — an Internet-Draft, and the revision the status-list library pins — <https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/> | §4.1 (status list bit array, packed least-significant-bit first), §5.1 (status list token in JWT form; `sub` MUST be the list URI — §5.2 for CWT), §7.1 (status value 0x01 is INVALID). Used by the in-repo test status-list authority; production verification is delegated to the status-list library |
| OpenID4VC High Assurance Interoperability Profile (HAIP) | 1.0 (final) — <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html> | §5.2 (a verifier supports at least one of signed or unsigned browser-API requests) |
| ETSI TS 119 411-8 — access certificate policy for EUDI Wallet relying parties | V1.1.1 (2025-10) — <https://www.etsi.org/deliver/etsi_ts/119400_119499/11941108/01.01.01_60/ts_11941108v010101p.pdf> | §4.2.2 (certificate policy — the access certificate chain is profile-validated once at startup, fail-closed), §5.3 (the `QCP-l-eudiwrp` certificate policy identifier) |
| ETSI TS 119 475 — relying party attributes | V1.2.1 | A.2.1 (the service-provider entitlement carried on the access certificate) |
| JWT-Secured Authorization Request (JAR) | RFC 9101 | §6.3 (request object assembly and validation) — the signed request object served by reference |
| OAuth 2.0 | RFC 6749 | §5.2 (error response — the shape the wallet-facing endpoints emit) |
| JSON Web Signature (JWS) | RFC 7515 | §4.1 (protected header), §4.1.6 (`x5c` certificate chain) |
| JSON Web Key (JWK) | RFC 7517 | §4 (common key parameters), §5 (JWK Set format) — the published webhook-signing key set |
| JSON Web Algorithms (JWA) | RFC 7518 | §6.2 (elliptic-curve key parameters — `crv`, `x`, `y`) |
| JWK Thumbprint | RFC 7638 | §3 (thumbprint of the ephemeral response-encryption key, bound into the mdoc session transcript) |
| Problem Details for HTTP APIs | RFC 9457 | The error envelope on the management-facing API. The wallet-facing endpoints deliberately emit OpenID4VP error shapes instead |
| Agreed Cryptographic Mechanisms (ECCG) | v2.0 | The cryptographic allow-list: P-256, ES256, ECDH-ES, A128GCM, COSE ES256 |

## Notes on the pins

**ARF — the pin is 2.9 and the 3.0.0 re-check is outstanding.** These citations were written
against ARF 2.9. Every clause number cited above still exists in 3.0.0 and still carries a
heading describing the same verification step, but resolving is not agreeing: a clause number
can survive a major version while the text under it moves. Until the two editions have been
compared clause by clause, treat the numbers above as pinned to 2.9, and confirm the text
before relying on any of them against 3.0.0.

**ISO/IEC 18013-5 and TS 18013-7 are paywalled.** They are not reproduced here, so the clause
numbers above are recorded as cited and are not independently confirmed in this repository.

**Two sources are Internet-Drafts.** SD-JWT VC and Token Status List have both renumbered
sections between revisions before. Re-read those clauses against whichever revision a
deployment's issuers actually emit.

## Where the client-visible references live

The specification references returned to clients in the verification report are defined in one
place, `internal/pipeline/specrefs.go`, and are never inlined at a check site. A change to a
cited clause therefore changes one file, not many.

## Citation form

Every bracket names exactly one clause of one document, so any citation in this repository can be
looked up mechanically.

The `specRef` values returned to clients in the verification report are prose rather than citations —
`ISO/IEC 18013-5 §8.3 / IETF SD-JWT VC` names the two formats a check covers, and `ARF Topic 18` and
`ARF AS-RP-51-008/011/013` name a topic and requirement identifiers. They are API values consumers
match on, and they stay as they are.
