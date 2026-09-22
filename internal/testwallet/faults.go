package testwallet

import "time"

// presentSpec is the resolved set of fault knobs for one BuildResponse /
// present call. The zero value is the honest happy path — every field left at
// its zero value produces a valid, verifiable presentation. Faults
// are applied by the FaultOption setters below.
//
// Most knobs are per-credential (they change how a single credential is issued
// or key-bound); wrongState, extraCredentialID and duplicateCredential are
// response-level (they change the shape of the assembled vp_token / response
// object) and are only consulted by BuildResponse. dcapiOrigin is per-credential
// (it changes the mdoc SessionTranscript handover) but is threaded in the same
// spec for uniformity.
//
// Single-goroutine test use only; the fields are read directly by present.go
// and wallet.go.
type presentSpec struct {
	// Per-credential faults.
	malformed          bool                      // return structural garbage instead of a credential (step 2)
	unregisteredIssuer bool                      // sign with the rogue chain that is not in the anchor set (step 3)
	tamperDigest       bool                      // flip a disclosed SD-JWT value after issuance → digest mismatch (step 4)
	revoked            bool                      // flip the credential's status-list bit to INVALID (step 5)
	wrongNonce         bool                      // bind the KB-JWT / mdoc handover to the wrong nonce (step 6)
	staleKBAge         time.Duration             // back-date the KB-JWT iat by this much (step 6)
	wrongTranscript    bool                      // bind the mdoc DeviceAuth to a different response_uri (step 6)
	omitKB             bool                      // strip the KB-JWT from the SD-JWT presentation (step 6/7)
	missingClaims      []string                  // canonical JSON claim paths to withhold from the disclosed set (step 8)
	claimsOverride     map[string]map[string]any // per-query-id issued-claim overrides / canary values (step 8)
	dcapiOrigin        string                    // present the mdoc under the DC-API handover for this origin
	validity           time.Duration             // override the issued credential's remaining validity window (step 5 short-lived exemption; 0 = default 24h)

	// Response-level faults (consulted by BuildResponse only).
	wrongState          bool   // emit a top-level state that does not match ro.State (step 1)
	extraCredentialID   string // add an unrequested vp_token entry under this query id (over-disclosure; rejected at step 1)
	duplicateCredential bool   // reuse ONE credential's bytes across every query id (step 9 combined-presentation violation)
}

// FaultOption mutates a presentSpec. Options compose; the honest path is the
// empty option set.
type FaultOption func(*presentSpec)

// resolveSpec folds a list of options into a fresh presentSpec.
func resolveSpec(opts []FaultOption) *presentSpec {
	spec := &presentSpec{}
	for _, o := range opts {
		o(spec)
	}
	return spec
}

// WithWrongState makes the response's top-level state disagree with ro.State,
// so state-binding (pipeline step 1) fails.
func WithWrongState() FaultOption { return func(s *presentSpec) { s.wrongState = true } }

// WithWrongNonce binds the KB-JWT (SD-JWT) or handover (mdoc) to a nonce other
// than the request nonce, so nonce/replay binding (pipeline step 6) fails.
func WithWrongNonce() FaultOption { return func(s *presentSpec) { s.wrongNonce = true } }

// WithRevokedCredential flips the credential's status-list bit to INVALID so
// status evaluation (pipeline step 5) fails.
func WithRevokedCredential() FaultOption { return func(s *presentSpec) { s.revoked = true } }

// WithTamperedDigest tampers a disclosed SD-JWT value after issuance so its
// digest no longer matches the issuer-signed _sd digest (pipeline step 4).
func WithTamperedDigest() FaultOption { return func(s *presentSpec) { s.tamperDigest = true } }

// WithStaleKBJWT back-dates the KB-JWT iat by age, so the freshness window
// (pipeline step 6) rejects it as a replay.
func WithStaleKBJWT(age time.Duration) FaultOption {
	return func(s *presentSpec) { s.staleKBAge = age }
}

// WithWrongTranscript binds the mdoc DeviceAuth to a different response_uri, so
// transcript binding (pipeline step 6) fails.
func WithWrongTranscript() FaultOption { return func(s *presentSpec) { s.wrongTranscript = true } }

// WithUnregisteredIssuer signs the credential with the rogue chain that is not
// in the trust anchor set, so issuer trust resolution (pipeline step 3) fails.
func WithUnregisteredIssuer() FaultOption {
	return func(s *presentSpec) { s.unregisteredIssuer = true }
}

// WithMalformedCredential emits structural garbage in place of a credential, so
// structural parsing (pipeline step 2) fails.
func WithMalformedCredential() FaultOption { return func(s *presentSpec) { s.malformed = true } }

// WithoutKBJWT omits the KB-JWT entirely (pipeline step 6 under the default
// require-KB policy; step 7 under the relaxed policy).
func WithoutKBJWT() FaultOption { return func(s *presentSpec) { s.omitKB = true } }

// WithMissingClaim withholds a requested claim from the disclosed set so
// claim-completeness (pipeline step 8) fails. path is the DCQL claims path in
// its canonical JSON string form (dcql.ClaimPath.String()), e.g.
// `["family_name"]` for SD-JWT or `["eu.europa.ec.eudi.pid.1","family_name"]`
// for mdoc.
func WithMissingClaim(path string) FaultOption {
	return func(s *presentSpec) { s.missingClaims = append(s.missingClaims, path) }
}

// WithExtraCredential adds an unrequested vp_token entry under queryID (a key
// the DCQL query does not ask for), so over-disclosure (pipeline step 8) is
// producible.
func WithExtraCredential(queryID string) FaultOption {
	return func(s *presentSpec) { s.extraCredentialID = queryID }
}

// WithDuplicateCredential makes ONE physical credential (byte-identical
// presentation) answer every credential query id in the request, so a single
// artifact satisfies multiple query ids — the ARF Topic 18 per-credential
// independence / combined-check violation (pipeline step 9). This is CROSS-ID
// reuse, NOT presenting a single id twice:
// the latter is a DCQL multiple-not-allowed failure caught earlier at step 8.
// Use with a query whose credential ids are all satisfiable by the reused
// credential (e.g. two ids both requesting the same claim).
func WithDuplicateCredential() FaultOption {
	return func(s *presentSpec) { s.duplicateCredential = true }
}

// WithDCAPIOrigin presents mdoc credentials under the W3C Digital Credentials
// API SessionTranscript handover for origin (OID4VP Annex B.2.6.2) instead of
// the redirect handover.
func WithDCAPIOrigin(origin string) FaultOption {
	return func(s *presentSpec) { s.dcapiOrigin = origin }
}

// WithValidity overrides the issued credential's validity window (short-lived
// exemption tests: <24h ⇒ [ARF §6.6.3.7] revocation-check exemption). It shortens
// the Expiry (SD-JWT) / ValidUntil (mdoc) to w.now()+d while leaving NotBefore /
// ValidFrom at the honest back-dated origin, so the resolved validity window the
// verifier reads (Expiry-NotBefore) is ~d. A zero duration leaves the honest 24h
// window untouched.
func WithValidity(d time.Duration) FaultOption {
	return func(s *presentSpec) { s.validity = d }
}

// WithClaims overrides the issued values for queryCredID's claims (canary
// values). The override is merged on top of the query-derived
// claims: keys present in the query are re-valued (and, being disclosed, the
// canary flows through to the verifier); other query claims keep their derived
// values.
func WithClaims(queryCredID string, claims map[string]any) FaultOption {
	return func(s *presentSpec) {
		if s.claimsOverride == nil {
			s.claimsOverride = map[string]map[string]any{}
		}
		s.claimsOverride[queryCredID] = claims
	}
}
