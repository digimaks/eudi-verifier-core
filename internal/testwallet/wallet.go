// Package testwallet is a synthetic EUDI wallet used in tests to drive the
// verifier's wallet-facing flows end to end — request retrieval, credential
// presentation (PID mdoc and SD-JWT), and deliberate fault injection.
//
// Lockstep note ("copy-don't-rewrite"): this
// package is byte-for-byte duplicated in the standalone black-box test
// harness. It cannot be extracted into a shared
// library: THIS copy is imported directly by this service's own route
// tests (dcapi/deletion/matrix/metrics/policy-matrix, internal/anchors),
// while mole (the standalone black-box tester) needs the same
// wallet simulation without depending on this service's internal packages.
// Any change to this package's behavior MUST be mirrored by hand in the
// sibling copy; the two are expected to stay identical except for this note
// and its mirror-image counterpart in mole's wallet.go.
package testwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Client abstracts HTTP so the same harness drives azugo's in-process TestApp
// (routes tests), a compose deployment (integration + loadgen), and nothing at
// all (BuildResponse-only unit tests, where a nil Client is fine).
type Client interface {
	Get(ctx context.Context, rawurl string) (status int, body []byte, err error)
	PostForm(ctx context.Context, rawurl string, form url.Values) (status int, body []byte, err error)
	// PostJSON is DCAPI's transport shape: a JSON body and the
	// calling origin carried as a header, never inside the payload.
	PostJSON(ctx context.Context, rawurl string, body []byte, headers map[string]string) (status int, respBody []byte, err error)
}

// Wallet is the simulated EUDI wallet: it fetches and verifies a signed request
// object and, on the happy path, issues + presents one credential per DCQL
// credential query via the SD-JWT/mdoc Issue façades. Parameterized fault
// injection is layered on.
type Wallet struct {
	pki    *PKI
	client Client
	Status *StatusLists
	now    func() time.Time

	// lastStatusRef records the status-list reference allocated by the most
	// recent present call, so tests can assert which ref was allocated (and,
	// under WithRevokedCredential, revoked). Single-goroutine test use only.
	lastStatusRef StatusRef
}

// New builds a Wallet over the given PKI, HTTP client (may be nil for
// BuildResponse-level tests), and status-list authority.
func New(pki *PKI, client Client, status *StatusLists) *Wallet {
	return &Wallet{pki: pki, client: client, Status: status, now: time.Now}
}

// WithClock overrides the wallet clock (stale-KB fault, expiry tests).
func (w *Wallet) WithClock(now func() time.Time) *Wallet { w.now = now; return w }

// RequestObject is the parsed signed JAR (RFC 9101; [OID4VP §5]).
type RequestObject struct {
	Raw             []byte
	ClientID        string
	Nonce           string
	State           string
	ResponseURI     string
	Query           *dcql.Query
	EncryptionKey   *ecdsa.PublicKey // verifier ephemeral JWK (HAIP: response encryption mandatory)
	ExpectedOrigins []string         // DCAPI
}

// FetchRequestObject GETs request_uri and parses+verifies the JAR: signature
// against the x5c leaf (a real wallet then validates the WRPAC chain — out of
// harness scope), then extracts the OID4VP members. // [OID4VP §5.10], RFC 9101.
func (w *Wallet) FetchRequestObject(ctx context.Context, requestURI string) (*RequestObject, error) {
	status, body, err := w.client.Get(ctx, requestURI)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("testwallet: request_uri fetch: HTTP %d", status)
	}
	return w.ParseRequestObject(body)
}

// ParseRequestObject peeks the x5c leaf from the protected header, verifies the
// JAR signature with the leaf key, and extracts the OID4VP members and verifier
// ephemeral encryption key. // [OID4VP §5.10], [RFC 9101 §6.3].
func (w *Wallet) ParseRequestObject(jar []byte) (*RequestObject, error) {
	hdrSeg, _, ok := splitJWS(jar)
	if !ok {
		return nil, fmt.Errorf("testwallet: not a compact JWS")
	}
	var hdr struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(hdrSeg, &hdr); err != nil || len(hdr.X5C) == 0 {
		return nil, fmt.Errorf("testwallet: JAR header without x5c")
	}
	leafDER, err := base64.StdEncoding.DecodeString(hdr.X5C[0])
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	payload, _, err := crypto.VerifyJWS(jar, leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("testwallet: JAR signature: %w", err)
	}
	return parseRequestClaims(payload, jar)
}

// parseRequestClaims turns the OID4VP request parameters into a RequestObject.
// It is shared by the two ways a wallet can receive them: as the payload of a
// signed request object, and as the plain JSON object of an unsigned
// browser-based request (OID4VP Annex A.3.1). raw is kept for the caller's
// records — for a signed request it is the token, for an unsigned one the
// parameters themselves.
func parseRequestClaims(payload, raw []byte) (*RequestObject, error) {
	var claims struct {
		ClientID    string          `json:"client_id"`
		Nonce       string          `json:"nonce"`
		State       string          `json:"state"`
		ResponseURI string          `json:"response_uri"`
		DCQLQuery   json.RawMessage `json:"dcql_query"`
		ClientMeta  struct {
			JWKS struct {
				Keys []struct {
					Kty, Crv, X, Y string
				} `json:"keys"`
			} `json:"jwks"`
		} `json:"client_metadata"`
		ExpectedOrigins []string `json:"expected_origins"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	q, err := dcql.Parse(claims.DCQLQuery)
	if err != nil {
		return nil, fmt.Errorf("testwallet: dcql_query: %w", err)
	}
	ro := &RequestObject{
		Raw: raw, ClientID: claims.ClientID, Nonce: claims.Nonce, State: claims.State,
		ResponseURI: claims.ResponseURI, Query: q, ExpectedOrigins: claims.ExpectedOrigins,
	}
	for _, k := range claims.ClientMeta.JWKS.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		xb, err1 := base64.RawURLEncoding.DecodeString(k.X)
		yb, err2 := base64.RawURLEncoding.DecodeString(k.Y)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("testwallet: bad ephemeral JWK")
		}
		pub, perr := P256PublicKey(xb, yb)
		if perr != nil {
			return nil, fmt.Errorf("testwallet: bad ephemeral JWK: %w", perr)
		}

		ro.EncryptionKey = pub

		break
	}
	if ro.EncryptionKey == nil {
		return nil, fmt.Errorf("testwallet: no P-256 encryption key in client_metadata")
	}
	return ro, nil
}

// ParseDCAPIRequest unwraps a W3C Digital Credentials API request member
// (OID4VP Annex A, as returned in oid4vp.WalletInvocation.DCAPI) in either of
// the two shapes a verifier may hand a browser:
//
//   - signed   — {"protocol":"openid4vp-v1-signed","data":{"request":"<jws>"}}:
//     the inner JAR is parsed with the SAME logic as ParseRequestObject, since
//     the signed browser request is claims-compatible with the request_uri JAR
//     (same x5c signature, dcql_query, client_metadata; expected_origins
//     instead of response_uri). No JAR-parsing logic is duplicated.
//   - unsigned — {"protocol":"openid4vp-v1-unsigned","data":{…parameters…}}
//     (Annex A.3.1): the same parameters as a plain object, with no signature
//     to check, no client_id and no expected_origins. A real wallet takes the
//     verifier's identity from the calling web origin instead; this one has no
//     identity to check, so it simply reads the parameters.
//
// Both are accepted because a wallet must cope with whichever mode the
// verifier is deployed in, and a test wallet that only understood the signed
// shape would report an unsigned deployment as a malformed request.
//
// DCAPI sessions carry no response_uri claim at all (the browser returns the
// response, not a URI — OID4VP Annex A; sessions.Creator never puts one on a
// DCAPI RequestSpec, since oid4vp.NewSession rejects it). responseURI is the
// actual wallet-facing transport endpoint, learned out-of-band
// (sessions.Created.ResponseURI) — it is stamped onto the result since the
// parsed claims leave RequestObject.ResponseURI at its zero value here.
func (w *Wallet) ParseDCAPIRequest(member []byte, responseURI string) (*RequestObject, error) {
	var env struct {
		Protocol string          `json:"protocol"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(member, &env); err != nil {
		return nil, fmt.Errorf("testwallet: dcapi request member: %w", err)
	}

	var signed struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal(env.Data, &signed); err != nil {
		return nil, fmt.Errorf("testwallet: dcapi request member data: %w", err)
	}

	var ro *RequestObject
	var err error
	switch {
	case signed.Request != "":
		ro, err = w.ParseRequestObject([]byte(signed.Request))
	case env.Protocol == dcapiProtocolUnsigned:
		ro, err = parseRequestClaims(env.Data, env.Data)
	default:
		return nil, fmt.Errorf("testwallet: dcapi request member %q carries neither a signed request nor unsigned parameters", env.Protocol)
	}
	if err != nil {
		return nil, err
	}
	ro.ResponseURI = responseURI
	return ro, nil
}

// dcapiProtocolUnsigned is the OID4VP Annex A.1 protocol identifier for the
// unsigned browser-based request.
const dcapiProtocolUnsigned = "openid4vp-v1-unsigned"

// splitJWS decodes the header and payload segments of a compact JWS without
// verifying the signature.
func splitJWS(token []byte) (headerJSON, payload []byte, ok bool) {
	parts := make([][]byte, 0, 3)
	start := 0
	for i := 0; i <= len(token); i++ {
		if i == len(token) || token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	if len(parts) != 3 {
		return nil, nil, false
	}
	h, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, nil, false
	}
	p, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, nil, false
	}
	return h, p, true
}

// BuildResponse produces the application/x-www-form-urlencoded body for
// POST /wallet/{id}/response: response=<JWE(vp_token,state)>. With no options
// it is the honest happy path; the FaultOptions (faults.go) make every pipeline
// check fail-able. Per-credential faults are threaded into present; the
// response-level faults (WithWrongState, WithExtraCredential,
// WithDuplicateCredential) reshape the assembled vp_token / state here.
// // [OID4VP §8.2] direct_post.jwt; [OID4VP §8.1] vp_token object keyed by query cred id.
func (w *Wallet) BuildResponse(ctx context.Context, ro *RequestObject, opts ...FaultOption) (url.Values, error) {
	if ro.Query == nil {
		return nil, fmt.Errorf("testwallet: request object has no dcql query")
	}
	spec := resolveSpec(opts)

	vpToken := map[string][]string{}
	var firstPresentation string
	for i := range ro.Query.Credentials {
		cq := &ro.Query.Credentials[i]
		pres, err := w.present(ctx, ro, cq, spec)
		if err != nil {
			return nil, fmt.Errorf("testwallet: present %s: %w", cq.ID, err)
		}
		// Combined-presentation fault (step 9, ARF Topic 18): the SAME physical
		// credential — byte-identical presentation — answers EVERY query id. Each
		// id still receives exactly ONE candidate, so the DCQL multiple-not-allowed
		// gate (step 8, one presentation per query) is NOT tripped; the violation is
		// that two DIFFERENT query ids are satisfied by one artifact, which is what
		// check_combined.go (step 9) rejects. This is CROSS-ID reuse
		// (`pres = firstPresentation`), NOT presenting a
		// single id twice — the latter reduces to DCQL multiple-not-allowed and
		// fails at step 8, a different step. (Requires a query with ≥2 credential
		// ids whose claims are all satisfied by the reused credential.)
		if spec.duplicateCredential && firstPresentation != "" {
			pres = firstPresentation
		}
		if firstPresentation == "" {
			firstPresentation = pres
		}
		vpToken[cq.ID] = []string{pres}
	}
	// Over-disclosure: present a credential under a query id the DCQL query never
	// asked for. This was originally filed under step 8 (query_fulfilment), but in
	// the shipped stack the engine rejects an unknown credential id earlier,
	// at ProcessResponse / pipeline step 1 (presentationsFromVPToken →
	// ErrUnknownCredentialID: "no over-disclosure enters the pipeline silently").
	if spec.extraCredentialID != "" && len(ro.Query.Credentials) > 0 {
		extra, err := w.present(ctx, ro, &ro.Query.Credentials[0], spec)
		if err != nil {
			return nil, fmt.Errorf("testwallet: present extra %s: %w", spec.extraCredentialID, err)
		}
		vpToken[spec.extraCredentialID] = []string{extra}
	}

	state := ro.State
	if spec.wrongState {
		// A state that cannot match ro.State, so state binding (step 1) fails.
		state = ro.State + "-tampered"
	}

	payload, err := json.Marshal(map[string]any{"vp_token": vpToken, "state": state})
	if err != nil {
		return nil, err
	}
	// The mdoc SessionTranscript handover already binds to the RP's ephemeral
	// encryption key via its RFC 7638 thumbprint (see present.go), so no apu
	// header is needed on the JWE.
	jweTok, err := crypto.EncryptJWE(ro.EncryptionKey, nil, payload)
	if err != nil {
		return nil, err
	}
	return url.Values{"response": []string{string(jweTok)}}, nil
}

// Respond builds the response (honest, or with the given faults) and POSTs it,
// returning status + body. Calling Respond twice with the same ro reproduces
// the replay fault (step 1) — no dedicated option is needed.
//
// DCAPI sessions (spec.dcapiOrigin set by WithDCAPIOrigin) use
// ProcessDCAPIResponse's JSON shape and carry the origin as a transport
// header — the calling origin is never part of the JSON body itself
// (ProcessDCAPIResponse takes it as an explicit parameter, dcapi.go:140).
// BuildResponse itself is unchanged: it still returns url.Values with the
// encrypted `response` member; DCAPI re-wraps that same JWE into a JSON
// envelope.
func (w *Wallet) Respond(ctx context.Context, ro *RequestObject, opts ...FaultOption) (int, []byte, error) {
	spec := resolveSpec(opts)
	form, err := w.BuildResponse(ctx, ro, opts...)
	if err != nil {
		return 0, nil, err
	}
	if spec.dcapiOrigin != "" {
		body, merr := json.Marshal(map[string]string{"response": form.Get("response")})
		if merr != nil {
			return 0, nil, merr
		}
		return w.client.PostJSON(ctx, ro.ResponseURI, body, map[string]string{"Origin": spec.dcapiOrigin})
	}
	return w.client.PostForm(ctx, ro.ResponseURI, form)
}

// p256CoordLen is the byte length of a P-256 coordinate.
const p256CoordLen = 32

// P256PublicKey builds a P-256 public key from a JWK's x/y coordinates.
//
// It parses the SEC 1 uncompressed encoding rather than assigning the raw
// coordinates, so the point is checked to be on the curve instead of becoming a
// key that only misbehaves later.
//
// A coordinate is left-padded to the field size: RFC 7518 requires a JWK to
// carry the full 32 bytes including leading zeros, but producers that strip
// them exist and such a key was accepted before this.
func P256PublicKey(xb, yb []byte) (*ecdsa.PublicKey, error) {
	if len(xb) > p256CoordLen || len(yb) > p256CoordLen {
		return nil, fmt.Errorf("coordinate longer than %d bytes", p256CoordLen)
	}

	// 0x04 || X || Y, each coordinate right-aligned in its own field-sized slot.
	buf := make([]byte, 1+2*p256CoordLen)
	buf[0] = 4
	copy(buf[1+p256CoordLen-len(xb):], xb)
	copy(buf[1+2*p256CoordLen-len(yb):], yb)

	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), buf)
}
