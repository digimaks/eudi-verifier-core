package testwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	mdoc "github.com/gmb-eudi/go-mdoc"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
)

// dsKeyID is the in-memory KeyProvider key id for the document-signer key. It
// is a map lookup key, not an algorithm identifier (crypto algorithm literals
// stay in go-eudi-crypto).
const dsKeyID = "ds"

// issuerID is the iss/issuer identifier stamped on issued SD-JWT VCs. The
// harness's trust comes from the x5c chain to the IACA root, not from iss.
const issuerID = "https://issuer.test"

// present issues one credential for the given DCQL credential query in its
// declared format and returns the holder presentation: an SD-JWT VC combined
// form (issuer-JWT ~ disclosures ~ KB-JWT), or a base64url-encoded mdoc
// DeviceResponse (OID4VP Annex B.2 vp_token encoding). spec carries the
// parameterized faults (faults.go); a zero spec is the honest happy path.
func (w *Wallet) present(ctx context.Context, ro *RequestObject, cq *dcql.CredentialQuery, spec *presentSpec) (string, error) {
	if spec.malformed {
		// Structural garbage that is neither a compact JWS (no '~'/'.') nor a
		// valid base64url mdoc DeviceResponse (the NUL/0xFF bytes are outside
		// the base64url alphabet): structural parsing (pipeline step 2) must
		// reject it before any signature check.
		return "not-a-credential-\x00\xff", nil
	}
	switch cq.Format {
	case dcql.FormatSDJWT:
		return w.presentSDJWT(ctx, ro, cq, spec)
	case dcql.FormatMdoc:
		return w.presentMdoc(ctx, ro, cq, spec)
	default:
		return "", fmt.Errorf("testwallet: unsupported credential format %q", cq.Format)
	}
}

// presentSDJWT issues an SD-JWT VC carrying the queried claims (all selectively
// disclosable), then key-binds a presentation to the request's aud/nonce. The
// disclosed set is driven by cq.Claims (minus WithMissingClaim paths); issued
// values come from the query's value constraints, overridden by WithClaims.
// [SD-JWT VC draft-18 §2]; [OID4VP §8.1].
func (w *Wallet) presentSDJWT(ctx context.Context, ro *RequestObject, cq *dcql.CredentialQuery, spec *presentSpec) (string, error) {
	vct := "urn:eudi:pid:1"
	if cq.Meta != nil && len(cq.Meta.VCTValues) > 0 {
		vct = cq.Meta.VCTValues[0]
	}

	claims := map[string]any{}
	var selective, disclose []sdjwt.ClaimPath
	if len(cq.Claims) == 0 {
		// No claims member (e.g. PresetPIDFull): present a default mandatory set.
		claims["family_name"] = "Doe"
		claims["given_name"] = "Jane"
		selective = []sdjwt.ClaimPath{sdjwt.Path("family_name"), sdjwt.Path("given_name")}
		disclose = selective
	} else {
		for _, c := range cq.Claims {
			sp, err := toSDJWTKeyPath(c.Path)
			if err != nil {
				return "", err
			}
			if err := setNested(claims, c.Path, claimValue(c)); err != nil {
				return "", err
			}
			selective = append(selective, sp)
			// Withhold WithMissingClaim paths from the presentation while still
			// issuing them selectively — the credential HAS the claim, the
			// presentation omits it (claim-completeness fault, step 8).
			if !contains(spec.missingClaims, c.Path.String()) {
				disclose = append(disclose, sp)
			}
		}
	}
	// WithClaims canary/value overrides: merged on top of the
	// query-derived claims — queried keys are re-valued (and, being disclosed,
	// the canary flows through), other query claims keep their derived values.
	for k, v := range spec.claimsOverride[cq.ID] {
		claims[k] = v
	}

	now := w.now()
	// Short-lived exemption knob (WithValidity): shorten Expiry to now+validity
	// so the verifier's resolved window (Expiry-NotBefore) is <24h; default 24h.
	expiry := now.Add(24 * time.Hour)
	if spec.validity > 0 {
		expiry = now.Add(spec.validity)
	}
	tmpl := sdjwt.CredentialTemplate{
		VCT:       vct,
		Issuer:    issuerID,
		IssuedAt:  now,
		NotBefore: now.Add(-time.Minute),
		Expiry:    expiry,
		HolderKey: w.pki.DeviceKey.Public(),
		Claims:    claims,
		Selective: selective,
		Status:    w.sdjwtStatus(spec),
	}
	provider, chain := w.issuerMaterial(spec)
	issuer := sdjwt.NewIssuer(provider, dsKeyID, sdjwt.WithChain(chain))
	sdJWT, err := issuer.Issue(ctx, tmpl)
	if err != nil {
		return "", err
	}

	nonce := ro.Nonce
	if spec.wrongNonce {
		nonce = ro.Nonce + "-wrong"
	}
	kbNow := now
	if spec.staleKBAge > 0 {
		kbNow = now.Add(-spec.staleKBAge) // back-date the KB iat past the freshness window
	}
	// [OID4VP §A.4]: over the browser-based API the Key Binding audience is
	// the calling origin prefixed with "origin:", "even for signed requests" —
	// the Client Identifier is not used there, and an unsigned request does not
	// carry one at all. Every other flow key-binds to the Client Identifier the
	// wallet authenticated.
	aud := ro.ClientID
	if spec.dcapiOrigin != "" {
		aud = "origin:" + spec.dcapiOrigin
	}
	pres, err := sdjwt.PresentKB(ctx, w.pki.DeviceKey, sdJWT, disclose, aud, nonce, kbNow)
	if err != nil {
		return "", err
	}
	if spec.omitKB {
		// [SD-JWT §4]: strip the trailing KB-JWT, keeping the '~' that precedes
		// it, leaving a valid KB-less combined form (RequireKB → ErrKBRequired).
		if i := strings.LastIndexByte(string(pres), '~'); i >= 0 {
			pres = pres[:i+1]
		}
	}
	if spec.tamperDigest {
		pres = tamperFirstDisclosure(pres)
	}
	return string(pres), nil
}

// tamperFirstDisclosure flips the disclosed VALUE inside the first disclosure
// segment while leaving the issuer-signed _sd digest untouched, so the
// disclosure's recomputed digest no longer matches any referenced digest →
// ErrDigestMismatch (pipeline step 4 / [SD-JWT §7.1]). No-op if the
// presentation has no disclosure to tamper.
func tamperFirstDisclosure(pres []byte) []byte {
	parts := strings.Split(string(pres), "~")
	if len(parts) < 3 { // <issuer>~<disclosure>~... — need at least one disclosure
		return pres
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return pres
	}
	var d []any // [salt, name, value]
	if json.Unmarshal(raw, &d) != nil || len(d) != 3 {
		return pres
	}
	d[2] = "TAMPERED"
	nb, err := json.Marshal(d)
	if err != nil {
		return pres
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(nb)
	return []byte(strings.Join(parts, "~"))
}

// presentMdoc issues an mdoc carrying the queried elements, then produces a
// DeviceResponse whose DeviceAuth is bound to the OID4VP SessionTranscript
// handover (which binds to the RP's ephemeral encryption key by RFC 7638
// thumbprint; DC-API origin variant under WithDCAPIOrigin).
// // [ISO/IEC 18013-5 §9.1.3]; OID4VP Annex B.2.
func (w *Wallet) presentMdoc(ctx context.Context, ro *RequestObject, cq *dcql.CredentialQuery, spec *presentSpec) (string, error) {
	if ro.EncryptionKey == nil {
		return "", fmt.Errorf("testwallet: mdoc presentation needs the verifier ephemeral encryption key")
	}
	docType := "eu.europa.ec.eudi.pid.1"
	if cq.Meta != nil && cq.Meta.DoctypeValue != "" {
		docType = cq.Meta.DoctypeValue
	}

	namespaces := map[string]map[string]any{}
	disclose := map[string][]string{}
	if len(cq.Claims) == 0 {
		namespaces[docType] = map[string]any{"family_name": "Doe", "given_name": "Jane"}
		disclose[docType] = []string{"family_name", "given_name"}
	} else {
		for _, c := range cq.Claims {
			ns, elem, err := mdocPath(c.Path)
			if err != nil {
				return "", err
			}
			if namespaces[ns] == nil {
				namespaces[ns] = map[string]any{}
			}
			namespaces[ns][elem] = claimValue(c)
			// Withhold WithMissingClaim elements from the disclosed set while
			// still issuing them (claim-completeness fault, step 8).
			if !contains(spec.missingClaims, c.Path.String()) {
				disclose[ns] = append(disclose[ns], elem)
			}
		}
	}
	// WithClaims canary/value overrides: applied to the doctype namespace.
	if o := spec.claimsOverride[cq.ID]; o != nil {
		if namespaces[docType] == nil {
			namespaces[docType] = map[string]any{}
		}
		for k, v := range o {
			namespaces[docType][k] = v
		}
	}

	now := w.now()
	// Short-lived exemption knob (WithValidity): shorten ValidUntil to
	// now+validity so the verifier's resolved window is <24h; default 24h.
	validUntil := now.Add(24 * time.Hour)
	if spec.validity > 0 {
		validUntil = now.Add(spec.validity)
	}
	doc := mdoc.DocumentTemplate{
		DocType:    docType,
		Namespaces: namespaces,
		ValidityInfo: mdoc.ValidityInfo{
			Signed:     now,
			ValidFrom:  now.Add(-time.Minute),
			ValidUntil: validUntil,
		},
		Status: w.mdocStatus(spec),
	}
	provider, chain := w.issuerMaterial(spec)
	issuer := mdoc.NewIssuer(provider, dsKeyID, derChain(chain))
	issuerSigned, err := issuer.Issue(ctx, doc, w.pki.DeviceKey.Public())
	if err != nil {
		return "", err
	}

	// Raw digest bytes: the handover carries the thumbprint as a CBOR byte
	// string, so the wallet side must bind the same representation the verifier
	// does — a mismatch here would make both sides agree while both are wrong.
	thumb, err := crypto.JWKThumbprintBytes(ro.EncryptionKey)
	if err != nil {
		return "", err
	}
	nonce := ro.Nonce
	if spec.wrongNonce {
		nonce = ro.Nonce + "-wrong"
	}
	responseURI := ro.ResponseURI
	if spec.wrongTranscript {
		responseURI = "https://evil.example/response"
	}
	var st mdoc.SessionTranscript
	if spec.dcapiOrigin != "" {
		// OID4VP Annex B.2.6.2: (origin, nonce, jwkThumbprint) — no client_id or
		// response_uri in the DC-API variant.
		st = mdoc.OID4VPDCAPIHandover(spec.dcapiOrigin, nonce, thumb)
	} else {
		// OID4VP Annex B.2.6.1: (client_id, nonce, jwkThumbprint, response_uri).
		st = mdoc.OID4VPHandover(ro.ClientID, nonce, thumb, responseURI)
	}
	resp, err := mdoc.DevicePresent(ctx, w.pki.DeviceKey, issuerSigned, disclose, st)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(resp), nil
}

// issuerMaterial returns the document-signer key provider and x5c chain for a
// presentation: the genuine DS chain to the IACA root, or — under
// WithUnregisteredIssuer — the rogue chain that is deliberately absent from the
// trust anchor set (issuer-trust fault, step 3).
func (w *Wallet) issuerMaterial(spec *presentSpec) (crypto.KeyProvider, []*x509.Certificate) {
	key := w.pki.DSKey
	chain := []*x509.Certificate{w.pki.DSCert, w.pki.IACARoot}
	if spec.unregisteredIssuer {
		key = w.pki.RogueKey
		chain = []*x509.Certificate{w.pki.RogueCert, w.pki.RogueRoot}
	}
	return crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{dsKeyID: key}), chain
}

// allocStatus allocates a fresh status-list reference, records it for test
// assertions (w.lastStatusRef), and — under WithRevokedCredential — flips its
// bit to INVALID (revocation fault, step 5). ok is false when the wallet has
// no status authority (nil-safe for BuildResponse-only tests).
func (w *Wallet) allocStatus(spec *presentSpec) (StatusRef, bool) {
	if w.Status == nil {
		return StatusRef{}, false
	}
	ref := w.Status.NewRef()
	w.lastStatusRef = ref
	if spec.revoked {
		w.Status.Revoke(ref)
	}
	return ref, true
}

// sdjwtStatus builds the SD-JWT status reference for an allocated ref, or nil.
func (w *Wallet) sdjwtStatus(spec *presentSpec) *sdjwt.StatusRef {
	ref, ok := w.allocStatus(spec)
	if !ok {
		return nil
	}
	return &sdjwt.StatusRef{URI: ref.URI, Index: ref.Index}
}

// mdocStatus is the mdoc counterpart of sdjwtStatus (Index is uint here).
func (w *Wallet) mdocStatus(spec *presentSpec) *mdoc.StatusRef {
	ref, ok := w.allocStatus(spec)
	if !ok {
		return nil
	}
	return &mdoc.StatusRef{URI: ref.URI, Index: uint(ref.Index)}
}

// claimValue returns the value to issue for a queried claim: the query's first
// expected value when it constrains one (so the presentation satisfies the
// query later), else a deterministic placeholder derived from the claim name.
func claimValue(c dcql.ClaimsQuery) any {
	if len(c.Values) > 0 {
		return c.Values[0]
	}
	name := "value"
	if n := len(c.Path); n > 0 && c.Path[n-1].Kind == dcql.KindKey {
		name = c.Path[n-1].Key
	}
	return "test-" + name
}

// toSDJWTKeyPath converts a DCQL claims path (object keys only, which is all
// the PID/EAA SD-JWT presets use) to an sdjwt.ClaimPath.
func toSDJWTKeyPath(path dcql.ClaimPath) (sdjwt.ClaimPath, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("testwallet: empty sd-jwt claim path")
	}
	out := make(sdjwt.ClaimPath, 0, len(path))
	for _, e := range path {
		if e.Kind != dcql.KindKey {
			return nil, fmt.Errorf("testwallet: sd-jwt claim path supports object keys only in this harness")
		}
		out = append(out, e.Key)
	}
	return out, nil
}

// setNested writes value at the (object-key) claims path, creating intermediate
// objects as needed.
func setNested(root map[string]any, path dcql.ClaimPath, value any) error {
	cur := root
	for i, e := range path {
		if e.Kind != dcql.KindKey {
			return fmt.Errorf("testwallet: sd-jwt claim path supports object keys only in this harness")
		}
		if i == len(path)-1 {
			cur[e.Key] = value
			return nil
		}
		next, ok := cur[e.Key].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[e.Key] = next
		}
		cur = next
	}
	return nil
}

// mdocPath splits a DCQL mdoc claims path into [namespace, element].
func mdocPath(path dcql.ClaimPath) (ns, elem string, err error) {
	if len(path) != 2 || path[0].Kind != dcql.KindKey || path[1].Kind != dcql.KindKey {
		return "", "", fmt.Errorf("testwallet: mdoc claim path must be [namespace, element]")
	}
	return path[0].Key, path[1].Key, nil
}

// derChain flattens a certificate chain to raw DER (leaf first) — the shape
// mdoc.NewIssuer's x5chain parameter wants; sdjwt.WithChain takes the
// []*x509.Certificate slice directly.
func derChain(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.Raw
	}
	return out
}

// contains reports whether list holds s.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
