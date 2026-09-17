package testwallet

import (
	"bytes"
	"compress/zlib"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"testing"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	mdoc "github.com/gmb-eudi/go-mdoc"
	sdjwt "github.com/gmb-eudi/go-sdjwt"

	"github.com/go-quicktest/qt"
)

// These tests are the fault-injection self-verification suite: each
// fault must produce an artifact that the FORMAT LIBRARY itself accepts or
// rejects exactly as the pipeline step it targets predicts, independent of the
// verifier pipeline. The honest happy path is proven by TestPresentSDJWTHappyPath
// / TestPresentMdocHappyPath / TestBuildResponseEncryptsVPToken (testwallet_test.go)
// and is not re-proven here.

const (
	sdjwtPIDQuery = `{"credentials":[{"id":"pid","format":"dc+sd-jwt",` +
		`"meta":{"vct_values":["urn:eudi:pid:1"]},` +
		`"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}`
	mdocPIDQuery = `{"credentials":[{"id":"pid","format":"mso_mdoc",` +
		`"meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},` +
		`"claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]},` +
		`{"path":["eu.europa.ec.eudi.pid.1","given_name"]}]}]}`
)

func faultWallet(t *testing.T) (*Wallet, *RequestObject) {
	t.Helper()
	pki := NewPKI(t)
	return New(pki, nil, NewStatusLists(pki)), happyRequest(t)
}

// mustQuery parses a single-credential DCQL query and returns the credential.
func mustQuery(t *testing.T, raw string) *dcql.CredentialQuery {
	t.Helper()
	q, err := dcql.Parse([]byte(raw))
	qt.Assert(t, qt.IsNil(err))
	return &q.Credentials[0]
}

// sdjwtVerify runs the real sdjwt verifier against a presentation under the
// request's aud/nonce, requiring a KB-JWT (HAIP default policy).
func sdjwtVerify(pres string, issuerKey stdcrypto.PublicKey, ro *RequestObject) (*sdjwt.VerifiedCredential, error) {
	return sdjwt.NewVerifier().Verify(context.Background(), sdjwt.VerifyInput{
		Presentation:  []byte(pres),
		IssuerKey:     issuerKey,
		ExpectedAud:   ro.ClientID,
		ExpectedNonce: ro.Nonce,
		RequireKB:     true,
	})
}

// mdocVerify runs the real mdoc verifier against a base64url DeviceResponse,
// binding to st and resolving the issuer chain against the given anchors.
func mdocVerify(t *testing.T, pres string, st mdoc.SessionTranscript, anchors []*x509.Certificate) ([]mdoc.VerifiedDocument, error) {
	t.Helper()
	respBytes, err := base64.RawURLEncoding.DecodeString(pres)
	qt.Assert(t, qt.IsNil(err))
	return mdoc.NewVerifier().Verify(context.Background(), mdoc.VerifyInput{
		DeviceResponse:    respBytes,
		SessionTranscript: st,
		IssuerTrust:       anchorTrust{anchors: anchors},
		ExpectedDocType:   "eu.europa.ec.eudi.pid.1",
	})
}

// honestHandover reconstructs the SessionTranscript an honest redirect-flow
// verifier would expect for ro.
func honestHandover(t *testing.T, ro *RequestObject) mdoc.SessionTranscript {
	t.Helper()
	thumb, err := crypto.JWKThumbprintBytes(ro.EncryptionKey)
	qt.Assert(t, qt.IsNil(err))
	return mdoc.OID4VPHandover(ro.ClientID, ro.Nonce, thumb, ro.ResponseURI)
}

// TestFaultOptionsWireToSpec proves each public WithXxx option sets exactly the
// presentSpec field its behavior tests exercise — the option setters are the
// contract the matrix consumes, so mis-wiring one (e.g. WithWrongNonce
// setting wrongState) must fail here.
func TestFaultOptionsWireToSpec(t *testing.T) {
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithWrongState()}).wrongState))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithWrongNonce()}).wrongNonce))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithRevokedCredential()}).revoked))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithTamperedDigest()}).tamperDigest))
	qt.Assert(t, qt.Equals(resolveSpec([]FaultOption{WithStaleKBJWT(time.Hour)}).staleKBAge, time.Hour))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithWrongTranscript()}).wrongTranscript))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithUnregisteredIssuer()}).unregisteredIssuer))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithMalformedCredential()}).malformed))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithoutKBJWT()}).omitKB))
	qt.Assert(t, qt.IsTrue(resolveSpec([]FaultOption{WithDuplicateCredential()}).duplicateCredential))
	qt.Assert(t, qt.Equals(resolveSpec([]FaultOption{WithExtraCredential("e")}).extraCredentialID, "e"))
	qt.Assert(t, qt.Equals(resolveSpec([]FaultOption{WithDCAPIOrigin("o")}).dcapiOrigin, "o"))

	missing := resolveSpec([]FaultOption{WithMissingClaim(`["x"]`)}).missingClaims
	qt.Assert(t, qt.DeepEquals(missing, []string{`["x"]`}))

	override, _ := resolveSpec([]FaultOption{WithClaims("pid", map[string]any{"family_name": "v"})}).claimsOverride["pid"]["family_name"].(string)
	qt.Assert(t, qt.Equals(override, "v"))
}

// ---- SD-JWT per-credential faults --------------------------------------

func TestSDJWTWrongNonceFailsKBNonce(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{wrongNonce: true})
	qt.Assert(t, qt.IsNil(err))
	_, err = sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.ErrorIs(err, sdjwt.ErrKBNonce))
}

func TestSDJWTStaleKBFailsFreshness(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{staleKBAge: time.Hour})
	qt.Assert(t, qt.IsNil(err))
	_, err = sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.ErrorIs(err, sdjwt.ErrKBStale))
}

func TestSDJWTTamperedDigestFailsIntegrity(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{tamperDigest: true})
	qt.Assert(t, qt.IsNil(err))
	_, err = sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.ErrorIs(err, sdjwt.ErrDigestMismatch))
}

func TestSDJWTOmitKBFailsWhenRequired(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{omitKB: true})
	qt.Assert(t, qt.IsNil(err))
	_, err = sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.ErrorIs(err, sdjwt.ErrKBRequired))
}

func TestSDJWTMalformedRejectedByLibrary(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{malformed: true})
	qt.Assert(t, qt.IsNil(err))
	_, err = sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.ErrorIs(err, sdjwt.ErrMalformed))
}

func TestSDJWTUnregisteredIssuerSignsWithRogueChain(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{unregisteredIssuer: true})
	qt.Assert(t, qt.IsNil(err))
	// Verifies against the ROGUE key: the failure the pipeline catches is trust
	// resolution (step 3), not the signature itself.
	_, err = sdjwtVerify(pres, w.pki.RogueKey.Public(), ro)
	qt.Assert(t, qt.IsNil(err))
	// ...and does NOT verify against the registered DS key.
	_, err = sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.ErrorIs(err, sdjwt.ErrIssuerSignature))
}

func TestSDJWTMissingClaimOmitsFromDisclosure(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery),
		&presentSpec{missingClaims: []string{`["given_name"]`}})
	qt.Assert(t, qt.IsNil(err))
	vc, err := sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.IsNil(err)) // still a structurally valid presentation
	_, hasFamily := vc.Claims["family_name"]
	qt.Assert(t, qt.IsTrue(hasFamily))
	_, hasGiven := vc.Claims["given_name"]
	qt.Assert(t, qt.IsFalse(hasGiven)) // the requested claim is absent → step 8 fails
}

func TestSDJWTClaimsOverrideCanary(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery),
		&presentSpec{claimsOverride: map[string]map[string]any{"pid": {"family_name": "CANARY-42"}}})
	qt.Assert(t, qt.IsNil(err))
	vc, err := sdjwtVerify(pres, w.pki.DSKey.Public(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(vc.Claims["family_name"], "CANARY-42")) // canary flows through
	_, hasGiven := vc.Claims["given_name"]
	qt.Assert(t, qt.IsTrue(hasGiven)) // other query-derived claims survive
}

func TestSDJWTRevokedFlipsStatusBit(t *testing.T) {
	w, ro := faultWallet(t)
	_, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{revoked: true})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(w.lastStatusRef.URI != "")) // wallet recorded the allocated ref
	qt.Assert(t, qt.IsTrue(statusBitSet(t, w.Status, w.lastStatusRef, w.pki.StatusKey.Public())))
}

func TestSDJWTHonestNotRevoked(t *testing.T) {
	w, ro := faultWallet(t)
	_, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(statusBitSet(t, w.Status, w.lastStatusRef, w.pki.StatusKey.Public())))
}

// ---- mdoc per-credential faults ----------------------------------------

func TestMdocWrongNonceFailsDeviceAuth(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, mdocPIDQuery), &presentSpec{wrongNonce: true})
	qt.Assert(t, qt.IsNil(err))
	_, err = mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.ErrorIs(err, mdoc.ErrDeviceAuth))
}

func TestMdocWrongTranscriptFailsDeviceAuth(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, mdocPIDQuery), &presentSpec{wrongTranscript: true})
	qt.Assert(t, qt.IsNil(err))
	_, err = mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.ErrorIs(err, mdoc.ErrDeviceAuth))
}

func TestMdocUnregisteredIssuerFailsIssuerAuth(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, mdocPIDQuery), &presentSpec{unregisteredIssuer: true})
	qt.Assert(t, qt.IsNil(err))
	// Against the honest anchor set the rogue chain does not resolve → step 3.
	_, err = mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.ErrorIs(err, mdoc.ErrIssuerAuth))
	// Against the rogue root it resolves and verifies — proving the fault is
	// trust resolution, not a broken signature.
	_, err = mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.RogueRoot})
	qt.Assert(t, qt.IsNil(err))
}

func TestMdocMissingClaimOmitsElement(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, mdocPIDQuery),
		&presentSpec{missingClaims: []string{`["eu.europa.ec.eudi.pid.1","given_name"]`}})
	qt.Assert(t, qt.IsNil(err))
	docs, err := mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.IsNil(err))
	ns := docs[0].Namespaces["eu.europa.ec.eudi.pid.1"]
	_, hasFamily := ns["family_name"]
	qt.Assert(t, qt.IsTrue(hasFamily))
	_, hasGiven := ns["given_name"]
	qt.Assert(t, qt.IsFalse(hasGiven)) // requested element withheld → step 8 fails
}

func TestMdocClaimsOverrideCanary(t *testing.T) {
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, mdocPIDQuery),
		&presentSpec{claimsOverride: map[string]map[string]any{"pid": {"family_name": "CANARY-7"}}})
	qt.Assert(t, qt.IsNil(err))
	docs, err := mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(docs[0].Namespaces["eu.europa.ec.eudi.pid.1"]["family_name"], "CANARY-7"))
}

func TestMdocDCAPIOriginBindsToOrigin(t *testing.T) {
	const origin = "https://rp.example"
	w, ro := faultWallet(t)
	pres, err := w.present(context.Background(), ro, mustQuery(t, mdocPIDQuery), &presentSpec{dcapiOrigin: origin})
	qt.Assert(t, qt.IsNil(err))

	thumb, err := crypto.JWKThumbprintBytes(ro.EncryptionKey)
	qt.Assert(t, qt.IsNil(err))
	// Verifies under the DC-API handover for this origin.
	_, err = mdocVerify(t, pres, mdoc.OID4VPDCAPIHandover(origin, ro.Nonce, thumb), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.IsNil(err))
	// ...and NOT under the redirect handover — proving the DC-API binding is
	// really in effect.
	_, err = mdocVerify(t, pres, honestHandover(t, ro), []*x509.Certificate{w.pki.IACARoot})
	qt.Assert(t, qt.ErrorIs(err, mdoc.ErrDeviceAuth))
}

// ---- Response-level faults (BuildResponse) ------------------------------

func TestWrongStateMismatchesRequest(t *testing.T) {
	w, ro, encKey := responseHarness(t, sdjwtPIDQuery)
	form, err := w.BuildResponse(context.Background(), ro, WithWrongState())
	qt.Assert(t, qt.IsNil(err))
	_, state := decryptResponse(t, form, encKey)
	qt.Assert(t, qt.Not(qt.Equals(state, ro.State))) // state binding (step 1) fails
}

func TestExtraCredentialAddsUnrequestedEntry(t *testing.T) {
	w, ro, encKey := responseHarness(t, sdjwtPIDQuery)
	form, err := w.BuildResponse(context.Background(), ro, WithExtraCredential("extra"))
	qt.Assert(t, qt.IsNil(err))
	vpToken, _ := decryptResponse(t, form, encKey)
	qt.Assert(t, qt.Equals(len(vpToken["pid"]), 1))   // requested credential present
	qt.Assert(t, qt.Equals(len(vpToken["extra"]), 1)) // unrequested one too → over-disclosure; real oid4vp.ProcessResponse
	// rejects the unknown vp_token key at step 1 (response_integrity), before structured
	// credentials exist — confirmed in the matrix, see matrix_test.go.
}

// TestDuplicateCredentialReusesAcrossQueryIDs proves the combined-presentation
// fault: ONE credential's exact bytes answer EVERY query id (ARF Topic 18 /
// pipeline step 9), NOT the same id presented twice (which is a DCQL
// multiple-not-allowed failure at step 8, a different step). Cross-id reuse
// keeps exactly one candidate per id — so step 8 is satisfied and step 9 is the
// first check that can reject the reuse. Design:
// `pres = firstPresentation`.
func TestDuplicateCredentialReusesAcrossQueryIDs(t *testing.T) {
	const twoCred = `{"credentials":[` +
		`{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]},` +
		`{"id":"pid2","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}`
	w, ro, encKey := responseHarness(t, twoCred)
	form, err := w.BuildResponse(context.Background(), ro, WithDuplicateCredential())
	qt.Assert(t, qt.IsNil(err))
	vpToken, _ := decryptResponse(t, form, encKey)
	qt.Assert(t, qt.Equals(len(vpToken["pid"]), 1))  // exactly one presentation per id (step 8 satisfied)
	qt.Assert(t, qt.Equals(len(vpToken["pid2"]), 1)) // ...for both ids
	// Byte-identical across two different query ids → combined-check (step 9).
	qt.Assert(t, qt.Equals(vpToken["pid"][0], vpToken["pid2"][0]))
}

// ---- helpers ------------------------------------------------------------

func responseHarness(t *testing.T, queryJSON string) (*Wallet, *RequestObject, *ecdsa.PrivateKey) {
	t.Helper()
	pki := NewPKI(t)
	w := New(pki, nil, NewStatusLists(pki))
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	q, err := dcql.Parse([]byte(queryJSON))
	qt.Assert(t, qt.IsNil(err))
	ro := &RequestObject{
		ClientID:      "x509_san_dns:verifier.test",
		Nonce:         "nonce-1",
		State:         "state-1",
		ResponseURI:   "https://verifier.test/wallet/S1/response",
		EncryptionKey: &encKey.PublicKey,
		Query:         q,
	}
	return w, ro, encKey
}

func decryptResponse(t *testing.T, form url.Values, encKey *ecdsa.PrivateKey) (map[string][]string, string) {
	t.Helper()
	respTok := form.Get("response")
	qt.Assert(t, qt.IsTrue(respTok != ""))
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"enc": encKey})
	pt, _, err := crypto.DecryptJWE(context.Background(), kp, "enc", []byte(respTok))
	qt.Assert(t, qt.IsNil(err))
	var body struct {
		VPToken map[string][]string `json:"vp_token"`
		State   string              `json:"state"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(pt, &body)))
	return body.VPToken, body.State
}

// statusBitSet decodes the served status-list token and reports whether the
// bit at ref.Index is set (status value 1 = INVALID). This mirrors the real
// evaluation, so it self-verifies the revocation fault (step 5).
func statusBitSet(t *testing.T, sl *StatusLists, ref StatusRef, statusKey stdcrypto.PublicKey) bool {
	t.Helper()
	tok, err := sl.Get(context.Background(), ref.URI)
	qt.Assert(t, qt.IsNil(err))
	payload, _, err := crypto.VerifyJWS(tok, statusKey)
	qt.Assert(t, qt.IsNil(err))
	var claims struct {
		StatusList struct {
			Lst string `json:"lst"`
		} `json:"status_list"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(payload, &claims)))
	comp, err := base64.RawURLEncoding.DecodeString(claims.StatusList.Lst)
	qt.Assert(t, qt.IsNil(err))
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	qt.Assert(t, qt.IsNil(err))
	defer func() { _ = zr.Close() }()
	raw, err := io.ReadAll(zr)
	qt.Assert(t, qt.IsNil(err))
	if ref.Index/8 >= len(raw) {
		return false
	}
	return raw[ref.Index/8]&(1<<(ref.Index%8)) != 0
}

// TestSDJWTDCAPIAudienceIsOriginPrefixed pins the Key Binding audience for
// browser-based presentations to the literal value the specification names,
// not to whatever this wallet and this verifier happen to agree on.
//
// [OID4VP §A.4]: the audience "MUST be the Origin, prefixed with
// `origin:`", and that "is the case even for signed requests" — so the Client
// Identifier is not the audience there. Asserting the exact string is the
// point: both sides of a private agreement can drift together and every test
// still passes, which is how the Client-Identifier audience survived here
// unnoticed until an unsigned request (which carries no Client Identifier at
// all) made it impossible.
func TestSDJWTDCAPIAudienceIsOriginPrefixed(t *testing.T) {
	const origin = "https://rp.example"
	w, ro := faultWallet(t)

	pres, err := w.present(context.Background(), ro, mustQuery(t, sdjwtPIDQuery), &presentSpec{dcapiOrigin: origin})
	qt.Assert(t, qt.IsNil(err))

	_, err = sdjwt.NewVerifier().Verify(context.Background(), sdjwt.VerifyInput{
		Presentation:  []byte(pres),
		IssuerKey:     w.pki.DSKey.Public(),
		ExpectedAud:   "origin:https://rp.example",
		ExpectedNonce: ro.Nonce,
		RequireKB:     true,
	})
	qt.Assert(t, qt.IsNil(err))

	// And the Client Identifier is NOT accepted as the audience there.
	_, err = sdjwt.NewVerifier().Verify(context.Background(), sdjwt.VerifyInput{
		Presentation:  []byte(pres),
		IssuerKey:     w.pki.DSKey.Public(),
		ExpectedAud:   ro.ClientID,
		ExpectedNonce: ro.Nonce,
		RequireKB:     true,
	})
	qt.Assert(t, qt.IsNotNil(err))
}

// anchorTrust is the mdoc trust boundary for these tests: it validates the
// issuer chain against a fixed anchor set at the credential's own signing time,
// which is the model the service runs by default.
type anchorTrust struct{ anchors []*x509.Certificate }

func (a anchorTrust) ResolveIssuerKey(x5chain [][]byte, signed time.Time) (stdcrypto.PublicKey, error) {
	leaf, err := x509.ParseCertificate(x5chain[0])
	if err != nil {
		return nil, err
	}
	if _, err := crypto.VerifyChain(leaf, nil, crypto.ChainOptions{Anchors: a.anchors, At: signed}); err != nil {
		return nil, err
	}
	return leaf.PublicKey, nil
}
