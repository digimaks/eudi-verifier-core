package testwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
	statuslist "github.com/gmb-eudi/go-statuslist"

	"github.com/go-quicktest/qt"
)

// TestPKIAnchorsChainToIACARoot proves the anchor set a real trust.AnchorSource
// could serve actually validates the harness's document-signer cert
// (go-eudi-crypto explicit-anchor path validation).
func TestPKIAnchorsChainToIACARoot(t *testing.T) {
	pki := NewPKI(t)
	anchors := pki.Anchors()
	qt.Assert(t, qt.IsTrue(len(anchors) >= 2)) // PID-provider + wallet-provider at minimum

	found := false
	for _, a := range anchors {
		if a.Type == trust.PIDProvider {
			found = true
			// The DS cert must chain to this anchor.
			chains, err := crypto.VerifyChain(pki.DSCert, nil, crypto.ChainOptions{
				Anchors: []*x509.Certificate{a.Cert}, At: time.Now(),
			})
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsTrue(len(chains) > 0))
		}
	}
	qt.Assert(t, qt.IsTrue(found))
}

// TestRogueAnchorsNotTrusted proves the rogue chain is genuinely NOT part of the
// trusted set: a rogue-signed leaf fails path validation against the anchor set,
// while the genuine DS leaf succeeds (issuer-authenticity fault is producible).
func TestRogueAnchorsNotTrusted(t *testing.T) {
	pki := NewPKI(t)
	qt.Assert(t, qt.IsNil(pki.RogueAnchors())) // rogue chain must not be resolvable

	var trusted []*x509.Certificate
	for _, a := range pki.Anchors() {
		trusted = append(trusted, a.Cert)
	}

	_, err := crypto.VerifyChain(pki.RogueCert, nil, crypto.ChainOptions{Anchors: trusted, At: time.Now()})
	qt.Assert(t, qt.IsNotNil(err)) // rogue DS does not chain to any trusted anchor

	_, err = crypto.VerifyChain(pki.DSCert, nil, crypto.ChainOptions{Anchors: trusted, At: time.Now()})
	qt.Assert(t, qt.IsNil(err)) // genuine DS does — the anchor set is real
}

// TestStatusListsServeAndRevoke exercises the in-memory Token Status List
// authority: it serves a signed token whose sub binds to the list URI, and a
// revoke changes the served list content.
func TestStatusListsServeAndRevoke(t *testing.T) {
	pki := NewPKI(t)
	sl := NewStatusLists(pki)
	ref := sl.NewRef() // fresh index on the test list

	tok, err := sl.Get(context.Background(), ref.URI)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(len(tok) > 0))

	// Token verifies with the status signer key and says: not revoked.
	payload, _, err := crypto.VerifyJWS(tok, pki.StatusKey.Public())
	qt.Assert(t, qt.IsNil(err))
	var claims map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(payload, &claims)))
	qt.Assert(t, qt.Equals(claims["sub"].(string), ref.URI))

	sl.Revoke(ref)
	tok2, err := sl.Get(context.Background(), ref.URI)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.DeepEquals(tok, tok2))) // list content changed
	var _ statuslist.Fetcher = sl                  // implements the fetcher seam
}

// TestParseRequestObject feeds ParseRequestObject a JAR built inline with
// crypto.SignJWS (the harness does not yet depend on request-object
// construction) and asserts the OID4VP members are extracted.
func TestParseRequestObject(t *testing.T) {
	pki := NewPKI(t)
	w := New(pki, nil, NewStatusLists(pki))

	// Verifier ephemeral encryption key advertised in client_metadata.jwks.
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	jwk, err := crypto.ECPublicKeyToJWK(encKey.Public())
	qt.Assert(t, qt.IsNil(err))

	claims := map[string]any{
		"client_id":    "x509_san_dns:verifier.test",
		"nonce":        "n-1",
		"state":        "s-1",
		"response_uri": "https://verifier.test/wallet/S1/response",
		"dcql_query": json.RawMessage(`{"credentials":[{"id":"pid","format":"dc+sd-jwt",` +
			`"meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}`),
		"client_metadata": map[string]any{"jwks": map[string]any{"keys": []map[string]any{jwk}}},
	}
	body, err := json.Marshal(claims)
	qt.Assert(t, qt.IsNil(err))

	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"sig": pki.DSKey})
	jar, err := crypto.SignJWS(context.Background(), kp, "sig",
		map[string]any{"typ": "oauth-authz-req+jwt", "x5c": []*x509.Certificate{pki.DSCert, pki.IACARoot}}, body)
	qt.Assert(t, qt.IsNil(err))

	ro, err := w.ParseRequestObject(jar)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ro.ClientID, "x509_san_dns:verifier.test"))
	qt.Assert(t, qt.Equals(ro.Nonce, "n-1"))
	qt.Assert(t, qt.Equals(ro.State, "s-1"))
	qt.Assert(t, qt.Equals(ro.ResponseURI, "https://verifier.test/wallet/S1/response"))
	qt.Assert(t, qt.IsNotNil(ro.Query))
	qt.Assert(t, qt.Equals(len(ro.Query.Credentials), 1))
	qt.Assert(t, qt.IsNotNil(ro.EncryptionKey))
}

// TestPresentSDJWTHappyPath proves the happy-path wallet issues and presents a
// valid SD-JWT VC: the presentation verifies with the real sdjwt.Verifier under
// the request's aud/nonce, with a KB-JWT required.
func TestPresentSDJWTHappyPath(t *testing.T) {
	pki := NewPKI(t)
	w := New(pki, nil, NewStatusLists(pki))
	ro := happyRequest(t)

	q, err := dcql.Parse([]byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt",` +
		`"meta":{"vct_values":["urn:eudi:pid:1"]},` +
		`"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}`))
	qt.Assert(t, qt.IsNil(err))

	pres, err := w.present(context.Background(), ro, &q.Credentials[0], &presentSpec{})
	qt.Assert(t, qt.IsNil(err))

	v := sdjwt.NewVerifier()
	vc, err := v.Verify(context.Background(), sdjwt.VerifyInput{
		Presentation:  []byte(pres),
		IssuerKey:     pki.DSKey.Public(),
		ExpectedAud:   ro.ClientID,
		ExpectedNonce: ro.Nonce,
		RequireKB:     true,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(vc.VCT, "urn:eudi:pid:1"))
	_, hasFamily := vc.Claims["family_name"]
	qt.Assert(t, qt.IsTrue(hasFamily))
	_, hasGiven := vc.Claims["given_name"]
	qt.Assert(t, qt.IsTrue(hasGiven))
	qt.Assert(t, qt.IsNotNil(vc.Status)) // carries a status_list reference
}

// TestPresentMdocHappyPath proves the happy-path wallet issues and presents a
// valid mdoc DeviceResponse: it verifies with the real mdoc.Verifier, bound to
// the OID4VP handover derived from the request's ephemeral encryption key.
func TestPresentMdocHappyPath(t *testing.T) {
	pki := NewPKI(t)
	w := New(pki, nil, NewStatusLists(pki))
	ro := happyRequest(t)

	q, err := dcql.Parse([]byte(`{"credentials":[{"id":"pid","format":"mso_mdoc",` +
		`"meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},` +
		`"claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]}]}]}`))
	qt.Assert(t, qt.IsNil(err))

	pres, err := w.present(context.Background(), ro, &q.Credentials[0], &presentSpec{})
	qt.Assert(t, qt.IsNil(err))

	respBytes, err := base64.RawURLEncoding.DecodeString(pres)
	qt.Assert(t, qt.IsNil(err))

	thumb, err := crypto.JWKThumbprintBytes(ro.EncryptionKey)
	qt.Assert(t, qt.IsNil(err))
	st := mdoc.OID4VPHandover(ro.ClientID, ro.Nonce, thumb, ro.ResponseURI)

	v := mdoc.NewVerifier()
	docs, err := v.Verify(context.Background(), mdoc.VerifyInput{
		DeviceResponse:    respBytes,
		SessionTranscript: st,
		IssuerTrust:       anchorTrust{anchors: []*x509.Certificate{pki.IACARoot}},
		ExpectedDocType:   "eu.europa.ec.eudi.pid.1",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(docs), 1))
	_, hasNS := docs[0].Namespaces["eu.europa.ec.eudi.pid.1"]
	qt.Assert(t, qt.IsTrue(hasNS))
	qt.Assert(t, qt.IsNotNil(docs[0].Status)) // carries a status_list reference
}

// TestBuildResponseEncryptsVPToken proves the honest wallet assembles the
// direct_post.jwt body: a compact JWE that decrypts (with the RP ephemeral
// private key) to {vp_token, state}, keyed by the DCQL credential id.
func TestBuildResponseEncryptsVPToken(t *testing.T) {
	pki := NewPKI(t)
	w := New(pki, nil, NewStatusLists(pki))

	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	q, err := dcql.Parse([]byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt",` +
		`"meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}`))
	qt.Assert(t, qt.IsNil(err))
	ro := &RequestObject{
		ClientID: "x509_san_dns:verifier.test", Nonce: "nonce-1", State: "state-1",
		ResponseURI:   "https://verifier.test/wallet/S1/response",
		EncryptionKey: &encKey.PublicKey, Query: q,
	}

	form, err := w.BuildResponse(context.Background(), ro)
	qt.Assert(t, qt.IsNil(err))
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
	qt.Assert(t, qt.Equals(body.State, "state-1"))
	qt.Assert(t, qt.Equals(len(body.VPToken["pid"]), 1))
}

// happyRequest builds a minimal RequestObject with a verifier ephemeral
// encryption key, for BuildResponse-level and present-level tests.
func happyRequest(t *testing.T) *RequestObject {
	t.Helper()
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	return &RequestObject{
		ClientID:      "x509_san_dns:verifier.test",
		Nonce:         "nonce-1",
		State:         "state-1",
		ResponseURI:   "https://verifier.test/wallet/S1/response",
		EncryptionKey: &encKey.PublicKey,
	}
}
