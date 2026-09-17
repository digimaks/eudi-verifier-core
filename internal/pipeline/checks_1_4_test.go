package pipeline

import (
	"errors"
	"fmt"
	"testing"

	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	sdjwt "github.com/gmb-eudi/go-sdjwt"

	"github.com/go-quicktest/qt"
)

// The single attribution table (Locked pipeline contract): typed error class
// → (report step, err code). Wrapped errors must classify identically.
func TestClassifyFormatError(t *testing.T) {
	tests := []struct {
		err      error
		wantStep string
		wantCode string
	}{
		{sdjwt.ErrMalformed, CheckParse, "err:credential:parse"},
		{sdjwt.ErrIssuerSignature, CheckIssuerAuthenticity, "err:credential:issuer-untrusted"},
		{sdjwt.ErrExpired, CheckIssuerAuthenticity, "err:credential:expired"},
		// ErrNotYetValid is ErrExpired's sibling (errors.go: both
		// err:credential:expired) — nbf-in-the-future vs exp-in-the-past.
		{sdjwt.ErrNotYetValid, CheckIssuerAuthenticity, "err:credential:expired"},
		{sdjwt.ErrDigestMismatch, CheckDataIntegrity, "err:credential:integrity"},
		// ErrDuplicateDigest/ErrClaimCollision are sdjwt's own
		// err:credential:integrity sentinels (errors.go), same class as
		// ErrDigestMismatch, both raised inside reconstruct() during Verify.
		{sdjwt.ErrDuplicateDigest, CheckDataIntegrity, "err:credential:integrity"},
		{sdjwt.ErrClaimCollision, CheckDataIntegrity, "err:credential:integrity"},
		// No single sdjwt.ErrKB sentinel exists — every real
		// KB-class sentinel must attribute to step 6 identically.
		{sdjwt.ErrKBRequired, CheckDeviceBinding, "err:credential:binding-failed"},
		{sdjwt.ErrKBType, CheckDeviceBinding, "err:credential:binding-failed"},
		{sdjwt.ErrKBSignature, CheckDeviceBinding, "err:credential:binding-failed"},
		{sdjwt.ErrKBAudience, CheckDeviceBinding, "err:credential:binding-failed"},
		{sdjwt.ErrKBNonce, CheckDeviceBinding, "err:credential:binding-failed"},
		{sdjwt.ErrKBStale, CheckDeviceBinding, "err:credential:binding-failed"},
		{sdjwt.ErrKBSDHash, CheckDeviceBinding, "err:credential:binding-failed"},
		// ErrMissingCNF (errors.go: err:credential:binding-failed) is holder
		// binding required but cnf absent — same class as the KB sentinels.
		{sdjwt.ErrMissingCNF, CheckDeviceBinding, "err:credential:binding-failed"},
		{mdoc.ErrMalformed, CheckParse, "err:credential:parse"},
		{mdoc.ErrIssuerAuth, CheckIssuerAuthenticity, "err:credential:issuer-untrusted"},
		{mdoc.ErrValidity, CheckIssuerAuthenticity, "err:credential:expired"},
		{mdoc.ErrIntegrity, CheckDataIntegrity, "err:credential:integrity"},
		{mdoc.ErrDeviceAuth, CheckDeviceBinding, "err:credential:binding-failed"},
		// ErrDeviceMacUnsupported (errors.go: err:credential:binding-failed) is
		// deviceMac presented where remote flows require deviceSignature — a
		// device-authentication-class failure like ErrDeviceAuth.
		{mdoc.ErrDeviceMacUnsupported, CheckDeviceBinding, "err:credential:binding-failed"},
		{trust.ErrCacheExpired, CheckIssuerAuthenticity, "err:trust:anchor-unavailable"},
		// An expired certificate is NOT an unknown issuer. Both sentinels reach
		// here — the trust layer's when a certificate on the path was outside its
		// window at the validation time, the mdoc one when the credential's
		// signing time fell outside its signer's window — and both must be
		// distinguishable from issuer-untrusted, which is what a relying party
		// acts on differently.
		{trust.ErrChainOutOfValidity, CheckIssuerAuthenticity, "err:credential:issuer-cert-expired"},
		{mdoc.ErrIssuerCertValidity, CheckIssuerAuthenticity, "err:credential:issuer-cert-expired"},
		{trust.ErrChainUntrusted, CheckIssuerAuthenticity, "err:credential:issuer-untrusted"},
		{errors.New("anything else"), CheckIssuerAuthenticity, "err:credential:issuer-untrusted"},
	}
	for _, tc := range tests {
		t.Run(tc.wantCode+"/"+tc.wantStep, func(t *testing.T) {
			step, code := classifyFormatError(wrap(tc.err))
			qt.Assert(t, qt.Equals(step, tc.wantStep))
			qt.Assert(t, qt.Equals(code, tc.wantCode))
		})
	}
}

// wrap proves classification is done via errors.Is (survives %w wrapping),
// never a top-level identity comparison.
func wrap(err error) error { return fmt.Errorf("outer: %w", err) }

// The default map reproduces the old hardcoded classification —
// PID identifiers → PID-provider; anything else → QEAA → PubEAA → EAA.
func TestDefaultCredentialTrustIssuance(t *testing.T) {
	m := DefaultCredentialTrust()
	qt.Assert(t, qt.DeepEquals(m.Issuance("eu.europa.ec.eudi.pid.1"),
		[]trust.AnchorType{trust.PIDProvider}))
	qt.Assert(t, qt.DeepEquals(m.Issuance("urn:eudi:pid:1"),
		[]trust.AnchorType{trust.PIDProvider}))
	qt.Assert(t, qt.DeepEquals(m.Issuance("org.iso.18013.5.1.mDL"),
		[]trust.AnchorType{trust.QEAAProvider, trust.PubEAAProvider, trust.EAAProvider}))
}

// Status-list signer resolution tries *_status anchors
// first (derived via trust.StatusType), then the issuer provider anchors.
func TestDefaultCredentialTrustStatus(t *testing.T) {
	m := DefaultCredentialTrust()
	qt.Assert(t, qt.DeepEquals(m.Status("eu.europa.ec.eudi.pid.1"),
		[]trust.AnchorType{trust.PIDProviderStatus, trust.PIDProvider}))
	qt.Assert(t, qt.DeepEquals(m.Status("org.iso.18013.5.1.mDL"),
		[]trust.AnchorType{
			trust.QEAAProviderStatus, trust.PubEAAProviderStatus, trust.EAAProviderStatus,
			trust.QEAAProvider, trust.PubEAAProvider, trust.EAAProvider,
		}))
}

// A NEW credential type is onboarded via config, not a
// recompile. A configured class wins over the default fallback, and its status
// types are derived automatically.
func TestConfiguredCredentialTrustOnboardsNewType(t *testing.T) {
	m, err := ParseCredentialTrust([]byte(`{"classes":[
		{"types":["urn:example:health:1"],"issuance":["qeaa_provider"]}
	]}`))
	qt.Assert(t, qt.IsNil(err))
	// The new vct maps to exactly the configured issuer type…
	qt.Assert(t, qt.DeepEquals(m.Issuance("urn:example:health:1"),
		[]trust.AnchorType{trust.QEAAProvider}))
	// …its status resolution derives qeaa_provider_status first, then issuer.
	qt.Assert(t, qt.DeepEquals(m.Status("urn:example:health:1"),
		[]trust.AnchorType{trust.QEAAProviderStatus, trust.QEAAProvider}))
	// …and the built-in PID default still applies (config merges over default).
	qt.Assert(t, qt.DeepEquals(m.Issuance("urn:eudi:pid:1"),
		[]trust.AnchorType{trust.PIDProvider}))
}

// EAA trust scoped by use case — an anchor accredited for use case A
// must not vouch for a credential scoped to B, and a use-case-scoped credential
// is rejected by an anchor with no declared use cases (fail closed).
func TestCredentialTrustUseCaseScoping(t *testing.T) {
	m, err := ParseCredentialTrust([]byte(`{"classes":[
		{"types":["org.iso.18013.5.1.mDL"],"issuance":["eaa_provider"],"use_case":"mdl"}
	]}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(m.UseCaseFor("org.iso.18013.5.1.mDL"), "mdl"))
	qt.Assert(t, qt.Equals(m.UseCaseFor("urn:eudi:pid:1"), "")) // unscoped by default

	qt.Assert(t, qt.IsTrue(useCaseAllowed("mdl", []string{"mdl"})))      // accredited for the use case
	qt.Assert(t, qt.IsFalse(useCaseAllowed("mdl", []string{"diploma"}))) // trusted for A, rejected for B
	qt.Assert(t, qt.IsFalse(useCaseAllowed("mdl", nil)))                 // fail closed: no declared use cases
	qt.Assert(t, qt.IsTrue(useCaseAllowed("", nil)))                     // unscoped credential: always allowed
}

func TestParseRejectsGarbagePresentation(t *testing.T) {
	pc := NewContext("01JZXS", nil, nil)
	pc.Presentations = oid4vpPresentationFixture("pid", "dc+sd-jwt", []byte("not-a-credential\x00"))
	res, err := Parse().Run(t.Context(), pc)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Outcome, OutcomeFail))
	qt.Assert(t, qt.Equals(res.Code, "err:credential:parse"))
}

// oid4vpPresentationFixture builds a one-entry vp_token for a check unit test.
func oid4vpPresentationFixture(id, format string, payload []byte) []oid4vp.Presentation {
	return []oid4vp.Presentation{{QueryCredID: id, Format: format, Payload: payload}}
}
