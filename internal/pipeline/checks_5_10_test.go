package pipeline

import (
	"context"
	"testing"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
	statuslist "github.com/gmb-eudi/go-statuslist"

	"github.com/go-quicktest/qt"
)

// presFixture builds a single oid4vp.Presentation for a check unit test (the
// per-entry analogue of oid4vpPresentationFixture, which wraps a
// one-element slice).
func presFixture(id, format string, payload []byte) oid4vp.Presentation {
	return oid4vp.Presentation{QueryCredID: id, Format: format, Payload: payload}
}

func TestUserBindingRequiresDeviceBinding(t *testing.T) {
	pc := NewContext("01JZXS", nil, nil)
	pc.Credentials = []*Credential{{Pres: presFixture("a", "dc+sd-jwt", nil), DeviceBindingCheck: OutcomeSkipped}}
	res, err := UserBinding().Run(context.Background(), pc)
	qt.Assert(t, qt.IsNil(err))
	// [ARF §6.6.3.9] option 1: user binding = assertion that
	// device binding PASSED. Skipped device binding ⇒ user binding fails.
	qt.Assert(t, qt.Equals(res.Outcome, OutcomeFail))
	qt.Assert(t, qt.Equals(res.Code, "err:credential:binding-failed"))
}

func TestUserBindingPassesWhenBound(t *testing.T) {
	pc := NewContext("01JZXS", nil, nil)
	pc.Credentials = []*Credential{
		{Pres: presFixture("a", "dc+sd-jwt", nil), DeviceBindingCheck: OutcomePass, StatusResult: statuslist.StatusValid},
	}
	res, err := UserBinding().Run(context.Background(), pc)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Outcome, OutcomePass))
}

func TestCombinedChecksRejectsDuplicateCredential(t *testing.T) {
	pc := NewContext("01JZXS", nil, nil)
	same := []byte("identical-presentation-bytes")
	pc.Credentials = []*Credential{
		{Pres: presFixture("a", "dc+sd-jwt", same)},
		{Pres: presFixture("b", "dc+sd-jwt", same)},
	}
	res, err := CombinedChecks().Run(context.Background(), pc)
	qt.Assert(t, qt.IsNil(err))
	// ARF Topic 18: each credential independently presented; the same
	// artifact answering two query ids is a combined-presentation violation.
	qt.Assert(t, qt.Equals(res.Outcome, OutcomeFail))
	qt.Assert(t, qt.Equals(res.Code, "err:presentation:combined-check"))
}

func TestCombinedChecksPassesDistinctCredentials(t *testing.T) {
	pc := NewContext("01JZXS", nil, nil)
	pc.Credentials = []*Credential{
		{Pres: presFixture("a", "dc+sd-jwt", []byte("one"))},
		{Pres: presFixture("b", "mso_mdoc", []byte("two"))},
	}
	res, err := CombinedChecks().Run(context.Background(), pc)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Outcome, OutcomePass))
}

// TestZeroClearsAttributeBuffers proves Zero (finalize.go) best-effort scrubs
// every attribute-carrying buffer after handoff (ARF AS-RP-51-011/013): the
// raw presentation payload, the reconstructed SD-JWT claim map, and the
// Result's per-credential claim values.
func TestZeroClearsAttributeBuffers(t *testing.T) {
	pc := NewContext("01JZXS", nil, nil)
	payload := []byte("attribute-bearing-bytes")
	sd := &sdjwt.VerifiedCredential{Claims: map[string]any{"family_name": "X"}}
	pc.Credentials = []*Credential{{Pres: presFixture("pid", "dc+sd-jwt", payload), SD: sd}}
	res := &Result{Credentials: []ResultCredential{{Claims: map[string]any{"family_name": "X"}}}}

	Zero(pc, res)

	for _, b := range payload {
		qt.Assert(t, qt.Equals(b, byte(0)))
	}
	qt.Assert(t, qt.Equals(len(sd.Claims), 0))
	qt.Assert(t, qt.Equals(len(res.Credentials[0].Claims), 0))
}
