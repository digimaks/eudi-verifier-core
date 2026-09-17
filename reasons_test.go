package verifiercore

import (
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/go-quicktest/qt"
)

// Taxonomy — every reason eudi-verifier-core produces, with its
// pinned HTTP status. `expired` and `revoked` are kit BUILT-INS (410) and
// cannot be re-registered (RegisterReason panics on built-ins); their 422
// mapping is applied at the single production site via
// WithStatus — asserted in pipeline tests.
func TestRegisterReasonsPinsStatuses(t *testing.T) {
	RegisterReasons() // must be idempotent per process; second call is a no-op guard

	tests := []struct {
		code   string
		status int
	}{
		{"err:session:not-found", 404},      // built-in reason "not-found"
		{"err:session:consumed", 409},       // registered
		{"err:session:handoff-failed", 503}, // registered (new)
		{"err:presentation:invalid-response", 400},
		{"err:presentation:nonce-mismatch", 400},
		{"err:presentation:query-unfulfilled", 422},
		{"err:presentation:combined-check", 422}, // registered (new)
		{"err:credential:parse", 422},
		{"err:credential:issuer-untrusted", 422},
		{"err:credential:issuer-cert-expired", 422}, // registered (new): unrated, it fell through to 500
		{"err:credential:integrity", 422},
		{"err:credential:binding-failed", 422},
		{"err:revocation:unavailable", 422},
		{"err:trust:anchor-unavailable", 503},
		{"err:pipeline:internal", 500}, // registered (new)
	}
	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			p := pkerrors.NewProblem(tc.code)
			qt.Assert(t, qt.Equals(p.Status, tc.status))
		})
	}
}
