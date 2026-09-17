package routes

import (
	"encoding/json"
	"testing"

	verifiercore "github.com/dativa-lv/eudi-verifier-core"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/go-quicktest/qt"
)

// decodeWalletError reads the OID4VP error shape the wallet actually receives.
func decodeWalletError(t *testing.T, body []byte) (code, desc string) {
	t.Helper()

	var out map[string]string
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))

	return out["error"], out["error_description"]
}

// TestVerificationOutcome_RefusalsReachTheWallet pins the wallet-boundary answer
// for every verification outcome the pipeline can end on. A refusal must arrive
// as a refusal: reporting it as a server fault is what left a tester unable to
// tell a trust-data gap from a crash.
//
// The two descriptions are the point of the split — a credential we will not
// accept is a different problem for the operator than a presentation that did
// not verify.
func TestVerificationOutcome_RefusalsReachTheWallet(t *testing.T) {
	verifiercore.RegisterReasons()

	tests := []struct {
		name     string
		failCode string
		status   int
		desc     string
	}{
		// Refused credential — the response verified, the credential is not accepted.
		{"issuer not trusted", "err:credential:issuer-untrusted", 400, descNotAccepted},
		{"revoked", "err:revocation:revoked", 400, descNotAccepted},
		{"expired", "err:credential:expired", 400, descNotAccepted},
		// The signer's certificate was outside its window at the instant the
		// deployment judges the path at. Live-observed as a 500 before it was
		// rated: the fallback recognises the word "expired" and not this code.
		{"issuer certificate expired", "err:credential:issuer-cert-expired", 400, descNotAccepted},

		// Failed presentation — the response itself did not hold up.
		{"invalid response", "err:presentation:invalid-response", 400, descNotVerified},
		{"nonce mismatch", "err:presentation:nonce-mismatch", 400, descNotVerified},
		{"malformed credential", "err:credential:parse", 400, descNotVerified},
		{"integrity", "err:credential:integrity", 400, descNotVerified},
		{"binding failed", "err:credential:binding-failed", 400, descNotVerified},
		{"query unfulfilled", "err:query:query-unfulfilled", 400, descNotVerified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body, ok := verificationOutcome(walletFailProblem(tt.failCode))
			qt.Assert(t, qt.IsTrue(ok))
			qt.Check(t, qt.Equals(status, tt.status))

			code, desc := decodeWalletError(t, body)
			qt.Check(t, qt.Equals(code, walletErrInvalidRequest))
			qt.Check(t, qt.Equals(desc, tt.desc))
		})
	}
}

// TestVerificationOutcome_OurFaultsStayServerErrors is the other half of the
// rule, and the one a careless widening would break: an outcome the reason
// registry rates a server fault is OURS, must not be dressed as the wallet's
// fault, and must leak nothing. None of these codes is listed in this package —
// they are excluded by their registry rating alone.
func TestVerificationOutcome_OurFaultsStayServerErrors(t *testing.T) {
	verifiercore.RegisterReasons()

	ours := []string{
		"err:trust:anchor-unavailable", // 503 — our trust cache, not their credential
		"err:session:handoff-failed",   // 503 — our result delivery
		"err:pipeline:internal",        // 500
		"err:something:unregistered",   // no rating at all ⇒ fails closed
	}

	for _, code := range ours {
		t.Run(code, func(t *testing.T) {
			_, _, ok := verificationOutcome(walletFailProblem(code))
			qt.Check(t, qt.IsFalse(ok))
		})
	}
}

// TestVerificationOutcome_NonProblemErrorsDelegate keeps the layering honest:
// the protocol sentinels stay the engine's to map, so this classifier must
// decline anything that is not one of our problems.
func TestVerificationOutcome_NonProblemErrorsDelegate(t *testing.T) {
	_, _, ok := verificationOutcome(errStub{})
	qt.Check(t, qt.IsFalse(ok))
}

type errStub struct{}

func (errStub) Error() string { return "not a problem" }

// TestVerificationOutcome_StatusComesFromTheRegistry proves the status is read
// from the registry rather than a table kept here: a problem carrying an
// explicit server status is refused even though its code is one this file names
// as a trust refusal.
func TestVerificationOutcome_StatusComesFromTheRegistry(t *testing.T) {
	verifiercore.RegisterReasons()

	_, _, ok := verificationOutcome(
		pkerrors.NewProblem("err:credential:issuer-untrusted", pkerrors.WithStatus(503)),
	)
	qt.Check(t, qt.IsFalse(ok))
}
