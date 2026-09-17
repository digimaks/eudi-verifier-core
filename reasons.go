package verifiercore

import (
	"sync"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
)

var reasonsOnce sync.Once

// RegisterReasons teaches the kit taxonomy every non-built-in reason this
// service produces (reason strings are
// append-only). Call once, before platform.Setup.
//
// NOT registered here (kit built-ins, non-overridable): not-found(404),
// expired(410), revoked(410), forbidden(403), conflict(409), invalid(400).
// err:credential:expired and err:revocation:revoked are pinned to
// 422 — applied via pkerrors.WithStatus(422) at the FailCode→problem site,
// routes/processor_pipeline.go's walletFailProblem (asserted there). That 422
// is the problem-object / problem+json status; the wallet boundary speaks OID4VP
// error shapes, so it renders 400 invalid_request rather than the problem status.
//
// The status registered here nonetheless DECIDES what the wallet is told: the
// wallet boundary reads it to separate a refusal it should report from a fault
// of ours it must not blame on the wallet (routes/wallet_error.go). Registering
// a reason with the wrong status therefore misreports it on both surfaces at
// once — which is the point of there being one rating rather than two.
func RegisterReasons() {
	reasonsOnce.Do(func() {
		reg := func(reason string, status int, title string) {
			pkerrors.RegisterReason(reason, pkerrors.ReasonSpec{Status: status, Title: title})
		}
		reg("consumed", 409, "Session already consumed")
		reg("invalid-response", 400, "Invalid presentation response")
		reg("nonce-mismatch", 400, "Nonce binding failed")
		reg("query-unfulfilled", 422, "Query not fulfilled")
		reg("combined-check", 422, "Combined presentation check failed")
		reg("parse", 422, "Credential malformed")
		reg("issuer-untrusted", 422, "Issuer not trusted")
		// The issuer's own certificate was outside its validity window at the
		// instant the deployment judges the path at. Rated with issuer-untrusted
		// because it is the same kind of answer — the presentation verified, the
		// credential is refused — and it needs registering explicitly: the
		// fallback rating matches whole reason words, so "expired" is recognised
		// and "issuer-cert-expired" is not, which would make a routine refusal
		// arrive at the wallet as a server fault.
		reg("issuer-cert-expired", 422, "Issuer certificate expired")
		// The wallet refused and reported why, rather than presenting something
		// that failed. Client-visible (400): it is the wallet's own outcome, so
		// telling it so is correct, and rating it a fault of ours would blame the
		// messenger. err:presentation:wallet-declined.
		reg("wallet-declined", 400, "Wallet reported an error")
		reg("integrity", 422, "Credential integrity check failed")
		reg("binding-failed", 422, "Device or user binding failed")
		reg("unavailable", 422, "Revocation status unavailable")    // err:revocation:unavailable
		reg("anchor-unavailable", 503, "Trust anchors unavailable") // err:trust:anchor-unavailable
		reg("handoff-failed", 503, "Result handoff failed")         // err:session:handoff-failed
		reg("internal", 500, "Internal verification error")         // err:pipeline:internal
	})
}
