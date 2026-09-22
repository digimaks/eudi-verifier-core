package routes

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
	"github.com/digimaks/eudi-verifier-core/internal/policy"
	"github.com/digimaks/eudi-verifier-core/internal/sessions"
	"github.com/digimaks/eudi-verifier-core/internal/testwallet"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
)

type fullReport struct {
	Outcome     string          `json:"outcome"`
	FailCode    string          `json:"fail_code"`
	Policy      map[string]bool `json:"policy"`
	Checks      []struct{ Name, Outcome, Code string }
	Credentials []struct {
		StatusProvenance string `json:"status_provenance"`
	} `json:"credentials"`
}

func policyRun(t *testing.T, pol policy.ClientPolicy, breakStatus func(f *fixture), faults ...testwallet.FaultOption) fullReport {
	t.Helper()
	f := newFixture(t)
	if breakStatus != nil {
		breakStatus(f)
	}
	created, err := f.app.SessionCreator().Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-pol",
		Flow: oid4vp.CrossDevice, Query: *dcql.PresetPIDFull(), Policy: pol,
		WebhookURL: "https://client.test/hook",
	})
	qt.Assert(t, qt.IsNil(err))
	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	_, _, err = f.wallet.Respond(t.Context(), ro, faults...)
	qt.Assert(t, qt.IsNil(err))

	raw, err := f.app.SessionDB().GetReport(t.Context(), created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	var r fullReport
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &r)))
	return r
}

func boolp(b bool) *bool { return &b }

// Branch 1 — fail-closed default: status list unobtainable ⇒ verification fails.
func TestRevocationUnavailableFailsClosedByDefault(t *testing.T) {
	r := policyRun(t, policy.ClientPolicy{}, func(f *fixture) { f.wallet.Status.Break() })
	qt.Assert(t, qt.Equals(r.Outcome, "failed"))
	qt.Assert(t, qt.Equals(r.FailCode, "err:revocation:unavailable"))
	qt.Assert(t, qt.IsTrue(r.Policy["revocation_fail_closed"]))
}

// Branch 2 — explicit fail-open: verification proceeds, skip VISIBLE in report.
func TestRevocationUnavailableFailOpenIsVisible(t *testing.T) {
	r := policyRun(t, policy.ClientPolicy{RevocationFailClosedP: boolp(false)},
		func(f *fixture) { f.wallet.Status.Break() })
	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
	qt.Assert(t, qt.IsFalse(r.Policy["revocation_fail_closed"]))
	for _, c := range r.Checks {
		if c.Name == pipeline.CheckRevocation {
			qt.Assert(t, qt.Equals(c.Outcome, "skipped")) // shows in report
		}
	}
	qt.Assert(t, qt.StringContains(r.Credentials[0].StatusProvenance, "fail-open"))
}

// Branch 3 — short-lived exemption: <24h validity skips the status check with
// the provenance VERBATIM.
func TestShortLivedExemption(t *testing.T) {
	r := policyRun(t, policy.ClientPolicy{}, nil, testwallet.WithValidity(2*time.Hour))
	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
	// The real provenance
	// string is statuslist.OutcomeSkippedShortLived == "skipped-short-lived"
	// (status.go:65), not the originally pinned
	// "status-skipped-short-lived", and NOT string(statuslist.StatusSkippedShortLived)
	// (StatusSkippedShortLived is a Status/int — that conversion is a
	// rune-conversion bug, not a string form).
	qt.Assert(t, qt.Equals(r.Credentials[0].StatusProvenance, "skipped-short-lived"))
}

// Branch 3b — exemption disabled: <24h credential still checked.
func TestShortLivedExemptionDisabled(t *testing.T) {
	r := policyRun(t, policy.ClientPolicy{ShortLivedExemptionP: boolp(false)}, nil,
		testwallet.WithValidity(2*time.Hour), testwallet.WithRevokedCredential())
	qt.Assert(t, qt.Equals(r.Outcome, "failed"))
	qt.Assert(t, qt.Equals(r.FailCode, "err:revocation:revoked"))
	qt.Assert(t, qt.IsFalse(r.Policy["short_lived_exemption"]))
}

// Branch 4 — revoked under fail-open still fails (fail-open covers
// UNAVAILABILITY, never a positive revoked answer).
func TestRevokedFailsEvenFailOpen(t *testing.T) {
	r := policyRun(t, policy.ClientPolicy{RevocationFailClosedP: boolp(false)}, nil,
		testwallet.WithRevokedCredential())
	qt.Assert(t, qt.Equals(r.Outcome, "failed"))
	qt.Assert(t, qt.Equals(r.FailCode, "err:revocation:revoked"))
}

// The error taxonomy pins
// err:credential:expired and err:revocation:revoked to HTTP 422. Both reason
// strings are kit built-ins that otherwise resolve to 410 (gone/expired/revoked),
// so walletFailProblem is the ONE site that applies the documented
// WithStatus(422) override. This asserts the resulting problem OBJECT carries
// status 422 (its problem+json status). NOTE: the wallet does not SEE 422 — the
// wallet boundary speaks OID4VP error shapes and renders 400 invalid_request.
// What the 422 decides is that the wallet is told at all: being rated
// client-visible is what marks the outcome a refusal to report rather than a
// fault of ours (routes/wallet_error.go, TestVerificationOutcome_*).
func TestWalletFailProblemStatus422(t *testing.T) {
	for _, code := range []string{"err:credential:expired", "err:revocation:revoked"} {
		var p *pkerrors.Problem
		qt.Assert(t, qt.IsTrue(errors.As(walletFailProblem(code), &p)),
			qt.Commentf("walletFailProblem(%q) must be a *pkerrors.Problem", code))
		qt.Assert(t, qt.Equals(p.Status, 422)) // the taxonomy pins 422, not the built-in 410
	}
	// A FailCode outside the override list keeps its taxonomy-derived status:
	// err:session:not-found is a kit built-in ⇒ 404 (proves the override is
	// scoped to the two codes only, never a blanket 422).
	var other *pkerrors.Problem
	qt.Assert(t, qt.IsTrue(errors.As(walletFailProblem("err:session:not-found"), &other)))
	qt.Assert(t, qt.Equals(other.Status, 404))
}
