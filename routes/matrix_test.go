package routes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
	"github.com/digimaks/eudi-verifier-core/internal/policy"
	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"
	"github.com/digimaks/eudi-verifier-core/internal/sessions"
	"github.com/digimaks/eudi-verifier-core/internal/testwallet"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/go-quicktest/qt"
)

// failingSink poisons step 10 only (matrix row 10).
type failingSink struct{}

func (failingSink) Deliver(context.Context, *sessiondb.Session, *pipeline.Result) error {
	return context.DeadlineExceeded
}

type persistedReport struct {
	Outcome  string `json:"outcome"`
	FailCode string `json:"fail_code"`
	Checks   []struct {
		Name    string `json:"name"`
		Outcome string `json:"outcome"`
		Code    string `json:"code"`
		SpecRef string `json:"spec_ref"`
	} `json:"checks"`
}

func report(t *testing.T, f *fixture, id string) persistedReport {
	t.Helper()
	raw, err := f.app.SessionDB().GetReport(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	var r persistedReport
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &r)))
	return r
}

// assertOnlyStepFailed: all earlier checks pass-or-skip, the target check
// fails with the exact code, and no later check appears (short-circuit).
func assertOnlyStepFailed(t *testing.T, r persistedReport, step, code string) {
	t.Helper()
	qt.Assert(t, qt.Equals(r.Outcome, "failed"))
	qt.Assert(t, qt.Equals(r.FailCode, code))
	last := r.Checks[len(r.Checks)-1]
	qt.Assert(t, qt.Equals(last.Name, step))
	qt.Assert(t, qt.Equals(last.Outcome, "fail"))
	qt.Assert(t, qt.Equals(last.Code, code))
	qt.Assert(t, qt.Equals(last.SpecRef, pipeline.SpecRefs[step])) // client-visible specRef from THE table
	for _, c := range r.Checks[:len(r.Checks)-1] {
		qt.Assert(t, qt.IsTrue(c.Outcome == "pass" || c.Outcome == "skipped"),
			qt.Commentf("earlier check %s must not fail (got %s)", c.Name, c.Outcome))
	}
	// Short-circuit: nothing after the failed step.
	idx := map[string]int{}
	for i, name := range pipeline.AllChecks {
		idx[name] = i
	}
	for _, c := range r.Checks {
		qt.Assert(t, qt.IsTrue(idx[c.Name] <= idx[step]))
	}
}

func run(t *testing.T, f *fixture, created *sessions.Created, faults ...testwallet.FaultOption) persistedReport {
	t.Helper()
	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	status, _, err := f.wallet.Respond(t.Context(), ro, faults...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(status >= 400)) // every matrix row is a failure at the wallet boundary
	return report(t, f, created.SessionID)
}

// mustParse parses a DCQL query for the matrix or fails the test.
func mustParse(t *testing.T, raw string) *dcql.Query {
	t.Helper()
	q, err := dcql.Parse([]byte(raw))
	qt.Assert(t, qt.IsNil(err))
	return q
}

func TestFaultMatrixEachStepFailsAlone(t *testing.T) {
	// combinedQuery: two SD-JWT credential ids BOTH requesting family_name, so the
	// SAME reused credential (WithDuplicateCredential, cross-id) satisfies both —
	// step 8 (query_fulfilment) passes and the reuse first fails at step 9
	// (combined_checks). The original two-cred query asked pid2 for a
	// DIFFERENT claim (given_name); with cross-id reuse that fails at step 8
	// (claims-unsatisfied) instead of step 9, so both ids must request the same
	// claim for the combined-check to be the step under test.
	twoCredQuery := mustParse(t, `{"credentials":[
		{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
		 "claims":[{"path":["family_name"]}]},
		{"id":"pid2","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
		 "claims":[{"path":["family_name"]}]}]}`)
	// Single SD-JWT query. Used for faults verified against the SD-JWT format
	// library (present_test.go uses the equivalent sdjwtPIDQuery): the
	// SD-JWT presentation string is NOT base64url-decoded at step 1, so malformed
	// SD-JWT survives to step 2's sdjwt.Peek — whereas PresetPIDFull also carries
	// an mdoc credential, whose non-base64url garbage fails ProcessResponse's
	// mandatory base64url decode at step 1 (ErrMalformedResponse), never reaching
	// step 2. It also carries an explicit claims member so WithMissingClaim can
	// withhold a REQUESTED claim (PresetPIDFull requests no specific claims, so
	// nothing is withholdable and the query is trivially satisfied).
	sdjwtQuery := mustParse(t, `{"credentials":[
		{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
		 "claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}`)
	mdocQuery := mustParse(t, `{"credentials":[
		{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},
		 "claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]}]}]}`)
	// mdoc query with two elements, so WithMissingClaim can withhold one and
	// leave the query unsatisfied at step 8 (mdoc variant of the SD-JWT row).
	mdocTwoClaimQuery := mustParse(t, `{"credentials":[
		{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},
		 "claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]},
		           {"path":["eu.europa.ec.eudi.pid.1","given_name"]}]}]}`)

	relaxed := policy.ClientPolicy{}
	no := false
	relaxed.RequireDeviceBindingSDJWTP = &no
	noKBQuery := mustParse(t, `{"credentials":[
		{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
		 "require_cryptographic_holder_binding":false,
		 "claims":[{"path":["family_name"]}]}]}`)

	type row struct {
		name   string
		step   string
		code   string
		query  *dcql.Query
		policy policy.ClientPolicy
		faults []testwallet.FaultOption
	}
	rows := []row{
		// 1 — response_integrity ([OID4VP §8.2] state binding).
		{"wrong state", pipeline.CheckResponseIntegrity, "err:presentation:nonce-mismatch",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithWrongState()}},
		// 2 — parse (SD-JWT: malformed bytes survive step 1's response parse — an
		// SD-JWT presentation is not base64url-decoded there — and fail step 2's
		// sdjwt.Peek; an mdoc's malformed bytes would fail base64url decode at step 1).
		{"malformed credential", pipeline.CheckParse, "err:credential:parse",
			sdjwtQuery, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithMalformedCredential()}},
		// 3 — issuer_authenticity.
		{"unregistered issuer", pipeline.CheckIssuerAuthenticity, "err:credential:issuer-untrusted",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithUnregisteredIssuer()}},
		// 4 — data_integrity (SD-JWT variant; mdoc digest tamper covered separately).
		{"tampered digest", pipeline.CheckDataIntegrity, "err:credential:integrity",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithTamperedDigest()}},
		// 5 — revocation.
		{"revoked credential", pipeline.CheckRevocation, "err:revocation:revoked",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithRevokedCredential()}},
		// 6 — device_binding: SD-JWT stale KB + wrong nonce, and mdoc wrong transcript.
		{"stale KB-JWT", pipeline.CheckDeviceBinding, "err:credential:binding-failed",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithStaleKBJWT(time.Hour)}},
		{"wrong nonce in KB", pipeline.CheckDeviceBinding, "err:credential:binding-failed",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithWrongNonce()}},
		{"mdoc wrong transcript", pipeline.CheckDeviceBinding, "err:credential:binding-failed",
			mdocQuery, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithWrongTranscript()}},
		// 7 — user_binding fails ALONE: policy+query waive device binding (6
		// = skipped), wallet presents without KB, v1 user binding requires 6.
		{"user binding without device binding", pipeline.CheckUserBinding, "err:credential:binding-failed",
			noKBQuery, relaxed, []testwallet.FaultOption{testwallet.WithoutKBJWT()}},
		// 8 — query_fulfilment: under-disclose a REQUESTED claim (SD-JWT + mdoc).
		{"missing requested claim (sd-jwt)", pipeline.CheckQueryFulfilment, "err:presentation:query-unfulfilled",
			sdjwtQuery, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithMissingClaim(`["family_name"]`)}},
		{"missing requested claim (mdoc)", pipeline.CheckQueryFulfilment, "err:presentation:query-unfulfilled",
			mdocTwoClaimQuery, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithMissingClaim(`["eu.europa.ec.eudi.pid.1","family_name"]`)}},
		// 1 (over-disclosure): an unrequested credential id is rejected at the
		// PROTOCOL boundary (ProcessResponse / step 1), before the pipeline
		// can reach step 8 — presentationsFromVPToken returns ErrUnknownCredentialID
		// ("no over-disclosure enters the pipeline silently"). The original design
		// filed over-disclosure under step 8, but the shipped
		// engine defends it earlier; proving that here keeps the fault meaningful.
		{"over-disclosure (unknown credential id)", pipeline.CheckResponseIntegrity, "err:presentation:invalid-response",
			nil, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithExtraCredential("unrequested")}},
		// 9 — combined_checks: ONE credential (cross-id reuse) answers BOTH query
		// ids of twoCredQuery. Each id gets exactly one candidate (step 8 passes);
		// the two ids sharing one artifact is the ARF Topic 18 independence
		// violation step 9 rejects.
		{"duplicate credential across query ids", pipeline.CheckCombinedChecks, "err:presentation:combined-check",
			twoCredQuery, policy.ClientPolicy{}, []testwallet.FaultOption{testwallet.WithDuplicateCredential()}},
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			q := tc.query
			if q == nil {
				q = dcql.PresetPIDFull()
			}
			created, err := f.app.SessionCreator().Create(t.Context(), sessions.CreateInput{
				ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-matrix",
				Flow: oid4vp.CrossDevice, Query: *q, Policy: tc.policy,
				WebhookURL: "https://client.test/hook",
			})
			qt.Assert(t, qt.IsNil(err))
			r := run(t, f, created, tc.faults...)
			assertOnlyStepFailed(t, r, tc.step, tc.code)
		})
	}
}

// Row 1b — replay: second POST fails before the pipeline (session consumed);
// the FIRST run's report stays verified (replay must not corrupt it).
func TestFaultMatrixReplay(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)
	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))

	status, _, err := f.wallet.Respond(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, 200))

	status2, body2, err := f.wallet.Respond(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(status2 >= 400))
	qt.Assert(t, qt.IsTrue(len(body2) > 0)) // OID4VP error body

	r := report(t, f, created.SessionID)
	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
}

// Anchor staleness => err:trust:anchor-unavailable at
// issuer_authenticity + degraded readiness. Fail closed, never skip.
func TestStaleAnchorCacheFailsClosed(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)
	f.app.ExpireTestAnchors() // Static.Expire() behind an App test hook
	r := run(t, f, created)
	assertOnlyStepFailed(t, r, pipeline.CheckIssuerAuthenticity, "err:trust:anchor-unavailable")
}

// Row 10 — assemble_forward fails alone: poison the sink; all nine earlier
// checks pass, step 10 fails with err:session:handoff-failed.
func TestFaultMatrixHandoffFailure(t *testing.T) {
	f := newFixture(t)
	f.app.SetResultSink(failingSink{})
	created := f.createSession(t, oid4vp.CrossDevice)
	r := run(t, f, created)
	assertOnlyStepFailed(t, r, pipeline.CheckAssembleForward, "err:session:handoff-failed")
	qt.Assert(t, qt.Equals(len(r.Checks), 10)) // every check executed
}

// Happy-path control: all ten checks present and pass/skip-free.
func TestFaultMatrixHappyPathAllTenPass(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)
	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	status, _, err := f.wallet.Respond(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, 200))

	r := report(t, f, created.SessionID)
	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
	qt.Assert(t, qt.Equals(len(r.Checks), 10))
	for i, c := range r.Checks {
		qt.Assert(t, qt.Equals(c.Name, pipeline.AllChecks[i])) // canonical order
		qt.Assert(t, qt.Equals(c.Outcome, "pass"))
	}
}
