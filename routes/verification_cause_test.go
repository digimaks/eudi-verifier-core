package routes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dativa-lv/eudi-verifier-core/internal/policy"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessions"
	"github.com/dativa-lv/eudi-verifier-core/internal/testwallet"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// The test wallet's status authority (internal/testwallet/statuslist.go). Every
// credential it issues references this list, so it is what a resolution failure
// must name.
const testStatusListURI = "https://status.test/1"

// causeReport is the persisted report with the two fields this feature adds —
// the failing check's own account of the cause, and the list it was about.
type causeReport struct {
	Outcome  string `json:"outcome"`
	FailCode string `json:"fail_code"`
	Checks   []struct {
		Name          string `json:"name"`
		Outcome       string `json:"outcome"`
		Code          string `json:"code"`
		Detail        string `json:"detail"`
		StatusListURI string `json:"status_list_uri"`
	} `json:"checks"`
}

// last returns the check the pipeline stopped on — the failing one, since the
// run short-circuits at the first failure.
func (r causeReport) last() struct {
	Name          string `json:"name"`
	Outcome       string `json:"outcome"`
	Code          string `json:"code"`
	Detail        string `json:"detail"`
	StatusListURI string `json:"status_list_uri"`
} {
	return r.Checks[len(r.Checks)-1]
}

// causeRun drives one real presentation through the whole pipeline and returns
// everything the three surfaces say about it: the persisted report, the log
// records emitted while it ran, and the session id so a test can also read the
// internal report route.
//
// The logger is swapped for an observer sink BEFORE the presentation, so the
// warn line is captured exactly as a real sink would receive it.
func causeRun(t *testing.T, pol policy.ClientPolicy, prepare func(f *fixture), faults ...testwallet.FaultOption) (*fixture, string, causeReport, *observer.ObservedLogs) {
	t.Helper()

	f := newFixture(t)
	if prepare != nil {
		prepare(f)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	qt.Assert(t, qt.IsNil(f.app.ReplaceLogger(zap.New(core))))

	created, err := f.app.SessionCreator().Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-cause",
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
	var r causeReport
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &r)))
	return f, created.SessionID, r, logs
}

// failureLines returns the verification-failure records the run emitted. The
// count matters as much as the content: one per failed verification, never one
// per check and never one per request.
func failureLines(logs *observer.ObservedLogs) []observer.LoggedEntry {
	return logs.FilterMessage("verification failed").All()
}

func field(t *testing.T, e observer.LoggedEntry, key string) (string, bool) {
	t.Helper()
	for _, f := range e.Context {
		if f.Key == key {
			return f.String, true
		}
	}
	return "", false
}

// The failure this whole feature exists for: a status list the verifier cannot
// resolve. All three surfaces must name the cause AND the list — the public
// code alone cannot distinguish this from a list signed by an unresolvable key.
func TestUnresolvableStatusListNamesCauseAndListEverywhere(t *testing.T) {
	f, sessionID, r, logs := causeRun(t, policy.ClientPolicy{},
		func(f *fixture) { f.wallet.Status.Break() })

	// 1. The persisted report.
	qt.Assert(t, qt.Equals(r.Outcome, "failed"))
	qt.Assert(t, qt.Equals(r.FailCode, "err:revocation:unavailable"))
	failed := r.last()
	qt.Assert(t, qt.Equals(failed.Name, "revocation"))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(failed.Detail, "statuslist: status list could not be fetched")))
	qt.Assert(t, qt.Equals(failed.StatusListURI, testStatusListURI))

	// 2. The log line — exactly one, and it carries the same account.
	lines := failureLines(logs)
	qt.Assert(t, qt.Equals(len(lines), 1))
	qt.Assert(t, qt.Equals(lines[0].Level, zapcore.WarnLevel))
	check, ok := field(t, lines[0], "check")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(check, "revocation"))
	code, _ := field(t, lines[0], "code")
	qt.Assert(t, qt.Equals(code, "err:revocation:unavailable"))
	cause, _ := field(t, lines[0], "cause")
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(cause, "statuslist: status list could not be fetched")))
	uri, ok := field(t, lines[0], "status_list_uri")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(uri, testStatusListURI))

	// 3. The internal route — the same bytes, on demand, without the log or the
	// database.
	status, body := internalGet(t, f.tapp, "/internal/v1/sessions/"+sessionID+"/report", bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, 200))
	qt.Assert(t, qt.StringContains(string(body), `"detail":"statuslist: status list could not be fetched`))
	qt.Assert(t, qt.StringContains(string(body), `"status_list_uri":"`+testStatusListURI+`"`))
}

// A revoked credential is a DIFFERENT outcome from an unresolvable one: the
// list was read and it said revoked. There is nothing to diagnose about the
// list, so no URI is recorded — the boundary between "here is where to look"
// and "here is a holder's credential" is kept deliberately.
func TestRevokedCredentialRecordsNoListURI(t *testing.T) {
	_, _, r, logs := causeRun(t, policy.ClientPolicy{}, nil, testwallet.WithRevokedCredential())

	qt.Assert(t, qt.Equals(r.FailCode, "err:revocation:revoked"))
	failed := r.last()
	qt.Assert(t, qt.Equals(failed.Name, "revocation"))
	qt.Assert(t, qt.StringContains(failed.Detail, "revoked"))
	qt.Assert(t, qt.Equals(failed.StatusListURI, ""))

	lines := failureLines(logs)
	qt.Assert(t, qt.Equals(len(lines), 1))
	_, hasURI := field(t, lines[0], "status_list_uri")
	qt.Assert(t, qt.IsFalse(hasURI)) // absent, not empty
}

// The line is about whichever check failed, not about revocation: a failure
// three steps earlier must be named just as precisely, and must not acquire a
// status-list field it has nothing to do with.
func TestFailureAtAnotherStepNamesThatStep(t *testing.T) {
	_, _, r, logs := causeRun(t, policy.ClientPolicy{}, nil, testwallet.WithWrongNonce())

	failed := r.last()
	qt.Assert(t, qt.Equals(failed.Outcome, "fail"))
	qt.Assert(t, qt.Not(qt.Equals(failed.Name, "revocation")))

	lines := failureLines(logs)
	qt.Assert(t, qt.Equals(len(lines), 1))
	check, _ := field(t, lines[0], "check")
	qt.Assert(t, qt.Equals(check, failed.Name))
	code, _ := field(t, lines[0], "code")
	qt.Assert(t, qt.Equals(code, failed.Code))
	_, hasURI := field(t, lines[0], "status_list_uri")
	qt.Assert(t, qt.IsFalse(hasURI))
}

// A verification that succeeds says nothing: no failure line at all. This is
// what keeps the line one-per-failure rather than one-per-request — the report
// route stays available for the successful run all the same.
func TestVerifiedRunLogsNoFailureLine(t *testing.T) {
	f, sessionID, r, logs := causeRun(t, policy.ClientPolicy{}, nil)

	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
	qt.Assert(t, qt.Equals(len(failureLines(logs)), 0))

	status, body := internalGet(t, f.tapp, "/internal/v1/sessions/"+sessionID+"/report", bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, 200))
	qt.Assert(t, qt.StringContains(string(body), `"outcome":"verified"`))
}

// An explicit fail-open policy turns the same unresolvable list into a visible
// skip rather than a failure — so there is no failure line, and the relaxation
// stays readable in the report instead.
func TestFailOpenLogsNoFailureLine(t *testing.T) {
	skip := false
	_, _, r, logs := causeRun(t, policy.ClientPolicy{RevocationFailClosedP: &skip},
		func(f *fixture) { f.wallet.Status.Break() })

	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
	qt.Assert(t, qt.Equals(len(failureLines(logs)), 0))
}
