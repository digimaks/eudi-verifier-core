package verifiercore

import (
	"testing"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-lib/go-platform-kit/observability"
)

// redactedLogger boots the eudi-verifier-core TestApp (testing.go), swaps its
// logger for an observer sink, and re-applies observability.EnableRedaction
// against that sink core so the assertion sees exactly what a production sink
// would receive.
//
// The kit does not export a bare
// core-wrapper (no `WrapRedactingCore`) — the redacting decorator
// (`redactCore`) is unexported; only `EnableRedaction(app *azugo.App, policy)`
// is exported, and it wraps whatever core is *currently* installed on the app
// and re-installs it via App.ReplaceLogger (see go-platform-kit's
// observability redaction). So instead of
// wrapping an observer core directly, this installs the observer core first
// (via ReplaceLogger) and then calls EnableRedaction, which wraps that same
// core — the log record captured by `logs` has gone through the identical
// redactCore.Write path a real sink would.
func redactedLogger(t *testing.T, policy *observability.RedactionPolicy) (*zap.Logger, *observer.ObservedLogs) {
	t.Helper()

	app := TestApp(t)

	core, logs := observer.New(zapcore.DebugLevel)
	qt.Assert(t, qt.IsNil(app.ReplaceLogger(zap.New(core))))
	observability.EnableRedaction(app.App, policy)

	return app.Log(), logs
}

func TestClaimValueNeverReachesSink(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	const canary = "CANARY-CLAIM-VALUE-77f1"
	lg.Info("pipeline check done",
		zap.String("claim_value", canary),        // DROPPED (claim values)
		zap.String("disclosure_salt", canary),    // DROPPED (salts)
		zap.String("vp_token", canary),           // DROPPED (raw vp_token)
		zap.String("kb_jwt_payload", canary),     // DROPPED
		zap.String("device_signature", canary),   // DROPPED
		zap.String("portrait", canary),           // DROPPED
		zap.String("biometric_template", canary), // DROPPED
		zap.String("document_number", canary),    // DROPPED
		zap.String("given_name", canary),         // MASKED (fleet default)
		zap.String("check", "device_binding"),    // kept — outcome identifiers are fine
		// NOTE: deliberately NOT "session_id" here. The fleet default already
		// DropKeys "session" (any field whose key merely *contains* "session"
		// — kit's own observability.TestRedaction_DropsSecrets asserts
		// "session_id" must be dropped, treating it as sensitive by
		// substring). So a literal "session_id" field is silently dropped
		// even without our extension — discovered by this end-to-end test.
		// Pipeline logging must identify a session via
		// "correlation_id" (bound by platform-kit's correlation middleware:
		// github.com/gmb-lib/go-platform-kit/correlation.LogKeyCorrelationID),
		// never a bespoke "session_id"/"*session*" log field.
		zap.String("correlation_id", "01JZX0S"), // kept
	)

	qt.Assert(t, qt.Equals(logs.Len(), 1))
	entry := logs.All()[0]
	for _, f := range entry.Context {
		qt.Assert(t, qt.Not(qt.Equals(f.String, canary)),
			qt.Commentf("field %q leaked the claim value", f.Key))
	}

	// Identifiers survive:
	found := map[string]string{}
	for _, f := range entry.Context {
		found[f.Key] = f.String
	}
	qt.Assert(t, qt.Equals(found["check"], "device_binding"))
	qt.Assert(t, qt.Equals(found["correlation_id"], "01JZX0S"))
}

// TestSessionIDFieldIsDroppedByFleetDefault documents (does not merely assume)
// that a literal "session_id" log field is dropped by the kit's fleet default
// — NOT by this project's extension — because DropKeys contains the substring
// "session". This is intentional fleet behavior (mirrors the kit's own
// observability.TestRedaction_DropsSecrets), recorded here so a future
// pipeline task doesn't reach for "session_id" as a log field and silently
// lose it. Use "correlation_id" instead.
func TestSessionIDFieldIsDroppedByFleetDefault(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	lg.Info("session lookup", zap.String("session_id", "01JZX0S"))

	qt.Assert(t, qt.Equals(logs.Len(), 1))
	for _, f := range logs.All()[0].Context {
		qt.Assert(t, qt.Not(qt.Equals(f.Key, "session_id")),
			qt.Commentf("session_id is expected to be dropped by the fleet default policy (DropKeys contains \"session\")"))
	}
}

// The fleet defaults must survive extension (add, never weaken).
func TestFleetDefaultsRetained(t *testing.T) {
	p := RedactionPolicy()
	def := observability.DefaultRedactionPolicy()
	for _, k := range def.DropKeys {
		qt.Assert(t, qt.SliceContains(p.DropKeys, k))
	}
	for _, k := range def.MaskKeys {
		qt.Assert(t, qt.SliceContains(p.MaskKeys, k))
	}
}

// The verification-failure line is only useful if it survives the sink. Its
// fields go through the same redacting core every log record does, and a policy
// that grew a key colliding with one of them would blank the diagnostic
// silently — the line would still appear, saying nothing. So the exact field
// set is pinned here against the real policy.
//
// What this does NOT claim: that redaction is what keeps claim values out of
// these fields. That guarantee is structural — the report type cannot hold a
// claim value (it reduces claims to names), and the check detail comes from
// library errors that carry none. Redaction is the second line, not the first.
func TestVerificationFailureFieldsSurviveRedaction(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	const (
		cause = "statuslist: status list token signature verification failed: ecdsa: verification error"
		uri   = "https://status.example/statuslist/lv/pid/abc123"
	)
	lg.Warn("verification failed",
		zap.String("check", "revocation"),
		zap.String("code", "err:revocation:unavailable"),
		zap.String("cause", cause),
		zap.String("spec_ref", "[ARF §6.6.3.7]"),
		zap.String("status_list_uri", uri),
	)

	entries := logs.FilterMessage("verification failed").All()
	qt.Assert(t, qt.Equals(len(entries), 1))

	got := map[string]string{}
	for _, f := range entries[0].Context {
		got[f.Key] = f.String
	}
	qt.Assert(t, qt.Equals(got["check"], "revocation"))
	qt.Assert(t, qt.Equals(got["code"], "err:revocation:unavailable"))
	qt.Assert(t, qt.Equals(got["cause"], cause))
	qt.Assert(t, qt.Equals(got["spec_ref"], "[ARF §6.6.3.7]"))
	qt.Assert(t, qt.Equals(got["status_list_uri"], uri))
}
