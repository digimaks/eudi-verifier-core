package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

type stubCheck struct {
	name string
	res  CheckResult
	err  error
	ran  *[]string
}

func (s stubCheck) Name() string { return s.name }
func (s stubCheck) Run(_ context.Context, _ *PipelineContext) (CheckResult, error) {
	*s.ran = append(*s.ran, s.name)
	return s.res, s.err
}

func TestOrderedShortCircuit(t *testing.T) {
	var ran []string
	e := &Engine{checks: []Check{
		stubCheck{name: "response_integrity", res: CheckResult{Outcome: OutcomePass}, ran: &ran},
		stubCheck{name: "parse", res: CheckResult{Outcome: OutcomeFail, Code: "err:credential:parse"}, ran: &ran},
		stubCheck{name: "issuer_authenticity", res: CheckResult{Outcome: OutcomePass}, ran: &ran},
	}}
	pc := NewContext("01JZXS", nil, nil)
	rep := e.Run(context.Background(), pc)

	qt.Assert(t, qt.DeepEquals(ran, []string{"response_integrity", "parse"})) // short-circuited
	qt.Assert(t, qt.Equals(rep.Outcome, "failed"))
	qt.Assert(t, qt.Equals(rep.FailCode, "err:credential:parse"))
	qt.Assert(t, qt.Equals(len(rep.Checks), 2)) // per-check accumulation up to the failure
	qt.Assert(t, qt.Equals(rep.Checks[1].SpecRef, SpecRefs[CheckParse]))
}

func TestSkippedContinues(t *testing.T) {
	var ran []string
	e := &Engine{checks: []Check{
		stubCheck{name: "revocation", res: CheckResult{Outcome: OutcomeSkipped, Code: "status-skipped-short-lived"}, ran: &ran},
		stubCheck{name: "device_binding", res: CheckResult{Outcome: OutcomePass}, ran: &ran},
	}}
	rep := e.Run(context.Background(), NewContext("01JZXS", nil, nil))
	qt.Assert(t, qt.Equals(rep.Outcome, "verified"))
	qt.Assert(t, qt.Equals(rep.Checks[0].Outcome, OutcomeSkipped)) // skip is visible, not silent
}

func TestInfrastructureErrorMapsToCode(t *testing.T) {
	var ran []string
	boom := errors.New("valkey down")
	e := &Engine{checks: []Check{
		stubCheck{name: "assemble_forward", err: boom, ran: &ran},
	}}
	rep := e.Run(context.Background(), NewContext("01JZXS", nil, nil))
	qt.Assert(t, qt.Equals(rep.Outcome, "failed"))
	qt.Assert(t, qt.Equals(rep.Checks[0].Code, "err:pipeline:internal")) // unmapped error → internal
}

// fakeRecorder is a pipeline.Recorder test double: it records which
// checks were started/finished and how many times the full-pipeline duration
// was observed, without touching any real metrics/tracing backend.
type fakeRecorder struct {
	started  []string
	outcomes []string
	observed int
}

func (f *fakeRecorder) StartCheck(ctx context.Context, check string) (context.Context, func(string)) {
	f.started = append(f.started, check)
	return ctx, func(outcome string) { f.outcomes = append(f.outcomes, outcome) }
}

func (f *fakeRecorder) ObservePipeline(time.Duration) { f.observed++ }

// TestRecorderSeesOnlyExecutedChecksAndObservesFullRunOnce proves two of the
// self-review requirements: (1) the recorder is only told about
// checks that actually ran (short-circuit is unaffected — it sees exactly the
// same two checks TestOrderedShortCircuit's ran slice does) with their real
// outcomes, and (2) ObservePipeline fires exactly ONCE per Run call — on the
// short-circuit return path, not just the full-completion path — so it is a
// genuine full-pipeline latency measurement (the p95 basis).
func TestRecorderSeesOnlyExecutedChecksAndObservesFullRunOnce(t *testing.T) {
	var ran []string
	rec := &fakeRecorder{}
	e := (&Engine{checks: []Check{
		stubCheck{name: "response_integrity", res: CheckResult{Outcome: OutcomePass}, ran: &ran},
		stubCheck{name: "parse", res: CheckResult{Outcome: OutcomeFail, Code: "err:credential:parse"}, ran: &ran},
		stubCheck{name: "issuer_authenticity", res: CheckResult{Outcome: OutcomePass}, ran: &ran},
	}}).WithRecorder(rec)

	rep := e.Run(context.Background(), NewContext("01JZXS", nil, nil))

	qt.Assert(t, qt.Equals(rep.Outcome, "failed")) // unchanged from TestOrderedShortCircuit
	qt.Assert(t, qt.DeepEquals(rec.started, []string{"response_integrity", "parse"}))
	qt.Assert(t, qt.DeepEquals(rec.outcomes, []string{"pass", "fail"}))
	qt.Assert(t, qt.Equals(rec.observed, 1))
}

// TestNilRecorderIsNoOp proves a nil Engine.recorder (New(...)'s default, and
// every Engine{checks: …} literal the existing tests in this file build)
// leaves Run's behavior byte-for-byte identical to before — no panic,
// same report.
func TestNilRecorderIsNoOp(t *testing.T) {
	var ran []string
	e := New(stubCheck{name: "response_integrity", res: CheckResult{Outcome: OutcomePass}, ran: &ran})
	rep := e.Run(context.Background(), NewContext("01JZXS", nil, nil))
	qt.Assert(t, qt.Equals(rep.Outcome, "verified"))
}

// spanWrappingRecorder simulates what an otel-backed Recorder's StartCheck
// really does: it returns a DIFFERENT concrete context.Context (via
// context.WithValue, as trace.ContextWithSpan does), never the ctx it was
// given.
type spanWrappingRecorder struct{}

type spanMarkerKey struct{}

func (spanWrappingRecorder) StartCheck(ctx context.Context, _ string) (context.Context, func(string)) {
	return context.WithValue(ctx, spanMarkerKey{}, "span"), func(string) {}
}

func (spanWrappingRecorder) ObservePipeline(time.Duration) {}

type ctxCapturingCheck struct{ got context.Context }

func (*ctxCapturingCheck) Name() string { return "response_integrity" }
func (c *ctxCapturingCheck) Run(ctx context.Context, _ *PipelineContext) (CheckResult, error) {
	c.got = ctx
	return CheckResult{Outcome: OutcomePass}, nil
}

// TestCheckRunsWithOriginalContextNotSpanWrapped locks in the deliberate
// choice documented on Engine.Run: the span-scoped context StartCheck returns
// must NOT reach Check.Run. app.go's production status-list fetcher
// type-asserts its ctx to *azugo.Context (statusFetch.Get, reached from the
// revocation check via statuslist.Checker.Check); an otel-wrapped context is
// a distinct concrete type and would fail that assertion, turning every
// production revocation check into an infrastructure failure. If this test
// ever fails, Engine.Run has started threading the recorder's context into
// checks and MUST be reverted.
func TestCheckRunsWithOriginalContextNotSpanWrapped(t *testing.T) {
	type rootMarkerKey struct{}
	base := context.WithValue(context.Background(), rootMarkerKey{}, "root")

	c := &ctxCapturingCheck{}
	e := New(c).WithRecorder(spanWrappingRecorder{})
	e.Run(base, NewContext("01JZXS", nil, nil))

	qt.Assert(t, qt.Equals(c.got, base))
	qt.Assert(t, qt.IsNil(c.got.Value(spanMarkerKey{}))) // never the recorder's derived context
}
