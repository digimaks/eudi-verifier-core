package obs

import (
	"strings"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/go-quicktest/qt"

	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
)

// Label values must come from closed sets (check enum × outcome enum) —
// never session ids, never anything derived from wallet input (no PII in
// labels).
func TestRecorderUsesClosedLabelSets(t *testing.T) {
	r := NewRecorder()
	qt.Assert(t, qt.IsNil(r.validate("response_integrity", "pass")))
	qt.Assert(t, qt.IsNil(r.validate("assemble_forward", "fail")))
	qt.Assert(t, qt.IsNotNil(r.validate("01JZXSESSION", "pass"))) // not a check name
	qt.Assert(t, qt.IsNotNil(r.validate("parse", "TESTSSON")))    // not an outcome
}

// Recorder must satisfy the narrow pipeline.Recorder seam without pipeline
// importing this package (dependency direction: obs -> pipeline for
// AllChecks only).
func TestRecorderSatisfiesPipelineInterface(_ *testing.T) {
	var _ pipeline.Recorder = NewRecorder()
}

// StartCheck/done must emit exactly the documented counter series, and must
// never panic or emit anything for a check/outcome pair outside the closed
// sets (defense in depth — Engine.Run can only ever pass AllChecks names and
// Outcome values, but the recorder must not trust that blindly).
func TestStartCheckEmitsCounter(t *testing.T) {
	r := NewRecorder()
	_, done := r.StartCheck(t.Context(), "response_integrity")
	done("pass")

	dump := dumpMetrics(t)
	qt.Assert(t, qt.IsTrue(strings.Contains(dump,
		`verifier_core_pipeline_check_total{check="response_integrity",outcome="pass"}`)))
}

func TestStartCheckIgnoresOutOfSetLabels(t *testing.T) {
	r := NewRecorder()
	// Neither call should panic; an invalid outcome must never reach the
	// counter (it would otherwise mint an unbounded, wallet-influenceable
	// metric series).
	_, done := r.StartCheck(t.Context(), "response_integrity")
	done("not-an-outcome")

	dump := dumpMetrics(t)
	qt.Assert(t, qt.IsFalse(strings.Contains(dump,
		`verifier_core_pipeline_check_total{check="response_integrity",outcome="not-an-outcome"}`)))
}

func TestObservePipelineRecordsHistogram(t *testing.T) {
	r := NewRecorder()
	r.ObservePipeline(25 * time.Millisecond)

	dump := dumpMetrics(t)
	qt.Assert(t, qt.IsTrue(strings.Contains(dump, metricPipelineSeconds)))
}

func TestRegisterAnchorStalenessGaugesReadsCallback(t *testing.T) {
	RegisterAnchorStalenessGauges([]string{"pid_provider"}, func(typ string) float64 {
		if typ == "pid_provider" {
			return 3600
		}
		return -1
	})

	dump := dumpMetrics(t)
	qt.Assert(t, qt.IsTrue(strings.Contains(dump,
		`verifier_core_anchor_staleness_seconds{type="pid_provider"}`)))
}

// dumpMetrics renders the shared VictoriaMetrics default registry (the same
// one Azugo serves at /metrics) so tests can assert on series without a
// running server.
func dumpMetrics(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	metrics.WritePrometheus(&b, true)
	return b.String()
}
