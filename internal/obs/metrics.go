// Package obs is eudi-verifier-core's observability delta on top of the kit:
// pipeline metrics + per-check spans. Names follow the kit
// convention (service-prefixed, VictoriaMetrics registry Azugo serves at
// /metrics). Every metric label value here comes from a
// CLOSED set (the pipeline check-name enum × outcome enum, or the fixed
// trust-anchor type taxonomy) — never a session id, never anything derived
// from wallet input.
package obs

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/gmb-lib/go-platform-kit/observability"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativa-lv/eudi-verifier-core/internal/pipeline"
)

const (
	metricCheckTotal      = "verifier_core_pipeline_check_total"
	metricPipelineSeconds = "verifier_core_pipeline_duration_seconds"
	metricAnchorStaleness = "verifier_core_anchor_staleness_seconds"
)

// Recorder implements pipeline.Recorder: it opens one span per pipeline check
// and increments the per-check outcome counter, plus the full-run latency
// histogram (p95 source). It is the sole place check/outcome label
// values are validated against the closed sets before they ever reach a
// metric series.
type Recorder struct {
	checkNames map[string]bool
	tracer     trace.Tracer
}

// NewRecorder builds a Recorder that accepts exactly pipeline.AllChecks as
// check names and pass/fail/skipped as outcomes.
func NewRecorder() *Recorder {
	names := make(map[string]bool, len(pipeline.AllChecks))
	for _, n := range pipeline.AllChecks {
		names[n] = true
	}
	return &Recorder{checkNames: names, tracer: otel.Tracer("eudi-verifier-core/pipeline")}
}

// validate rejects any check/outcome pair outside the closed sets. Called
// before every metric emission — defense in depth: Engine.Run only ever
// passes a Check.Name() (always one of pipeline.AllChecks) and a
// pipeline.Outcome value, but the recorder does not trust that blindly.
func (r *Recorder) validate(check, outcome string) error {
	if !r.checkNames[check] {
		return fmt.Errorf("obs: %q is not a pipeline check", check)
	}
	switch outcome {
	case string(pipeline.OutcomePass), string(pipeline.OutcomeFail), string(pipeline.OutcomeSkipped):
		return nil
	default:
		return fmt.Errorf("obs: %q is not an outcome", outcome)
	}
}

// StartCheck opens a span for one pipeline check; the returned func records
// the outcome counter and closes the span. Label values are enum-validated —
// an out-of-set check/outcome pair is silently dropped from metrics (never
// emitted as a garbage series) but the span still closes normally.
func (r *Recorder) StartCheck(ctx context.Context, check string) (context.Context, func(outcome string)) {
	ctx, span := r.tracer.Start(ctx, "pipeline."+check)
	return ctx, func(outcome string) {
		if err := r.validate(check, outcome); err == nil {
			observability.IncCounter(metricCheckTotal,
				map[string]string{"check": check, "outcome": outcome})
			span.SetAttributes(attribute.String("outcome", outcome))
		}
		span.End()
	}
}

// ObservePipeline records total pipeline latency (p95 source). No
// labels: cardinality-free by construction.
func (r *Recorder) ObservePipeline(d time.Duration) {
	observability.ObserveSeconds(metricPipelineSeconds, nil, d.Seconds())
}

// stalenessSource is the live (types, callback) pair RegisterAnchorStaleness
// gauges read through — see RegisterAnchorStalenessGauges for why the
// indirection exists (VictoriaMetrics/metrics.GetOrCreateGauge only honors
// the callback passed on the FIRST call for a given metric name).
type stalenessSource struct {
	lookup func(typ string) float64
}

var (
	currentStaleness  atomic.Pointer[stalenessSource]
	stalenessGaugeSet sync.Map // metric series name -> struct{}, guards one-time gauge registration
)

// RegisterAnchorStalenessGauges exposes per-type seconds-until-expiry
// (negative = already stale) gauges, one per entry in types (the closed
// trust-anchor type taxonomy — anchors.TypeKeyList()). freshness is polled at
// scrape time via secondsUntilExpiry.
//
// The kit has no gauge helper, so this reaches for
// VictoriaMetrics/metrics.GetOrCreateGauge directly — the same approach
// trust-cache-worker/internal/health/metrics.go already uses for the same
// gap. GetOrCreateGauge registers a name's callback ONCE per process and
// ignores the function argument on every later call with the same name; since
// this is called once per App in production but once per test fixture in
// `go test` (same process, many Apps), the actual read path is indirected
// through currentStaleness so the gauge (registered on first-ever call for a
// given type) always reflects the MOST RECENTLY registered source rather than
// a stale test's already-torn-down App.
func RegisterAnchorStalenessGauges(types []string, secondsUntilExpiry func(typ string) float64) {
	currentStaleness.Store(&stalenessSource{lookup: secondsUntilExpiry})
	for _, typ := range types {
		typ := typ
		name := fmt.Sprintf(`%s{type=%q}`, metricAnchorStaleness, typ)
		if _, loaded := stalenessGaugeSet.LoadOrStore(name, struct{}{}); loaded {
			continue // already registered for this type in this process
		}
		metrics.GetOrCreateGauge(name, func() float64 {
			src := currentStaleness.Load()
			if src == nil {
				return -1
			}
			return src.lookup(typ)
		})
	}
}
