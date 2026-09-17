package routes

import (
	"strings"
	"testing"

	"github.com/dativa-lv/eudi-verifier-core/internal/testwallet"

	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// TestMetricsAfterE2E is the acceptance proof: after a full pipeline
// run, /metrics carries the per-check outcome counter, the pipeline latency
// histogram, and the anchor-staleness gauge — and NONE of it leaks the
// session id or a presented claim value.
func TestMetricsAfterE2E(t *testing.T) {
	t.Setenv("METRICS_ENABLED", "true") // must be set before newFixture (TestApp reads it once at construction)
	f := newFixture(t)
	// azugo gates /metrics on ctx.IP() being a trusted source (default:
	// 127.0.0.1); TestApp drives requests over an in-memory fasthttputil pipe
	// whose RemoteAddr is not a real IP ("pipe"), so — unlike HealthzOptions,
	// which TestApp already trusts-all for the same reason — MetricsOptions
	// needs the same override here to reach the endpoint at all in-process.
	f.tapp.MetricsOptions.TrustAll = true
	created := f.createSession(t, oid4vp.CrossDevice)

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	_, _, err = f.wallet.Respond(t.Context(), ro,
		testwallet.WithClaims("pid_sdjwt", map[string]any{"family_name": "METRICS-CANARY-1"}))
	qt.Assert(t, qt.IsNil(err))

	resp, err := f.tapp.TestClient().Get("/metrics")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	text := string(body)

	qt.Assert(t, qt.IsTrue(strings.Contains(text,
		`verifier_core_pipeline_check_total{check="response_integrity",outcome="pass"}`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(text, "verifier_core_pipeline_duration_seconds")))
	qt.Assert(t, qt.IsTrue(strings.Contains(text, "verifier_core_anchor_staleness_seconds")))

	// NO PII in any label or sample: session ids, claim values.
	qt.Assert(t, qt.IsFalse(strings.Contains(text, created.SessionID)))
	qt.Assert(t, qt.IsFalse(strings.Contains(text, "METRICS-CANARY-1")))
}
