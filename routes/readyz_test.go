package routes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	verifiercore "github.com/digimaks/eudi-verifier-core"
	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// readyzBody is the JSON shape readyz emits when degraded.
type readyzBody struct {
	Status     string   `json:"status"`
	Components []string `json:"components"`
}

// readyzApp builds a TestApp whose AnchorSource is the production anchors.Valkey
// (init default — no SeedTestTrust here) reading the same miniredis the returned
// app writes through. The DB probe is stubbed healthy so readyz exercises the
// anchor-freshness / snapshot-health branches (unit tests have no Postgres).
func readyzApp(t *testing.T) (*azugo.TestApp, *verifiercore.App) {
	t.Helper()
	app := verifiercore.TestApp(t)
	app.SetDBPingForTest(func(context.Context) error { return nil })
	qt.Assert(t, qt.IsNil(Init(app)))
	tapp := azugo.NewTestApp(app.App)
	tapp.Start(t)
	t.Cleanup(tapp.Stop)
	return tapp, app
}

// seedFreshness writes a trust:freshness:<type> record through the app's own
// Valkey client (the same key builders the worker uses — never a hand-formatted
// key).
func seedFreshness(t *testing.T, app *verifiercore.App, keyType string, validUntil time.Time, stale bool) {
	t.Helper()
	fr := trustcache.TypeFreshness{SnapshotID: "snap-1", FetchedAt: time.Now(), ValidUntil: validUntil, UpstreamStale: stale}
	b, err := json.Marshal(fr)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Valkey().Set(context.Background(), trustcache.FreshnessKey(keyType), b, 0).Err()))
}

// seedSnapshot writes the trust:freshness:snapshot health record.
func seedSnapshot(t *testing.T, app *verifiercore.App, pending, stale bool) {
	t.Helper()
	sh := trustcache.SnapshotHealth{SnapshotID: "snap-1", LOTLSequence: 1, CheckedAt: time.Now(), PendingBootstrap: pending, UpstreamStale: stale}
	b, err := json.Marshal(sh)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Valkey().Set(context.Background(), trustcache.SnapshotHealthKey, b, 0).Err()))
}

func seedAllRequiredFresh(t *testing.T, app *verifiercore.App) {
	t.Helper()
	for _, ty := range requiredAnchorTypes {
		seedFreshness(t, app, ty, time.Now().Add(time.Hour), false)
	}
}

func getReadyz(t *testing.T, tapp *azugo.TestApp) (int, readyzBody) {
	t.Helper()
	resp, err := tapp.TestClient().Get("/readyz")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	var b readyzBody
	if len(body) > 0 {
		qt.Assert(t, qt.IsNil(json.Unmarshal(body, &b)))
	}
	return resp.StatusCode(), b
}

func hasComponent(components []string, want string) bool {
	for _, c := range components {
		if c == want {
			return true
		}
	}
	return false
}

func TestReadyzAllFreshOK(t *testing.T) {
	tapp, app := readyzApp(t)
	seedAllRequiredFresh(t, app)
	seedSnapshot(t, app, false, false)

	status, _ := getReadyz(t, tapp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
}

func TestReadyzExpiredAnchorTypeDegraded(t *testing.T) {
	tapp, app := readyzApp(t)
	seedAllRequiredFresh(t, app)
	seedSnapshot(t, app, false, false)
	// Override pid_provider with a past validity horizon => not fresh.
	seedFreshness(t, app, "pid_provider", time.Now().Add(-time.Hour), false)

	status, body := getReadyz(t, tapp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusServiceUnavailable))
	qt.Assert(t, qt.Equals(body.Status, "degraded"))
	qt.Assert(t, qt.IsTrue(hasComponent(body.Components, "anchors:pid_provider")))
	qt.Assert(t, qt.IsFalse(hasComponent(body.Components, "trust-snapshot")))
}

func TestReadyzPendingBootstrapDegraded(t *testing.T) {
	tapp, app := readyzApp(t)
	seedAllRequiredFresh(t, app)
	seedSnapshot(t, app, true, false) // pending upstream bootstrap => fail closed

	status, body := getReadyz(t, tapp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusServiceUnavailable))
	qt.Assert(t, qt.Equals(body.Status, "degraded"))
	qt.Assert(t, qt.IsTrue(hasComponent(body.Components, "trust-snapshot")))
}
