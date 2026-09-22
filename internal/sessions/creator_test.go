package sessions_test

import (
	"net/url"
	"testing"
	"time"

	verifiercore "github.com/digimaks/eudi-verifier-core"
	"github.com/digimaks/eudi-verifier-core/internal/policy"
	"github.com/digimaks/eudi-verifier-core/internal/sessions"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/go-quicktest/qt"
)

func TestCreateMintsOneIDEverywhere(t *testing.T) {
	app := verifiercore.TestApp(t)
	c := app.SessionCreator()

	created, err := c.Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-1",
		Flow: oid4vp.CrossDevice, Query: *dcql.PresetPIDFull(),
		Policy: policy.ClientPolicy{}, WebhookURL: "https://client.test/hook",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(created.SessionID != ""))
	qt.Assert(t, qt.StringContains(created.RequestURI, created.SessionID))

	// Guard against a request_uri URL-shape defect: the
	// request_uri embedded in the wallet invocation (what a real wallet
	// actually fetches) MUST be byte-identical to Created.RequestURI (what
	// routes/wallet.go's bound "/wallet/{sessionID}/request.jwt" route
	// actually serves) — app.go wires oid4vp.Config.RequestURIFunc to the
	// exact same formula creator.go uses below. Before that wiring, the
	// invocation carried "{PublicBaseURL}/{id}" (404) instead.
	u, err := url.Parse(created.Invocation.SchemeURI)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(u.Query().Get("request_uri"), created.RequestURI))

	// Same id in the Valkey store…
	sess, err := app.Sessions().Load(t.Context(), created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sess.ID, created.SessionID))

	// …and in the metadata store, correlation preserved.
	meta, err := app.SessionDB().Get(t.Context(), created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(meta.CorrelationID, "corr-1"))
	qt.Assert(t, qt.Equals(meta.Status, "pending"))
}

// TestCreateTTLClamping is the TTL-clamping acceptance test: the
// per-call CreateInput.TTL may shorten the configured default (TestApp's
// SessionTTL, the config.go default of 5m) but never extend it — the oid4vp
// engine session's own expiry is fixed at engine construction (creator.go
// CreateInput.TTL doc comment).
func TestCreateTTLClamping(t *testing.T) {
	const defaultTTL = 5 * time.Minute // config.go SetDefault("session_ttl", …), unset by TestApp
	tests := []struct {
		name    string
		ttl     time.Duration
		wantTTL time.Duration
	}{
		{"zero TTL uses the configured default", 0, defaultTTL},
		{"shorter TTL is used verbatim", time.Minute, time.Minute},
		{"longer TTL is clamped to the configured default", 24 * time.Hour, defaultTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := verifiercore.TestApp(t)
			c := app.SessionCreator()

			before := time.Now()
			created, err := c.Create(t.Context(), sessions.CreateInput{
				ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-ttl",
				Flow: oid4vp.CrossDevice, Query: *dcql.PresetPIDFull(),
				WebhookURL: "https://client.test/hook", TTL: tt.ttl,
			})
			after := time.Now()
			qt.Assert(t, qt.IsNil(err))

			qt.Assert(t, qt.IsTrue(!created.ExpiresAt.Before(before.Add(tt.wantTTL))))
			qt.Assert(t, qt.IsTrue(!created.ExpiresAt.After(after.Add(tt.wantTTL))))

			meta, err := app.SessionDB().Get(t.Context(), created.SessionID)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsTrue(!meta.ExpiresAt.Before(before.Add(tt.wantTTL))))
			qt.Assert(t, qt.IsTrue(!meta.ExpiresAt.After(after.Add(tt.wantTTL))))
		})
	}
}
