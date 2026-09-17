package routes

import (
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestJWKSServesWebhookSigningKey(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/verifier-jwks.json")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &set)))
	qt.Assert(t, qt.IsTrue(len(set.Keys) >= 1))
	k := set.Keys[0]
	qt.Assert(t, qt.Equals(k["kty"], "EC"))
	qt.Assert(t, qt.Equals(k["use"], "sig"))
	qt.Assert(t, qt.Equals(k["kid"], "webhook-signing"))
	qt.Assert(t, qt.IsTrue(k["x"] != nil))
	qt.Assert(t, qt.IsTrue(k["d"] == nil)) // NEVER the private part
}
