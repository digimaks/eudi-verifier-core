package routes

import (
	"strings"
	"testing"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The browser-mediated flow is the only cross-origin caller: the relying
// party's page posts the wallet's answer to the response endpoint, which lives
// on this service's origin. Everything below asserts what a browser actually
// enforces before that POST is allowed to happen.

const rpOrigin = "https://rp.test"

// corsTestApp builds the app with one configured origin. CORS_ORIGINS is read
// when configuration binds, so it must be set before the app is constructed.
func corsTestApp(tb testing.TB) *azugo.TestApp {
	tb.Helper()
	tb.Setenv("CORS_ORIGINS", rpOrigin)
	return testApp(tb)
}

// A preflight from a configured origin must be answered, and must name
// Content-Type: the response body is JSON, which a browser refuses to send
// cross-origin unless the preflight allows that header.
func TestCORSPreflightAllowsJSONPostFromConfiguredOrigin(t *testing.T) {
	app := corsTestApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Call(http.MethodOptions, "/wallet/anything/response", nil,
		app.TestClient().WithHeader("Origin", rpOrigin),
		app.TestClient().WithHeader("Access-Control-Request-Method", "POST"),
		app.TestClient().WithHeader("Access-Control-Request-Headers", "content-type"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	qt.Assert(t, qt.Equals(string(resp.Header.Peek("Access-Control-Allow-Origin")), rpOrigin))
	qt.Assert(t, qt.IsTrue(strings.Contains(
		strings.ToLower(string(resp.Header.Peek("Access-Control-Allow-Headers"))), "content-type")))
	qt.Assert(t, qt.IsTrue(strings.Contains(
		string(resp.Header.Peek("Access-Control-Allow-Methods")), "POST")))
}

// The response to the POST itself must also carry the origin header, or the
// page cannot read the outcome — including a refusal, which is exactly when an
// integrator needs to see it.
func TestCORSHeaderOnTheResponsePostItself(t *testing.T) {
	app := corsTestApp(t)
	app.Start(t)
	defer app.Stop()

	// An unknown routing token: the outcome does not matter here, only that the
	// answer is readable by the page that asked.
	resp, err := app.TestClient().Post("/wallet/unknown-token/response", []byte(`{"response":"x"}`),
		app.TestClient().WithHeader("Origin", rpOrigin),
		app.TestClient().WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(string(resp.Header.Peek("Access-Control-Allow-Origin")), rpOrigin))
}

// An origin nobody configured gets no headers at all — the browser then blocks
// the call on its side. Configuration is the whole gate; there is no wildcard.
func TestCORSUnconfiguredOriginGetsNothing(t *testing.T) {
	app := corsTestApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Call(http.MethodOptions, "/wallet/anything/response", nil,
		app.TestClient().WithHeader("Origin", "https://evil.test"),
		app.TestClient().WithHeader("Access-Control-Request-Method", "POST"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(string(resp.Header.Peek("Access-Control-Allow-Origin")), ""))
	qt.Assert(t, qt.Equals(string(resp.Header.Peek("Access-Control-Allow-Headers")), ""))
}

// With no origins configured at all, the service answers no cross-origin
// caller — an unconfigured deployment is closed, not open.
func TestCORSNoOriginsConfiguredIsClosed(t *testing.T) {
	t.Setenv("CORS_ORIGINS", "")
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Call(http.MethodOptions, "/wallet/anything/response", nil,
		app.TestClient().WithHeader("Origin", rpOrigin),
		app.TestClient().WithHeader("Access-Control-Request-Method", "POST"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(string(resp.Header.Peek("Access-Control-Allow-Origin")), ""))
}
