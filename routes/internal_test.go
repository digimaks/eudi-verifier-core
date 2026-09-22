package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	verifiercore "github.com/digimaks/eudi-verifier-core"
	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"

	dcql "github.com/gmb-eudi/go-dcql"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const internalTestToken = "test-internal-token" // matches verifiercore.TestApp (testing.go)

// testAppNoInternalAPI mirrors router_test.go's testApp, but boots the
// no-token variant (INTERNAL_API_TOKEN empty) — the fail-closed default: the
// /internal/v1 surface must not be registered at all.
func testAppNoInternalAPI(tb testing.TB) *azugo.TestApp {
	tb.Helper()
	app := verifiercore.TestAppNoInternalAPI(tb)
	qt.Assert(tb, qt.IsNil(Init(app)))
	return azugo.NewTestApp(app.App)
}

// validRegistrationJSON is a valid ARF RPRC_19a registration reference (wire
// shape: name/sub/registry_uri/intended_use_id — rpcert.RegistrationRef's
// MarshalJSON/registrationRefJSON).
func validRegistrationJSON() map[string]any {
	return map[string]any{
		"name":            "EUDI Test RP GmbH",
		"sub":             "01JZXCLIENT000000000000001",
		"registry_uri":    "https://registrar.test",
		"intended_use_id": "test-intended-use",
	}
}

// dcqlQueryRaw decodes a preset DCQL query into a generic JSON value so it can
// be embedded directly as a map value (matches the wire shape a real caller
// like eudi-api-management would send — a nested JSON object, not a string).
func dcqlQueryRaw(t *testing.T) any {
	t.Helper()
	b, err := json.Marshal(dcql.PresetPIDFull())
	qt.Assert(t, qt.IsNil(err))
	var raw any
	qt.Assert(t, qt.IsNil(json.Unmarshal(b, &raw)))
	return raw
}

// validCreateBody is the happy-path internalCreateRequest body (cross_device
// flow); test cases mutate a copy to exercise validation failures.
func validCreateBody(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"client_id":      "01JZXCLIENT000000000000001",
		"correlation_id": "corr-internal-1",
		"flow":           "cross_device",
		"dcql_query":     dcqlQueryRaw(t),
		"webhook_url":    "https://client.test/hook",
		"registration":   validRegistrationJSON(),
	}
}

// internalPost POSTs a JSON body to path with the given headers (Content-Type
// is always set; callers add Authorization or omit it to test the missing
// case). fasthttp.ReleaseResponse is called before returning, per the repo's
// test convention.
func internalPost(t *testing.T, app *azugo.TestApp, path string, body map[string]any, bearer *string) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	qt.Assert(t, qt.IsNil(err))
	opts := []azugo.TestClientOption{app.TestClient().WithHeader("Content-Type", "application/json")}
	if bearer != nil {
		opts = append(opts, app.TestClient().WithHeader("Authorization", "Bearer "+*bearer))
	}
	resp, err := app.TestClient().Post(path, b, opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	respBody, _ := resp.BodyUncompressed()
	respBody = append([]byte(nil), respBody...)
	fasthttp.ReleaseResponse(resp)
	return status, respBody
}

func internalDelete(t *testing.T, app *azugo.TestApp, path string, bearer *string) int {
	t.Helper()
	opts := []azugo.TestClientOption{}
	if bearer != nil {
		opts = append(opts, app.TestClient().WithHeader("Authorization", "Bearer "+*bearer))
	}
	resp, err := app.TestClient().Delete(path, opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	return status
}

func bearer(s string) *string { return &s }

// TestInternalAPIAbsentWithoutToken is the fail-closed default: no
// InternalAPIToken configured ⇒ the /internal/v1 surface is not registered at
// all (routes/router.go Init), so even a well-formed request 404s.
func TestInternalAPIAbsentWithoutToken(t *testing.T) {
	app := testAppNoInternalAPI(t)
	app.Start(t)
	defer app.Stop()

	status, _ := internalPost(t, app, "/internal/v1/sessions", validCreateBody(t), bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
}

func TestInternalAPIBearerAuth(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	t.Run("wrong bearer", func(t *testing.T) {
		status, _ := internalPost(t, app, "/internal/v1/sessions", validCreateBody(t), bearer("wrong-token"))
		qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
	})
	t.Run("missing authorization", func(t *testing.T) {
		status, _ := internalPost(t, app, "/internal/v1/sessions", validCreateBody(t), nil)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
	})
}

// internalCreateResponseWire mirrors routes.internalCreateResponse's JSON
// shape for test decoding (kept separate from the production type so this
// test would still catch an accidental wire-shape change).
type internalCreateResponseWire struct {
	SessionID   string    `json:"session_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	RequestURI  string    `json:"request_uri"`
	ResponseURI string    `json:"response_uri"`
	Invocation  struct {
		SchemeURI    string          `json:"scheme_uri,omitempty"`
		WalletURL    string          `json:"wallet_url"`
		QRPayload    string          `json:"qr_payload,omitempty"`
		DCAPIRequest json.RawMessage `json:"dc_api_request,omitempty"`
	} `json:"invocation"`
}

func requestURIPath(t *testing.T, requestURI string) string {
	t.Helper()
	u, err := url.Parse(requestURI)
	qt.Assert(t, qt.IsNil(err))
	return u.Path
}

// TestInternalCreateCrossDeviceHappyPath is the core
// acceptance: a valid create mints a REAL, servable session — proven by
// fetching the returned request_uri afterwards (200, not just a 201 shell).
func TestInternalCreateCrossDeviceHappyPath(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	status, body := internalPost(t, app, "/internal/v1/sessions", validCreateBody(t), bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))

	var resp internalCreateResponseWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &resp)))
	qt.Assert(t, qt.IsTrue(resp.SessionID != ""))
	qt.Assert(t, qt.StringContains(resp.RequestURI, resp.SessionID))
	qt.Assert(t, qt.IsTrue(resp.ResponseURI != ""))
	qt.Assert(t, qt.IsTrue(resp.Invocation.WalletURL != ""))

	getResp, err := app.TestClient().Get(requestURIPath(t, resp.RequestURI))
	qt.Assert(t, qt.IsNil(err))
	getStatus := getResp.StatusCode()
	fasthttp.ReleaseResponse(getResp)
	qt.Assert(t, qt.Equals(getStatus, fasthttp.StatusOK))
}

// TestInternalCreatePollOnlyNoWebhook: webhook_url is optional. Omitting it
// creates a poll-only session whose result is retrieved via GET, never
// delivered by webhook — so the create must still succeed (201).
func TestInternalCreatePollOnlyNoWebhook(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	delete(body, "webhook_url")
	body["correlation_id"] = "corr-poll-only"

	status, respBody := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))

	var resp internalCreateResponseWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(respBody, &resp)))
	qt.Assert(t, qt.IsTrue(resp.SessionID != ""))
	qt.Assert(t, qt.IsTrue(resp.Invocation.WalletURL != ""))
}

// TestInternalCreateTTLRespectedAndClamped exercises the seam:
// ttl_seconds flows through CreateInput.TTL and the response
// reports the EFFECTIVE (post-clamp) expiry.
func TestInternalCreateTTLRespectedAndClamped(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tests := []struct {
		name       string
		ttlSeconds int
		wantTTL    time.Duration
	}{
		{"short ttl used verbatim", 60, 60 * time.Second},
		{"long ttl clamped to the configured default", 999999, 5 * time.Minute}, // TestApp's SessionTTL default
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := validCreateBody(t)
			body["ttl_seconds"] = tt.ttlSeconds
			body["correlation_id"] = "corr-ttl-" + tt.name

			before := time.Now()
			status, respBody := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			after := time.Now()
			qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))

			var resp internalCreateResponseWire
			qt.Assert(t, qt.IsNil(json.Unmarshal(respBody, &resp)))
			qt.Assert(t, qt.IsTrue(!resp.ExpiresAt.Before(before.Add(tt.wantTTL-5*time.Second))))
			qt.Assert(t, qt.IsTrue(!resp.ExpiresAt.After(after.Add(tt.wantTTL+5*time.Second))))
		})
	}
}

// TestInternalCreateZeroRegistrationRejected is the guard:
// the Creator's TEST FIXTURE RegistrationRef substitution for a zero value
// must be unreachable from this API — a request omitting registration is
// rejected before Create is ever called.
func TestInternalCreateZeroRegistrationRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	delete(body, "registration")

	status, respBody := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
	qt.Assert(t, qt.IsFalse(strings.Contains(string(respBody), "Test Client")))
}

func TestInternalCreateUnknownFlowRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	body["flow"] = "carrier-pigeon"

	status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
}

// TestInternalCreateSemanticallyInvalidDCQLRejected: a query that PARSES
// (structurally a DCQL object — dcql.Parse only requires the credentials/
// credential_sets member to be present) but fails the [OID4VP §6] semantic
// rules (Query.Validate: empty credentials array) must be a 422 validation
// problem at THIS boundary, not an engine ErrSpec surfacing as a 500 —
// eudi-api-management must be able to tell "bad request" from "eudi-verifier-core is
// broken".
func TestInternalCreateSemanticallyInvalidDCQLRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	body["dcql_query"] = map[string]any{"credentials": []any{}}

	status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
}

// TestInternalDeleteSessionIdempotent covers the DELETE handler:
// 204 on the first delete, a subsequent GET of request_uri now fail-closed
// 404s (the wallet-facing Valkey session is gone), and a second DELETE is
// still 204 (idempotent — "nothing to delete" is not an error).
func TestInternalDeleteSessionIdempotent(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	status, body := internalPost(t, app, "/internal/v1/sessions", validCreateBody(t), bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
	var resp internalCreateResponseWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &resp)))

	delPath := "/internal/v1/sessions/" + resp.SessionID
	qt.Assert(t, qt.Equals(internalDelete(t, app, delPath, bearer(internalTestToken)), fasthttp.StatusNoContent))

	getResp, err := app.TestClient().Get(requestURIPath(t, resp.RequestURI))
	qt.Assert(t, qt.IsNil(err))
	getStatus := getResp.StatusCode()
	fasthttp.ReleaseResponse(getResp)
	qt.Assert(t, qt.Equals(getStatus, fasthttp.StatusNotFound))

	// Idempotent: deleting again is still a clean 204, not an error.
	qt.Assert(t, qt.Equals(internalDelete(t, app, delPath, bearer(internalTestToken)), fasthttp.StatusNoContent))
}

// TestInternalCreateDCAPIHappyPath: the dcapi flow returns the embedded
// dc_api.jwt request member (never a request_uri) plus the always-present
// response_uri (the only way a DCAPI caller learns the
// wallet-facing response endpoint).
func TestInternalCreateDCAPIHappyPath(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	body["flow"] = "dcapi"
	body["expected_origins"] = []string{"https://client.test"}

	status, respBody := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))

	var resp internalCreateResponseWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(respBody, &resp)))
	qt.Assert(t, qt.IsTrue(resp.ResponseURI != ""))
	qt.Assert(t, qt.IsTrue(len(resp.Invocation.DCAPIRequest) > 0))
}

// TestInternalCreateDCAPIWithoutOriginsIsCallerError is the regression test
// for the defect this validation exists to close: a browser-mediated create
// with no origins used to reach the engine, fail its spec check, and surface
// as an unclassified 500 — telling an integrator the verifier was broken when
// their own client registration was incomplete. It is the caller's error and
// must be reported as one.
func TestInternalCreateDCAPIWithoutOriginsIsCallerError(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	for _, tc := range []struct {
		name string
		set  func(map[string]any)
	}{
		{"absent", func(map[string]any) {}},
		{"empty", func(b map[string]any) { b["expected_origins"] = []string{} }},
		{"null", func(b map[string]any) { b["expected_origins"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := validCreateBody(t)
			body["flow"] = "dcapi"
			tc.set(body)

			status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			qt.Assert(t, qt.Equals(status, fasthttp.StatusBadRequest))
		})
	}
}

// TestInternalCreateDCAPIMalformedOriginsRejected pins the origin rule at the
// boundary. Each case is a value that would be accepted by a looser check and
// then never match the browser's real calling origin at run time — the failure
// mode worth catching at configuration time rather than mid-flow.
func TestInternalCreateDCAPIMalformedOriginsRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	for _, origin := range []string{
		"http://client.test",       // not https
		"https://",                 // no host
		"https://client.test/",     // trailing slash is a path
		"https://client.test/path", // path
		"https://client.test?q=1",  // query
		"https://client.test#frag", // fragment
		"https://user@client.test", // userinfo
		"client.test",              // no scheme
		"",                         // empty entry
	} {
		t.Run(origin, func(t *testing.T) {
			body := validCreateBody(t)
			body["flow"] = "dcapi"
			body["expected_origins"] = []string{origin}

			status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
		})
	}
}

// TestInternalCreateDCAPIMixedOriginsRejected: one bad entry in an otherwise
// good list fails the whole request — the list is a whitelist, so a silently
// dropped entry would widen or narrow it without the caller knowing.
func TestInternalCreateDCAPIMixedOriginsRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	body["flow"] = "dcapi"
	body["expected_origins"] = []string{"https://good.test", "https://bad.test/path"}

	status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
}

// TestInternalCreateExpectedOriginsAreDCAPIOnly: origins are meaningless for
// the redirect-based flows, and the engine rejects them there. Accepting them
// silently would let a caller believe an origin restriction was in force when
// none was.
func TestInternalCreateExpectedOriginsAreDCAPIOnly(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	for _, flow := range []string{"cross_device", "same_device"} {
		t.Run(flow, func(t *testing.T) {
			body := validCreateBody(t)
			body["flow"] = flow
			if flow == "same_device" {
				body["redirect_uri"] = "https://client.test/return"
			}
			body["expected_origins"] = []string{"https://client.test"}

			status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
		})
	}
}

// TestInternalCreateSameDeviceRedirectURIIsCallerError: the second instance of
// the same defect the origins validation closed. same_device has no return
// target without redirect_uri, so the engine refused it — as an unclassified
// 500, for a field the caller omitted. 400 when absent, 422 when it is not an
// absolute https URL, and the engine is never reached either way.
func TestInternalCreateSameDeviceRedirectURIIsCallerError(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	for _, tc := range []struct {
		name string
		set  func(map[string]any)
		want int
	}{
		{"absent", func(map[string]any) {}, fasthttp.StatusBadRequest},
		{"empty", func(b map[string]any) { b["redirect_uri"] = "" }, fasthttp.StatusBadRequest},
		{"not https", func(b map[string]any) { b["redirect_uri"] = "http://client.test/return" }, fasthttp.StatusUnprocessableEntity},
		{"no host", func(b map[string]any) { b["redirect_uri"] = "https://" }, fasthttp.StatusUnprocessableEntity},
		{"not a url", func(b map[string]any) { b["redirect_uri"] = "client.test/return" }, fasthttp.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := validCreateBody(t)
			body["flow"] = "same_device"
			tc.set(body)

			status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			qt.Assert(t, qt.Equals(status, tc.want))
		})
	}
}

// TestInternalCreateSameDeviceAcceptsRedirectURI guards the other direction: a
// check that refused every value would satisfy the cases above and break the
// only flow they describe.
func TestInternalCreateSameDeviceAcceptsRedirectURI(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := validCreateBody(t)
	body["flow"] = "same_device"
	body["redirect_uri"] = "https://client.test/return?ref=1"

	status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
}

// TestInternalCreateRedirectURINotRequiredElsewhere: the other flows tolerate a
// redirect_uri (the creator drops it before the engine sees it) and none of
// them require one. Restated as a test because tightening this was the shape of
// the bug that made the redirect flows unusable in the first place.
func TestInternalCreateRedirectURINotRequiredElsewhere(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	for _, flow := range []string{"cross_device", "dcapi"} {
		t.Run(flow, func(t *testing.T) {
			body := validCreateBody(t)
			body["flow"] = flow
			if flow == "dcapi" {
				body["expected_origins"] = []string{"https://client.test"}
			}
			status, _ := internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))

			body["redirect_uri"] = "https://client.test/return"
			status, _ = internalPost(t, app, "/internal/v1/sessions", body, bearer(internalTestToken))
			qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
		})
	}
}

// TestValidWebOrigin exercises the rule directly, including the accepted
// forms — a check that rejects everything would satisfy the negative cases
// above while breaking every real deployment.
func TestValidWebOrigin(t *testing.T) {
	for _, ok := range []string{
		"https://client.test",
		"https://client.test:19090",
		"https://sub.domain.client.test:443",
	} {
		qt.Assert(t, qt.IsNil(validWebOrigin(ok)), qt.Commentf("should accept %q", ok))
	}
	for _, bad := range []string{
		"", "client.test", "http://client.test", "https://",
		"https://client.test/", "https://client.test/p", "https://client.test?q=1",
		"https://client.test#f", "https://user@client.test", "https://user:pw@client.test",
	} {
		qt.Assert(t, qt.IsNotNil(validWebOrigin(bad)), qt.Commentf("should reject %q", bad))
	}
}

// internalGet GETs path with an optional bearer, returning status + body.
func internalGet(t *testing.T, app *azugo.TestApp, path string, bearer *string) (int, []byte) {
	t.Helper()
	opts := []azugo.TestClientOption{}
	if bearer != nil {
		opts = append(opts, app.TestClient().WithHeader("Authorization", "Bearer "+*bearer))
	}
	resp, err := app.TestClient().Get(path, opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	respBody, _ := resp.BodyUncompressed()
	respBody = append([]byte(nil), respBody...)
	fasthttp.ReleaseResponse(resp)
	return status, respBody
}

// The trust-identity diagnostic sits on the internal surface behind the same
// bearer: without the token it is 401, with it the body reports what this
// service can say about the trust snapshot it enforces. The test app's cache
// is empty, so every type reports fresh=false and — decisively — carries NO
// snapshotId field: an identity this process cannot read is absent, never
// guessed.
func TestInternalTrustStatus(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	status, _ := internalGet(t, app, "/internal/v1/trust-status", nil)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))

	status, body := internalGet(t, app, "/internal/v1/trust-status", bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(string(body), `"cacheReadable":true`))
	qt.Assert(t, qt.StringContains(string(body), `"pid_provider":{"fresh":false}`))
	qt.Assert(t, qt.Not(qt.StringContains(string(body), "snapshotId")))
}

// storedReport is a persisted verification report as the pipeline writes one:
// the failing check with its own account of why it failed, including the list
// it could not resolve. Kept as a literal so this test pins the wire shape the
// route serves rather than re-deriving it.
const storedReport = `{"session_id":"01JZXREPORT","outcome":"failed",` +
	`"fail_code":"err:revocation:unavailable","checks":[` +
	`{"name":"issuer_authenticity","outcome":"pass"},` +
	`{"name":"revocation","outcome":"fail","code":"err:revocation:unavailable",` +
	`"detail":"statuslist: status list token signature verification failed: ecdsa: verification error",` +
	`"status_list_uri":"https://status.example/statuslist/lv/pid/abc123"}],"policy":{}}`

// coreTestApp keeps the service App alongside the HTTP test app, so a test can
// seed the session store the routes read from.
func coreTestApp(tb testing.TB) (*azugo.TestApp, *verifiercore.App) {
	tb.Helper()
	app := verifiercore.TestApp(tb)
	qt.Assert(tb, qt.IsNil(Init(app)))
	return azugo.NewTestApp(app.App), app
}

// The report is the only place a check's own account of WHY it failed is
// written down: the wallet gets a code, the client-facing report carries the
// code without the detail. This route is how an operator reads the cause
// without database access — behind the same bearer as the rest of the internal
// surface, and byte-for-byte what was stored.
func TestInternalSessionReport(t *testing.T) {
	app, core := coreTestApp(t)
	app.Start(t)
	defer app.Stop()

	// A report belongs to a session, so the session row comes first — the
	// store refuses an orphan report exactly as the database does.
	_, cerr := core.SessionDB().Create(context.Background(), sessiondb.CreateInput{
		ID: "01JZXREPORT", ClientID: "01JZXCLIENT000000000000001", CorrelationID: "01JZXCORR",
		Flow: "cross_device", ExpiresAt: time.Now().Add(time.Minute),
	})
	qt.Assert(t, qt.IsNil(cerr))
	qt.Assert(t, qt.IsNil(core.SessionDB().SaveReport(context.Background(), "01JZXREPORT", json.RawMessage(storedReport))))

	status, _ := internalGet(t, app, "/internal/v1/sessions/01JZXREPORT/report", nil)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))

	status, body := internalGet(t, app, "/internal/v1/sessions/01JZXREPORT/report", bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.Equals(strings.TrimSpace(string(body)), storedReport))
	// The two fields the route exists for, named explicitly so a projection
	// that quietly drops either one fails here.
	qt.Assert(t, qt.StringContains(string(body), `"detail":"statuslist: status list token signature verification failed`))
	qt.Assert(t, qt.StringContains(string(body), `"status_list_uri":"https://status.example/statuslist/lv/pid/abc123"`))
}

// A session with no stored report is an anomaly on this surface, not an empty
// success: it renders 404 like the other session routes, never 200 with
// nothing in it.
func TestInternalSessionReportMissingIs404(t *testing.T) {
	app, _ := coreTestApp(t)
	app.Start(t)
	defer app.Stop()

	status, _ := internalGet(t, app, "/internal/v1/sessions/01JZXNOSUCHSESSION/report", bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
}

// Fail closed by absence: a deployment with no internal token configured
// registers no internal surface at all, so the report route is not reachable
// even with a correct-looking bearer.
func TestInternalSessionReportUnregisteredWithoutToken(t *testing.T) {
	app := testAppNoInternalAPI(t)
	app.Start(t)
	defer app.Stop()

	status, _ := internalGet(t, app, "/internal/v1/sessions/01JZXREPORT/report", bearer(internalTestToken))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
}

// A wrong bearer is the same 401 as no bearer: the comparison is
// constant-time over hashes, so a token that merely looks right gets exactly
// the same answer as none at all.
func TestInternalSessionReportWrongBearerIs401(t *testing.T) {
	app, _ := coreTestApp(t)
	app.Start(t)
	defer app.Stop()

	status, _ := internalGet(t, app, "/internal/v1/sessions/01JZXREPORT/report", bearer("not-the-internal-token"))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}
