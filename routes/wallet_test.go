package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	verifiercore "github.com/dativa-lv/eudi-verifier-core"
	"github.com/dativa-lv/eudi-verifier-core/internal/policy"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessions"
	"github.com/dativa-lv/eudi-verifier-core/internal/testwallet"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// testClientAdapter drives the azugo TestApp through the testwallet.Client seam.
type testClientAdapter struct{ app *azugo.TestApp }

func (a testClientAdapter) Get(_ context.Context, rawurl string) (int, []byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, nil, err
	}
	resp, err := a.app.TestClient().Get(u.Path)
	if err != nil {
		return 0, nil, err
	}
	defer fasthttp.ReleaseResponse(resp)
	body, err := resp.BodyUncompressed()
	return resp.StatusCode(), append([]byte(nil), body...), err
}

func (a testClientAdapter) PostForm(_ context.Context, rawurl string, form url.Values) (int, []byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, nil, err
	}
	resp, err := a.app.TestClient().Post(u.Path, []byte(form.Encode()),
		a.app.TestClient().WithHeader("Content-Type", "application/x-www-form-urlencoded"))
	if err != nil {
		return 0, nil, err
	}
	defer fasthttp.ReleaseResponse(resp)
	body, err := resp.BodyUncompressed()
	return resp.StatusCode(), append([]byte(nil), body...), err
}

// PostJSON is DCAPI's transport shape: a JSON body, plus the calling
// origin (and any other headers) carried as real HTTP headers.
func (a testClientAdapter) PostJSON(_ context.Context, rawurl string, body []byte, headers map[string]string) (int, []byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, nil, err
	}
	opts := []azugo.TestClientOption{a.app.TestClient().WithHeader("Content-Type", "application/json")}
	for k, v := range headers {
		opts = append(opts, a.app.TestClient().WithHeader(k, v))
	}
	resp, err := a.app.TestClient().Post(u.Path, body, opts...)
	if err != nil {
		return 0, nil, err
	}
	defer fasthttp.ReleaseResponse(resp)
	respBody, err := resp.BodyUncompressed()
	return resp.StatusCode(), append([]byte(nil), respBody...), err
}

type fixture struct {
	tapp   *azugo.TestApp
	app    *verifiercore.App
	wallet *testwallet.Wallet
	pki    *testwallet.PKI
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	app := verifiercore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	tapp := azugo.NewTestApp(app.App)
	tapp.Start(t)
	t.Cleanup(tapp.Stop)

	pki := testwallet.NewPKI(t)
	sl := testwallet.NewStatusLists(pki)
	app.SeedTestTrust(pki.Anchors(), sl) // backfills the real AnchorSource; until then a test seam on App
	w := testwallet.New(pki, testClientAdapter{tapp}, sl)
	return &fixture{tapp: tapp, app: app, wallet: w, pki: pki}
}

func (f *fixture) createSession(t *testing.T, flow oid4vp.Flow) *sessions.Created {
	t.Helper()
	created, err := f.app.SessionCreator().Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-e2e",
		Flow: flow, Query: *dcql.PresetPIDFull(), Policy: policy.ClientPolicy{},
		WebhookURL:  "https://client.test/hook",
		RedirectURI: "https://client.test/return",
	})
	qt.Assert(t, qt.IsNil(err))
	return created
}

func TestRequestObjectContentTypeAndSingleUse(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)

	resp, err := f.tapp.TestClient().Get("/wallet/" + created.SessionID + "/request.jwt")
	qt.Assert(t, qt.IsNil(err))
	ct := string(resp.Header.ContentType())
	body, _ := resp.BodyUncompressed()
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(ct, "application/oauth-authz-req+jwt")))
	qt.Assert(t, qt.IsTrue(len(body) > 0))

	// Single-use: second fetch fails with an OID4VP-shaped error, not problem+json.
	resp2, err := f.tapp.TestClient().Get("/wallet/" + created.SessionID + "/request.jwt")
	qt.Assert(t, qt.IsNil(err))
	body2, _ := resp2.BodyUncompressed()
	status2 := resp2.StatusCode()
	fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsTrue(status2 >= 400))
	var e map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body2, &e)))
	qt.Assert(t, qt.IsTrue(e["error"] != nil)) // OID4VP error member
	qt.Assert(t, qt.IsTrue(e["type"] == nil))  // NOT an RFC 9457 problem
}

func TestResponseHappyPathSameDeviceReturnsRedirectURI(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.SameDevice)

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	status, body, err := f.wallet.Respond(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))

	var out struct {
		RedirectURI string `json:"redirect_uri"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	qt.Assert(t, qt.StringContains(out.RedirectURI, "response_code=")) // [OID4VP §8.2] / [OID4VP §14.2]
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(out.RedirectURI, "https://client.test/return")))
}

// The first true end-to-end ten-step run. A verified report
// proves every check (issuer trust, real status-list fetch+verify, device
// binding, DCQL match, combined checks, assemble/forward) passed — the Engine
// short-circuits to "failed" on the first fail. It also asserts the persisted
// report is value-free: claim NAMES appear, the testwallet's
// claim VALUES ("Doe"/"Jane") never do.
func TestResponseHappyPathPersistsValueFreeTenStepReport(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	status, _, err := f.wallet.Respond(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))

	raw, err := f.app.SessionDB().GetReport(t.Context(), created.SessionID)
	qt.Assert(t, qt.IsNil(err))

	var rep struct {
		Outcome     string           `json:"outcome"`
		Checks      []map[string]any `json:"checks"`
		Credentials []struct {
			ClaimNames []string `json:"claim_names"`
		} `json:"credentials"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &rep)))
	qt.Assert(t, qt.Equals(rep.Outcome, "verified"))
	qt.Assert(t, qt.Equals(len(rep.Checks), 10)) // all ten steps ran
	qt.Assert(t, qt.IsTrue(len(rep.Credentials) > 0))

	// Claim NAMES are surfaced; claim VALUES never are (structural, Report builder).
	report := string(raw)
	qt.Assert(t, qt.IsTrue(strings.Contains(report, "family_name")))
	qt.Assert(t, qt.IsFalse(strings.Contains(report, "Doe")))
	qt.Assert(t, qt.IsFalse(strings.Contains(report, "Jane")))
}

// postRaw POSTs the exact given bytes to the response endpoint (unlike
// f.wallet.Respond, which re-encrypts a fresh JWE on every call — the [OID4VP §14.2]
// replay attack replays an IDENTICAL captured body, not a freshly built
// equivalent one).
func postRaw(t *testing.T, f *fixture, ro *testwallet.RequestObject, body []byte) (int, []byte) {
	t.Helper()
	u, err := url.Parse(ro.ResponseURI)
	qt.Assert(t, qt.IsNil(err))
	resp, err := f.tapp.TestClient().Post(u.Path, body,
		f.tapp.TestClient().WithHeader("Content-Type", "application/x-www-form-urlencoded"))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	respBody, _ := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	return status, respBody
}

// TestResponseSameDeviceReplayRejected: the [OID4VP §14.2] replay defense for the
// response endpoint. The original design had
// step 10's Finalize unconditionally DeleteSession, then had the processor
// re-Save the session (to persist ResponseCode for redemption) — but
// Save never recreates the sticky vc:session:{id}:consumed marker (only
// ConsumeOnce's SetNX does), so the marker was gone and a replay of the exact
// same captured body would re-run the whole pipeline, re-deliver to the sink,
// and mint a SECOND response_code silently overwriting the first. Finalize is
// now flow- and outcome-aware (internal/pipeline/finalize.go): a same-device
// SUCCESS re-Saves the session instead of deleting it, so DeleteSession (and
// therefore the marker) is never touched — the replay must hit ErrSessionConsumed
// at ConsumeOnce, before the pipeline runs a second time.
func TestResponseSameDeviceReplayRejected(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.SameDevice)

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	form, err := f.wallet.BuildResponse(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	body := []byte(form.Encode())

	status1, body1 := postRaw(t, f, ro, body)
	qt.Assert(t, qt.Equals(status1, fasthttp.StatusOK))
	var out1 struct {
		RedirectURI string `json:"redirect_uri"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body1, &out1)))
	qt.Assert(t, qt.StringContains(out1.RedirectURI, "response_code=")) // first run genuinely succeeded

	// Replay: the IDENTICAL bytes, POSTed again — must be rejected as a
	// consumed/replayed response, never silently re-run and mint a fresh code.
	status2, body2 := postRaw(t, f, ro, body)
	qt.Assert(t, qt.IsTrue(status2 >= 400))
	var e map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body2, &e)))
	qt.Assert(t, qt.IsTrue(e["error"] != nil)) // OID4VP error member, not a fresh redirect_uri
	qt.Assert(t, qt.IsTrue(e["redirect_uri"] == nil))

	// The first run's persisted report must survive the replay attempt intact.
	raw, err := f.app.SessionDB().GetReport(t.Context(), created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	var rep struct {
		Outcome string `json:"outcome"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &rep)))
	qt.Assert(t, qt.Equals(rep.Outcome, "verified"))
}

// TestResponseCrossDeviceReplayRejected is the control: cross-device mints no
// response_code, so Finalize deletes the session on success exactly as before
// this fix — a replay finds no session and is rejected. Kept alongside the
// same-device test so a future regression in the flow-aware branching trips
// this one too.
func TestResponseCrossDeviceReplayRejected(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	form, err := f.wallet.BuildResponse(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	body := []byte(form.Encode())

	status1, body1 := postRaw(t, f, ro, body)
	qt.Assert(t, qt.Equals(status1, fasthttp.StatusOK))
	qt.Assert(t, qt.Equals(strings.TrimSpace(string(body1)), "{}"))

	status2, body2 := postRaw(t, f, ro, body)
	qt.Assert(t, qt.IsTrue(status2 >= 400))
	var e map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body2, &e)))
	qt.Assert(t, qt.IsTrue(e["error"] != nil))
}

func TestResponseHappyPathCrossDeviceReturnsEmptyObject(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	status, body, err := f.wallet.Respond(t.Context(), ro)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.Equals(strings.TrimSpace(string(body)), "{}")) // no redirect in cross-device
}

func TestResponseBodyCap(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)
	// The response path segment is the routing token embedded in the
	// request object's response_uri claim, NOT created.SessionID (NewSession
	// never sees created.SessionID — see Create's doc comment) — fetch the
	// request object to learn the real path, same as the happy-path tests.
	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	u, err := url.Parse(ro.ResponseURI)
	qt.Assert(t, qt.IsNil(err))
	huge := strings.Repeat("A", f.app.Config().MaxResponseBodyBytes+1)
	resp, err := f.tapp.TestClient().Post(u.Path,
		[]byte("response="+huge),
		f.tapp.TestClient().WithHeader("Content-Type", "application/x-www-form-urlencoded"))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(status >= 400))
}

func TestUnknownSessionIsOID4VPError(t *testing.T) {
	f := newFixture(t)
	resp, err := f.tapp.TestClient().Get("/wallet/01JZXNOSUCH000000000000000/request.jwt")
	qt.Assert(t, qt.IsNil(err))
	body, _ := resp.BodyUncompressed()
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(status >= 400))
	var e map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &e)))
	qt.Assert(t, qt.IsTrue(e["error"] != nil))
}
