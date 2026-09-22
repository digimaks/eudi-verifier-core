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
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// walletDeclinedDescription is the wallet's own explanation, verbatim from the
// production capture that exposed this path: app 1.3.2 refused because the
// verifier advertised no content-encryption value it implements. It is the text
// a person debugging the deployment needs, and it exists nowhere else — only the
// wallet knows it.
const walletDeclinedDescription = "UnsupportedClientMetaData(value=Wallet doesn't support any of the encryption methods supported by Verifier)"

// TestWalletDeclinedIsNotAVerificationFailure asserts that a wallet which posts
// an OpenID4VP error response instead of a presentation is recorded as having
// DECLINED, with its stated reason preserved — not as a presentation that failed
// to verify.
//
// The two outcomes have opposite causes and opposite fixes: one means the wallet
// refused us and said why, the other means something arrived and did not hold up.
// Reporting them identically is what made a real deployment fault
// (an empty response-encryption intersection) read as "presentation could not be
// verified", with the wallet's own explanation discarded.
//
// Three things are asserted together because the bug needed all three to be
// visible: the reason code, the wallet's text surviving into the persisted
// report, and the description the wallet is answered with.
func TestWalletDeclinedIsNotAVerificationFailure(t *testing.T) {
	app := verifiercore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	tapp := azugo.NewTestApp(app.App)
	tapp.Start(t)
	t.Cleanup(tapp.Stop)

	sess, token := declinedSession(t, app)

	form := url.Values{
		"error":             {"invalid_request"},
		"error_description": {walletDeclinedDescription},
		"state":             {sess.State},
	}.Encode()

	resp, err := tapp.TestClient().Post("/wallet/"+token+"/response", []byte(form),
		tapp.TestClient().WithHeader("Content-Type", "application/x-www-form-urlencoded"))
	qt.Assert(t, qt.IsNil(err))

	status := resp.StatusCode()
	body := append([]byte(nil), resp.Body()...)
	fasthttp.ReleaseResponse(resp)

	var out struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))

	qt.Check(t, qt.Equals(status, 400))
	qt.Check(t, qt.Equals(out.Error, "invalid_request"))
	// The wallet is told which KIND of refusal this was. "presentation could not
	// be verified" would describe something that never happened.
	qt.Check(t, qt.Equals(out.Description, descWalletDeclined))
	// The wallet's own text is never echoed back to it — it already knows what it
	// sent, and it is untrusted input.
	qt.Check(t, qt.Not(qt.StringContains(string(body), "Wallet doesn't support")))

	report := declinedReport(t, app, sess.ID)

	qt.Check(t, qt.Equals(report.Outcome, "failed"))
	// The distinction the outcome cannot carry: a declined wallet is not an
	// unverifiable presentation. This is the code walletDeclinedCode mirrors, so
	// this assertion is also what stops the two sides drifting apart.
	qt.Check(t, qt.Equals(report.FailCode, walletDeclinedCode))
	qt.Check(t, qt.Equals(report.FailCode, "err:presentation:wallet-declined"))

	var found bool
	for _, c := range report.Checks {
		if strings.Contains(c.Detail, "Wallet doesn't support any of the encryption methods") {
			found = true
		}
	}
	// Without this the operator sees a generic failure and the one fact that
	// explains it is gone.
	qt.Check(t, qt.IsTrue(found))

}

// TestWalletDeclinedWithoutDescription asserts the path still classifies
// correctly when the wallet sends a bare code — error_description is OPTIONAL,
// so the reason code must not depend on the text being present.
func TestWalletDeclinedWithoutDescription(t *testing.T) {
	app := verifiercore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	tapp := azugo.NewTestApp(app.App)
	tapp.Start(t)
	t.Cleanup(tapp.Stop)

	sess, token := declinedSession(t, app)

	form := url.Values{
		"error": {"access_denied"}, // the user declined at the consent screen
		"state": {sess.State},
	}.Encode()

	resp, err := tapp.TestClient().Post("/wallet/"+token+"/response", []byte(form),
		tapp.TestClient().WithHeader("Content-Type", "application/x-www-form-urlencoded"))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.Equals(status, 400))
	qt.Check(t, qt.Equals(declinedReport(t, app, sess.ID).FailCode, walletDeclinedCode))
}

// declinedSession mints a session reachable through the response endpoint: the
// engine session, its metadata row (the processor loads it before running the
// pipeline) and the routing token the URL carries.
func declinedSession(t *testing.T, app *verifiercore.App) (*oid4vp.Session, string) {
	t.Helper()
	ctx := context.Background()
	token := "declined" + t.Name()

	reg, err := rpcert.NewRegistrationRef("Declined Client", "01JZXCLIENT000000000000001", "https://registrar.test", "declined-intended-use")
	qt.Assert(t, qt.IsNil(err))

	sess, _, err := app.Engine().NewSession(ctx, oid4vp.RequestSpec{
		Query:        *dcql.PresetPIDFull(),
		Flow:         oid4vp.CrossDevice,
		ResponseURI:  app.Config().PublicBaseURL + "/wallet/" + token + "/response",
		Registration: reg,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Sessions().Save(ctx, sess)))

	_, err = app.SessionDB().Create(ctx, sessiondb.CreateInput{
		ID: sess.ID, ClientID: "01JZXCLIENT000000000000001", Flow: "cross_device",
		ExpiresAt: time.Now().Add(time.Minute),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.RespondTokens().Put(ctx, token, sess.ID, time.Minute)))

	return sess, token
}

// declinedReport reads the report the run persisted, through the fake session
// DB's snapshot — the same surface the verified-deletion canary reads.
func declinedReport(t *testing.T, app *verifiercore.App, sessionID string) struct {
	Outcome  string `json:"outcome"`
	FailCode string `json:"fail_code"`
	Checks   []struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	} `json:"checks"`
} {
	t.Helper()

	var snap struct {
		Reports map[string]json.RawMessage `json:"reports"`
	}
	dump := app.SessionDBFakeDump()
	qt.Assert(t, qt.IsNotNil(dump))
	qt.Assert(t, qt.IsNil(json.Unmarshal(dump, &snap)))

	raw, ok := snap.Reports[sessionID]
	qt.Assert(t, qt.IsTrue(ok))

	var report struct {
		Outcome  string `json:"outcome"`
		FailCode string `json:"fail_code"`
		Checks   []struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &report)))

	return report
}
