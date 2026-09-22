package routes

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	verifiercore "github.com/digimaks/eudi-verifier-core"
	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"

	dcql "github.com/gmb-eudi/go-dcql"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// FuzzWalletResponseHandler drives arbitrary bodies through the FULL response
// endpoint, including go-oid4vp's untrusted-input parsing (form decode → JWE
// decrypt attempt → vp_token parse) reached via ProcessResponse — the wallet
// input boundary. It must never panic and never answer 2xx to
// garbage.
//
// A fresh session (+ routing token + metadata row) is minted for EVERY
// iteration: the [OID4VP §8.2] response endpoint is single-use (ConsumeOnce), so reusing
// one session would stop at ErrSessionConsumed after the first input and never
// re-enter the parser. The metadata row is required because pipelineProcessor
// loads it (SessionDB.Get) before running the pipeline — without it the run
// would short-circuit before step 1's ProcessResponse parse, defeating the
// fuzz. The session is deleted again after each iteration to bound memory.
// A garbage body can never be a valid JWE to the per-session ephemeral key, so
// every input fails at parse/decrypt (>=400) — the assertion is meaningful.
func FuzzWalletResponseHandler(f *testing.F) {
	app := verifiercore.TestApp(f)
	if err := Init(app); err != nil {
		f.Fatal(err)
	}
	tapp := azugo.NewTestApp(app.App)
	tapp.StartBenchmark() // no *testing.T needed (Start requires one; StartBenchmark does not)
	defer tapp.Stop()

	ctx := context.Background()
	query := *dcql.PresetPIDFull()
	reg, err := rpcert.NewRegistrationRef("Fuzz Client", "01JZXCLIENT000000000000001", "https://registrar.test", "fuzz-intended-use")
	if err != nil {
		f.Fatal(err)
	}
	baseURL := app.Config().PublicBaseURL
	var seq atomic.Uint64

	f.Add([]byte("response=garbage"))
	f.Add([]byte("response="))
	f.Add([]byte("=&=&=%%%"))
	f.Add([]byte(""))
	f.Add([]byte("response=eyJhbGciOiJFQ0RILUVTIn0..AAAA.AAAA.AAAA"))

	f.Fuzz(func(t *testing.T, body []byte) {
		token := "fuzz" + strconv.FormatUint(seq.Add(1), 36)
		sess, _, err := app.Engine().NewSession(ctx, oid4vp.RequestSpec{
			Query:        query,
			Flow:         oid4vp.CrossDevice,
			ResponseURI:  baseURL + "/wallet/" + token + "/response",
			Registration: reg,
		})
		if err != nil {
			t.Fatalf("new session: %v", err)
		}
		if err := app.Sessions().Save(ctx, sess); err != nil {
			t.Fatalf("save session: %v", err)
		}
		if _, err := app.SessionDB().Create(ctx, sessiondb.CreateInput{
			ID: sess.ID, ClientID: "01JZXCLIENT000000000000001", Flow: "cross_device",
			ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("create metadata: %v", err)
		}
		if err := app.RespondTokens().Put(ctx, token, sess.ID, time.Minute); err != nil {
			t.Fatalf("put respond token: %v", err)
		}
		defer func() { _ = app.Sessions().DeleteSession(ctx, sess.ID) }()

		resp, err := tapp.TestClient().Post("/wallet/"+token+"/response", body,
			tapp.TestClient().WithHeader("Content-Type", "application/x-www-form-urlencoded"))
		if err != nil {
			return // transport-level rejection is fine; a panic would fail the fuzzer
		}
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		if status < 400 {
			t.Fatalf("garbage accepted: HTTP %d", status)
		}
	})
}
