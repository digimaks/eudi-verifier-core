package routes

import (
	"testing"

	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
	"github.com/digimaks/eudi-verifier-core/internal/sessions"
	"github.com/digimaks/eudi-verifier-core/internal/testwallet"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/go-quicktest/qt"
)

const goodOrigin = "https://client.test"

func createDCAPISession(t *testing.T, f *fixture) *sessions.Created {
	t.Helper()
	created, err := f.app.SessionCreator().Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-dcapi",
		Flow: oid4vp.DCAPI, Query: *dcql.PresetPIDFull(),
		WebhookURL:      "https://client.test/hook",
		ExpectedOrigins: []string{goodOrigin}, // OID4VP Annex A signed requests
	})
	qt.Assert(t, qt.IsNil(err))
	return created
}

// OID4VP Annex A: the dc_api.jwt signed request carries expected_origins, is
// delivered as an embedded request member (Invocation.DCAPI) — NEVER via
// request_uri/FetchRequestObject —
// oid4vp.RequestObjectJWT rejects DCAPI sessions outright, and NewSession
// rejects any DCAPI spec carrying a response_uri, so there is no request_uri
// to fetch and no response_uri claim in the signed request. The wallet-side
// mdoc handover binds the origin; a wrong origin must fail step 1.
func TestDCAPIHappyPath(t *testing.T) {
	f := newFixture(t)
	created := createDCAPISession(t, f)

	ro, err := f.wallet.ParseDCAPIRequest(created.Invocation.DCAPI, created.ResponseURI)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(ro.ExpectedOrigins, []string{goodOrigin}))

	status, _, err := f.wallet.Respond(t.Context(), ro, testwallet.WithDCAPIOrigin(goodOrigin))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, 200))

	r := report(t, f, created.SessionID)
	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
}

func TestDCAPIWrongOriginRejected(t *testing.T) {
	f := newFixture(t)
	created := createDCAPISession(t, f)
	ro, err := f.wallet.ParseDCAPIRequest(created.Invocation.DCAPI, created.ResponseURI)
	qt.Assert(t, qt.IsNil(err))

	status, _, err := f.wallet.Respond(t.Context(), ro, testwallet.WithDCAPIOrigin("https://evil.example"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(status >= 400))

	r := report(t, f, created.SessionID)
	assertOnlyStepFailed(t, r, pipeline.CheckResponseIntegrity, "err:presentation:invalid-response")
}

// An unsigned browser request completes a real presentation. This is the whole
// case for supporting the mode at all: the wallet is handed the request
// parameters with no signature and no verifier identity, and the presentation
// it returns still verifies end to end.
//
// It is also the case AGAINST making it the default, visible in the same test:
// the request carries no client_id and no expected_origins, so nothing in it
// tells the wallet who is asking. Only the origin the browser asserts does.
func TestDCAPIUnsignedHappyPath(t *testing.T) {
	f := newFixture(t)
	created, err := f.app.SessionCreator().WithDCAPIMode(sessions.DCAPIModeUnsigned).
		Create(t.Context(), sessions.CreateInput{
			ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-dcapi-unsigned",
			Flow: oid4vp.DCAPI, Query: *dcql.PresetPIDFull(),
			WebhookURL:      "https://client.test/hook",
			ExpectedOrigins: []string{goodOrigin},
		})
	qt.Assert(t, qt.IsNil(err))

	ro, err := f.wallet.ParseDCAPIRequest(created.Invocation.DCAPI, created.ResponseURI)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ro.ClientID, ""))            // Annex A.2: omitted in unsigned requests
	qt.Assert(t, qt.Equals(len(ro.ExpectedOrigins), 0)) // Annex A.2: not for use in unsigned requests
	qt.Assert(t, qt.IsTrue(ro.Nonce != ""))

	status, _, err := f.wallet.Respond(t.Context(), ro, testwallet.WithDCAPIOrigin(goodOrigin))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, 200))

	r := report(t, f, created.SessionID)
	qt.Assert(t, qt.Equals(r.Outcome, "verified"))
}

// The origin check is ours and survives the mode change. An unsigned request
// never tells the wallet which origins are expected, so this service's own
// check is the only one left — if it were skipped along with the signature, an
// unsigned deployment would accept a response from any page at all.
func TestDCAPIUnsignedStillRejectsWrongOrigin(t *testing.T) {
	f := newFixture(t)
	created, err := f.app.SessionCreator().WithDCAPIMode(sessions.DCAPIModeUnsigned).
		Create(t.Context(), sessions.CreateInput{
			ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-dcapi-unsigned-origin",
			Flow: oid4vp.DCAPI, Query: *dcql.PresetPIDFull(),
			WebhookURL:      "https://client.test/hook",
			ExpectedOrigins: []string{goodOrigin},
		})
	qt.Assert(t, qt.IsNil(err))

	ro, err := f.wallet.ParseDCAPIRequest(created.Invocation.DCAPI, created.ResponseURI)
	qt.Assert(t, qt.IsNil(err))

	status, _, err := f.wallet.Respond(t.Context(), ro, testwallet.WithDCAPIOrigin("https://evil.example"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(status >= 400))
}
