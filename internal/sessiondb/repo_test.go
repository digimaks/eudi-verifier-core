package sessiondb

import (
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestParseEnvelopeSuccess(t *testing.T) {
	data, code, err := parseEnvelope([]byte(`{"result":"success","data":{"id":"01J"}}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, ""))
	qt.Assert(t, qt.Equals(string(data), `{"id":"01J"}`))
}

func TestParseEnvelopeError(t *testing.T) {
	_, code, err := parseEnvelope([]byte(`{"result":"error","code":"session:not_found","message":"unknown session"}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, "session:not_found"))
}

func TestParseEnvelopeGarbage(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`not json`))
	qt.Assert(t, qt.IsNotNil(err))
}

func TestFakeRoundtrip(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	s, err := f.Create(ctx, CreateInput{ClientID: "c1", CorrelationID: "corr1", Flow: "cross_device",
		WebhookURL: "https://client.test/hook", Policy: json.RawMessage(`{}`)})
	qt.Assert(t, qt.IsNil(err))

	got, err := f.Get(ctx, s.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.CorrelationID, "corr1"))

	qt.Assert(t, qt.IsNil(f.SetStatus(ctx, s.ID, "wallet_engaged")))
	qt.Assert(t, qt.IsNil(f.SaveReport(ctx, s.ID, json.RawMessage(`{"outcome":"verified"}`))))
	rep, err := f.GetReport(ctx, s.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(rep), `{"outcome":"verified"}`))
}

func TestFakeUnknownSessionIs404(t *testing.T) {
	f := NewFake()
	_, err := f.Get(t.Context(), "missing")
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*")) // rendered from session:not_found via FromResultCode
}

// resultError bridges the DB house-style code (session:<reason>) onto the kit
// taxonomy (err:session:<reason>) so FromResultCode maps status correctly
// (err:session:not-found → 404). Without the err: prefix
// FromResultCode cannot parse the code and every error collapses to 500.
func TestResultErrorHTTPStatus(t *testing.T) {
	type statusCoder interface{ StatusCode() int }

	nf, ok := resultError("session:not_found").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(nf.StatusCode(), 404))

	inv, ok := resultError("session:invalid").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsTrue(inv.StatusCode() >= 400 && inv.StatusCode() < 500)) // client error, not 500

	qt.Assert(t, qt.IsNil(resultError(""))) // empty code is not an error
}
