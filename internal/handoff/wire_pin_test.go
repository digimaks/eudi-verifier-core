package handoff_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/digimaks/eudi-verifier-core/internal/handoff"
	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/go-quicktest/qt"
)

// TestResultRoundTripPinsWireShape pins the cross-service wire contract:
// a pipeline.Result marshaled by eudi-verifier-core (the sole
// writer) must decode into handoffwire.Result (eudi-api-management's, sole
// reader's, copy of the shape) byte-for-byte on re-marshal — every field,
// including the "name" tag on CheckResult.Check, must survive.
func TestResultRoundTripPinsWireShape(t *testing.T) {
	res := &pipeline.Result{
		SessionID: "01JZXSESSION00000000000001",
		Outcome:   "verified",
		Report: &pipeline.Report{
			SessionID: "01JZXSESSION00000000000001",
			Outcome:   "verified",
			FailCode:  "",
			Checks: []pipeline.CheckResult{
				{
					Check:   "issuer_authenticity",
					Outcome: pipeline.OutcomePass,
					Code:    "err:trust:issuer-untrusted",
					SpecRef: "OID4VP §5 / ARF §6.6.3.4",
					Detail:  "resolved via pid_provider anchor",
				},
				{
					Check:   "revocation",
					Outcome: pipeline.OutcomeSkipped,
					Code:    "short-lived-exemption",
					SpecRef: "ARF §6.6.3.7",
					Detail:  "",
				},
			},
			Credentials: []pipeline.CredentialSummary{
				{
					QueryCredID:      "pid",
					Format:           "dc+sd-jwt",
					DoctypeOrVCT:     "urn:eudi:pid:1",
					IssuerCountry:    "UT",
					ClaimNames:       []string{"family_name", "given_name", "nested.deep"},
					StatusProvenance: "cached",
					DecoyDigests:     3,
				},
			},
			Policy: map[string]bool{"revocation_fail_closed": true, "short_lived_exemption": false},
		},
		Credentials: []pipeline.ResultCredential{
			{
				QueryCredentialID: "pid",
				Format:            "dc+sd-jwt",
				DoctypeOrVCT:      "urn:eudi:pid:1",
				Claims: map[string]any{
					"family_name": "value-not-asserted-here",
					"nested":      map[string]any{"deep": "also-not-asserted"},
				},
			},
		},
	}

	want, err := json.Marshal(res)
	qt.Assert(t, qt.IsNil(err))

	var wire handoffwire.Result
	qt.Assert(t, qt.IsNil(json.Unmarshal(want, &wire)))

	got, err := json.Marshal(wire)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(got), string(want)))

	// Belt-and-braces on the field this comment calls out explicitly: the
	// check-name wire tag is "name", not "check".
	qt.Assert(t, qt.StringContains(string(want), `"name":"issuer_authenticity"`))
}

// TestEnvelopeRoundTripPinsWireShape does the same for internal/handoff's
// Envelope (the Valkey key & queue contract) — handoff.Envelope is now
// a type alias of handoffwire.Envelope, so this also guards against the alias
// ever drifting back into a shadow copy.
func TestEnvelopeRoundTripPinsWireShape(t *testing.T) {
	env := handoff.Envelope{
		Version:       1,
		SessionID:     "01JZXSESSION00000000000001",
		ClientID:      "01JZXCLIENT000000000000001",
		CorrelationID: "corr-1",
		WebhookURL:    "https://client.test/hook",
		ResultJWE:     "header.payload.tag",
		EnqueuedAt:    time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
	}

	want, err := json.Marshal(env)
	qt.Assert(t, qt.IsNil(err))

	var wire handoffwire.Envelope
	qt.Assert(t, qt.IsNil(json.Unmarshal(want, &wire)))

	got, err := json.Marshal(wire)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(got), string(want)))
}
