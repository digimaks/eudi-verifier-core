package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

// Structural test: the report builder receives full claim MAPS but
// the marshaled report contains claim NAMES only.
func TestReportNeverContainsClaimValues(t *testing.T) {
	const canary = "CANARY-CLAIM-VALUE-4242"
	b := NewBuilder("01JZXS")
	b.AddCredential(CredentialSummary{
		QueryCredID:   "pid",
		Format:        "dc+sd-jwt",
		DoctypeOrVCT:  "urn:eudi:pid:1",
		IssuerCountry: "UT",
	}, map[string]any{
		"family_name": canary,
		"nested":      map[string]any{"given_name": canary},
	})
	b.Add(CheckResult{Check: CheckParse, Outcome: OutcomePass, SpecRef: SpecRefs[CheckParse]})
	b.Verified()

	raw, err := json.Marshal(b.Build())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(strings.Contains(string(raw), canary)))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(raw), "family_name")))       // names survive
	qt.Assert(t, qt.IsTrue(strings.Contains(string(raw), "nested.given_name"))) // nested names flattened
}
