package pipeline

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// The specRef strings are load-bearing (client-visible) and
// sourced from the single specrefs.go table.
func TestEveryCheckHasASpecRef(t *testing.T) {
	for _, name := range AllChecks {
		qt.Assert(t, qt.IsTrue(SpecRefs[name] != ""), qt.Commentf("check %s", name))
	}
	qt.Assert(t, qt.Equals(len(AllChecks), 10))
	qt.Assert(t, qt.Equals(len(SpecRefs), 10))
}

func TestCheckOrderMatchesREADME(t *testing.T) {
	want := []string{
		"response_integrity", "parse", "issuer_authenticity", "data_integrity",
		"revocation", "device_binding", "user_binding", "query_fulfilment",
		"combined_checks", "assemble_forward",
	}
	qt.Assert(t, qt.DeepEquals(AllChecks, want))
}

func TestSpecRefAnchors(t *testing.T) {
	qt.Assert(t, qt.Equals(SpecRefs[CheckResponseIntegrity], "OID4VP §8.2"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckIssuerAuthenticity], "ARF §6.6.3.6"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckRevocation], "ARF §6.6.3.7"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckDeviceBinding], "ARF §6.6.3.8"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckUserBinding], "ARF §6.6.3.9"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckQueryFulfilment], "OID4VP §6"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckCombinedChecks], "ARF Topic 18"))
	qt.Assert(t, qt.Equals(SpecRefs[CheckAssembleForward], "ARF AS-RP-51-008/011/013"))
}
