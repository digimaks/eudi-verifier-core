package pipeline

import (
	"bytes"
	"context"
)

type combinedChecks struct{}

// CombinedChecks is step 9. // ARF Topic 18: in a combined presentation each
// credential is independently verified (structural here — steps 2–7 ran per
// credential and short-circuit on any failure) and the SAME artifact must
// not answer multiple query ids. Cryptographic same-WSCD binding is an
// extension point: ARF 2.9 specifies no mechanism, so it is recorded as not
// evaluated (never silently passed).
func CombinedChecks() Check { return combinedChecks{} }

func (combinedChecks) Name() string { return CheckCombinedChecks }

func (combinedChecks) Run(_ context.Context, pc *PipelineContext) (CheckResult, error) {
	for i := range pc.Credentials {
		for j := i + 1; j < len(pc.Credentials); j++ {
			a, b := pc.Credentials[i], pc.Credentials[j]
			if a.Pres.QueryCredID != b.Pres.QueryCredID && bytes.Equal(a.Pres.Payload, b.Pres.Payload) {
				return CheckResult{Outcome: OutcomeFail, Code: "err:presentation:combined-check",
					Detail: "identical credential presented for " + a.Pres.QueryCredID + " and " + b.Pres.QueryCredID}, nil
			}
		}
	}
	return CheckResult{Outcome: OutcomePass, Detail: "wscd-binding: not evaluated (no ARF mechanism)"}, nil
}
