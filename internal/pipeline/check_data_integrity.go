package pipeline

import "context"

type dataIntegrity struct{}

// DataIntegrity is step 4. // [ISO/IEC 18013-5 §9.1.2] (ValueDigests vs
// disclosed IssuerSignedItems) / [SD-JWT §7.1] (_sd digests). The
// verification itself ran inside step 3's library call; this step REPORTS
// integrity-class failures at their designated position (deferred attribution)
// and records decoy-digest counts for the report.
func DataIntegrity() Check { return dataIntegrity{} }

func (dataIntegrity) Name() string { return CheckDataIntegrity }

func (dataIntegrity) Run(_ context.Context, pc *PipelineContext) (CheckResult, error) {
	for _, cred := range pc.Credentials {
		if cred.DeferredStep == CheckDataIntegrity {
			return CheckResult{Outcome: OutcomeFail, Code: "err:credential:integrity",
				Detail: "credential " + cred.Pres.QueryCredID + ": " + safeDetail(cred.DeferredErr)}, nil
		}
	}
	return CheckResult{Outcome: OutcomePass}, nil
}
