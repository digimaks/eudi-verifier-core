package pipeline

import "context"

type assembleForward struct{}

// AssembleForward is step 10. // ARF AS-RP-51-008: forward ONLY the presented
// attributes; ARF AS-RP-51-011/013: delete immediately after forwarding (or on
// failure — the failure path calls Finalize from the processor). The sink is
// the Valkey handoff queue; delivery to the client is handled downstream.
func AssembleForward() Check { return assembleForward{} }

func (assembleForward) Name() string { return CheckAssembleForward }

func (assembleForward) Run(ctx context.Context, pc *PipelineContext) (CheckResult, error) {
	res := &Result{SessionID: pc.SessionID, Outcome: "verified"}
	for _, cred := range pc.Credentials {
		res.Credentials = append(res.Credentials, ResultCredential{
			QueryCredentialID: cred.Pres.QueryCredID,
			Format:            cred.Pres.Format,
			DoctypeOrVCT:      cred.DoctypeOrVCT(),
			Claims:            cred.Claims(),
		})
		pc.Report.AddCredential(CredentialSummary{
			QueryCredID:      cred.Pres.QueryCredID,
			Format:           cred.Pres.Format,
			DoctypeOrVCT:     cred.DoctypeOrVCT(),
			IssuerCountry:    cred.Issuer.AnchorCountry, // trust.ResolvedIssuer has no .Country
			StatusProvenance: cred.StatusProvenance,
			DecoyDigests:     decoysOf(cred),
		}, cred.Claims())
	}

	result := CheckResult{Outcome: OutcomePass, SpecRef: SpecRefs[CheckAssembleForward], Check: CheckAssembleForward}

	// pc.Report only holds checks 1-9
	// right now — the Engine appends THIS check's own row to pc.Report AFTER
	// Run returns (per-check accumulation, pipeline.go Engine.Run).
	// Build the DELIVERED report as an independent copy with the 10th row added
	// here, so result_jwe matches the eventual persisted report exactly; copy
	// (not alias) pc.Report.Build()'s Checks slice so this does NOT double-count
	// when the Engine appends its own row to pc.Report afterward (Builder.Build
	// does a shallow struct copy — the Checks slice header is shared, so
	// appending in place here would risk corrupting the builder's backing array).
	delivered := pc.Report.Build()
	checks := make([]CheckResult, len(delivered.Checks), len(delivered.Checks)+1)
	copy(checks, delivered.Checks)
	delivered.Checks = append(checks, result)
	delivered.Outcome = "verified"
	res.Report = delivered

	if err := Finalize(ctx, pc, res); err != nil {
		return CheckResult{Outcome: OutcomeFail, Code: "err:session:handoff-failed",
			Detail: safeDetail(err)}, nil
	}
	return result, nil
}

func decoysOf(cred *Credential) int {
	if cred.SD != nil {
		return cred.SD.DecoyDigests // Decision: counted in report metadata
	}
	return 0
}
