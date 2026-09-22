package pipeline

import (
	"context"

	dcql "github.com/gmb-eudi/go-dcql"
)

type deviceBinding struct{}

// DeviceBinding is step 6. // [ARF §6.6.3.8], ARF AS-RP-01-003: mdoc DeviceAuth
// (deviceSignature over SessionTranscript) and SD-JWT KB-JWT (nonce, aud,
// sd_hash) were BOTH already verified inside step 3's SINGLE library call
// (there is no second sdjwt.Verify
// call here — real sdjwt.Verify verifies a present KB regardless of
// RequireKB, so a "phase 2" re-verify would just repeat step 3's call with a
// contradictory RequireKB value). This step only REPORTS: a deferred
// binding-class failure at its designated position (queryRequiresBinding below
// mirrors the SAME static per-query value verifySDJWT used to decide
// RequireKB), or pass/skip for a credential that reached here clean. SD-JWT
// binding is default-on, relaxable per client policy AND per query
// require_cryptographic_holder_binding — any skip is visible in the report.
func DeviceBinding() Check { return deviceBinding{} }

func (deviceBinding) Name() string { return CheckDeviceBinding }

func (deviceBinding) Run(_ context.Context, pc *PipelineContext) (CheckResult, error) {
	pc.Report.SetPolicyBranch("require_device_binding_sdjwt", pc.Policy.RequireDeviceBindingSDJWT())

	anySkipped := false
	for _, cred := range pc.Credentials {
		// Deferred mdoc DeviceAuth failure (or SD-JWT KB failure) from step 3's
		// single verify call reports here — its designated step.
		if cred.DeferredStep == CheckDeviceBinding {
			cred.DeviceBindingCheck = OutcomeFail
			return CheckResult{Outcome: OutcomeFail, Code: "err:credential:binding-failed",
				Detail: "credential " + cred.Pres.QueryCredID + ": " + safeDetail(cred.DeferredErr)}, nil
		}
		switch cred.Pres.Format {
		case dcql.FormatMdoc:
			// DeviceAuth verified in step 3's call; reaching here means pass.
			cred.HolderBound, cred.DeviceBindingCheck = true, OutcomePass

		case dcql.FormatSDJWT:
			required := pc.Policy.RequireDeviceBindingSDJWT() && queryRequiresBinding(pc, cred.Pres.QueryCredID)
			if !required {
				cred.DeviceBindingCheck = OutcomeSkipped
				anySkipped = true
				continue
			}
			// KB-JWT already verified in step 3 (verifySDJWT, RequireKB=true
			// for this same query); no DeferredStep == CheckDeviceBinding
			// above means it passed. No second Verify call.
			cred.HolderBound, cred.DeviceBindingCheck = true, OutcomePass
		}
	}
	if anySkipped {
		return CheckResult{Outcome: OutcomeSkipped, Code: "device-binding-policy-skipped"}, nil
	}
	return CheckResult{Outcome: OutcomePass}, nil
}
