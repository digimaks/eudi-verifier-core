package pipeline

import (
	"context"

	statuslist "github.com/gmb-eudi/go-statuslist"
)

type userBinding struct{}

// UserBinding is step 7. // [ARF §6.6.3.9] option 1 (Decision):
// v1 trusts the wallet's user authentication — implemented as the assertion
// that (a) device binding PASSED for every credential (step 6) and (b) the
// wallet solution is not revoked, proxied by credential revocation (step 5).
// Attribute/biometric binding is out of scope. Consequence: a client policy
// that skips SD-JWT device binding cannot pass user binding in v1 (flagged
// as a known open item).
func UserBinding() Check { return userBinding{} }

func (userBinding) Name() string { return CheckUserBinding }

func (userBinding) Run(_ context.Context, pc *PipelineContext) (CheckResult, error) {
	for _, cred := range pc.Credentials {
		if cred.DeviceBindingCheck != OutcomePass {
			return CheckResult{Outcome: OutcomeFail, Code: "err:credential:binding-failed",
				Detail: "user binding requires device binding for credential " + cred.Pres.QueryCredID}, nil
		}
		if cred.StatusResult == statuslist.StatusRevoked || cred.StatusResult == statuslist.StatusSuspended {
			return CheckResult{Outcome: OutcomeFail, Code: "err:credential:binding-failed",
				Detail: "wallet solution revocation proxy failed for credential " + cred.Pres.QueryCredID}, nil
		}
	}
	return CheckResult{Outcome: OutcomePass}, nil
}
