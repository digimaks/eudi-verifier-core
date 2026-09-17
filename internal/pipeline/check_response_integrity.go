package pipeline

import (
	"context"
	"errors"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

type responseIntegrity struct{}

// ResponseIntegrity is step 1. // [OID4VP §8.2]: decrypt the direct_post.jwt
// JWE (per-session ephemeral key), validate state binding, parse the
// vp_token object, mint the response_code. One-time-use was already
// linearized by SessionStore.ConsumeOnce at the transport layer; replay of
// the endpoint therefore fails before the pipeline starts.
func ResponseIntegrity() Check { return responseIntegrity{} }

func (responseIntegrity) Name() string { return CheckResponseIntegrity }

func (responseIntegrity) Run(ctx context.Context, pc *PipelineContext) (CheckResult, error) {
	// DCAPI uses a SEPARATE engine method
	// with a different signature/body shape — ProcessResponse explicitly
	// rejects DCAPI sessions (real source: response.go:69, ErrFlowMismatch).
	// oid4vp.RawResponse has ONLY a Body field (no Origin) — origin comes
	// from pc.Origin (set by the processor from the transport)
	// and is passed as ProcessDCAPIResponse's own parameter.
	if pc.Session.Flow == oid4vp.DCAPI {
		pres, err := pc.Engine.ProcessDCAPIResponse(ctx, pc.Session, pc.Origin, pc.Raw.Body)
		if err != nil {
			return CheckResult{Outcome: OutcomeFail, Code: classifyOID4VP(err), Detail: failDetail(err)}, nil
		}
		pc.Presentations = pres // no ResponseCode: DCAPI has no same-device return
		return CheckResult{Outcome: OutcomePass}, nil
	}
	pres, code, err := pc.Engine.ProcessResponse(ctx, pc.Session, pc.Raw)
	if err != nil {
		return CheckResult{Outcome: OutcomeFail, Code: classifyOID4VP(err), Detail: failDetail(err)}, nil
	}
	pc.Presentations = pres
	pc.ResponseCode = code
	return CheckResult{Outcome: OutcomePass}, nil
}

// failDetail records what a step-1 failure means for whoever reads the report.
//
// For a wallet that declined, that is the wallet's OWN stated reason, read off
// the typed error rather than its message: the wallet's account is the only one
// that exists — nothing on this side can reconstruct why a wallet refused — and
// the error's message deliberately carries the code alone. Wallet-supplied text,
// already length-capped where the error is built and capped again by the report
// builder; still untrusted, so it is recorded, never interpreted.
func failDetail(err error) string {
	var declined *oid4vp.WalletError
	if errors.As(err, &declined) {
		detail := "wallet reported " + declined.Code
		if declined.Description != "" {
			detail += ": " + declined.Description
		}

		return detail
	}

	return safeDetail(err)
}

// classifyOID4VP maps typed errors to problem codes.
func classifyOID4VP(err error) string {
	var declined *oid4vp.WalletError

	switch {
	case errors.As(err, &declined):
		// The wallet refused BEFORE presenting anything, and said why. That is
		// not a presentation that failed to verify: the two have opposite causes
		// and opposite fixes, and collapsing them into one code hides the only
		// explanation anyone gets — the wallet's own. Its text rides along in
		// the check Detail via safeDetail.
		return "err:presentation:wallet-declined"
	case errors.Is(err, oid4vp.ErrStateMismatch):
		return "err:presentation:nonce-mismatch" // state/nonce/response_code binding failed
	case errors.Is(err, oid4vp.ErrSessionConsumed):
		return "err:session:consumed"
	default:
		// ErrDecrypt / ErrMalformedResponse / ErrUnknownCredentialID / anything else.
		return "err:presentation:invalid-response"
	}
}
