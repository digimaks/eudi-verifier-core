package routes

import (
	"encoding/json"
	"errors"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
)

// The OID4VP / OAuth 2.0 error code this boundary emits for a refused
// verification ([OID4VP §8.2]; [RFC 6749 §5.2]). Server faults keep the
// engine's own server_error rendering — they never reach this file.
const walletErrInvalidRequest = "invalid_request"

// Descriptions for a refused verification. What the wallet — and the person
// watching it — needs is which KIND of refusal happened: a credential we will
// not accept is a trust-data question, an unverifiable presentation is a
// response question, and a wallet that declined outright is neither. Announcing
// them the same way is what made a routine refusal indistinguishable from an
// outage.
//
// Several descriptions under ONE error code deliberately: the protocol code set
// is bounded and every wallet-triggerable condition here is already
// invalid_request, so the difference rides in the description, exactly as the
// protocol-level mappings do for decrypt, state binding and nonce binding.
const (
	descNotAccepted = "credential not accepted"
	descNotVerified = "presentation could not be verified"
	// The wallet refused and told us why — no presentation was ever made. Saying
	// "could not be verified" here describes something that did not happen, and
	// it reads to whoever is watching as our failure rather than the wallet's
	// decision. The wallet's own text is recorded in the run's report, not echoed
	// back to it: it already knows what it sent, and it is untrusted input.
	descWalletDeclined = "wallet reported an error"
)

// walletDeclinedCode is the reason the pipeline assigns when the wallet posted
// an OpenID4VP error response instead of a presentation
// (internal/pipeline classifyOID4VP). Asserted end-to-end by the wallet-declined
// route test, so the two sides cannot drift apart silently.
const walletDeclinedCode = "err:presentation:wallet-declined"

// trustRefusalCodes are the outcomes where the response itself verified but the
// credential is refused — its issuer resolves to no configured anchor, it has
// been revoked, or it is outside its validity window. Anything else
// client-visible is a failure of the presentation.
var trustRefusalCodes = map[string]bool{
	"err:credential:issuer-untrusted":    true,
	"err:credential:issuer-cert-expired": true,
	"err:credential:expired":             true,
	"err:revocation:revoked":             true,
}

// verificationOutcome renders a verification that ran to a decision and refused,
// in the OID4VP error shape. ok is false for anything that is not such an
// outcome — a protocol-level failure the engine owns, or a fault of ours — so
// the caller falls through to the engine's own mapping.
//
// The status is READ FROM the reason registry the code already resolves
// against, never from a second list kept here. That is what keeps the two
// boundaries from drifting apart again: a code the registry rates client-visible
// is reported to the wallet as a refusal, and anything it rates a server fault
// stays one and leaks nothing. Trust anchors being unreachable, a failed result
// handoff and an internal pipeline fault are all ours by that rule alone,
// without appearing anywhere in this file. An unregistered code resolves to 500,
// so a new reason added without a rating fails closed.
func verificationOutcome(err error) (int, []byte, bool) {
	var p *pkerrors.Problem
	if !errors.As(err, &p) {
		return 0, nil, false
	}
	if st := p.StatusCode(); st < 400 || st >= 500 {
		return 0, nil, false
	}

	desc := descNotVerified

	switch {
	case p.Code == walletDeclinedCode:
		desc = descWalletDeclined
	case trustRefusalCodes[p.Code]:
		desc = descNotAccepted
	}

	return 400, walletErrorBody(walletErrInvalidRequest, desc), true
}

// walletErrorBody serializes the OID4VP error shape ({"error",
// "error_description"}) — the protocol's own envelope, which the wallet
// boundary speaks instead of problem+json.
func walletErrorBody(code, desc string) []byte {
	// A fixed-shape map of strings never fails to marshal.
	body, _ := json.Marshal(map[string]string{
		"error":             code,
		"error_description": desc,
	})

	return body
}
