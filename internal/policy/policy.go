// Package policy is the per-client verification policy snapshot, stored on
// the session at creation (session.session.policy) and echoed into the
// verification report (policy branches visible). Defaults fail
// closed.
package policy

import "encoding/json"

// ClientPolicy is the per-client verification policy. Every relaxation is an
// explicit *bool: nil = the fail-closed default. This makes an absent field
// indistinguishable from the safe default and every deviation an explicit,
// auditable choice (surfaced in the verification report).
type ClientPolicy struct {
	// nil = default true (fail closed / bind by default).
	RevocationFailClosedP      *bool `json:"revocation_fail_closed,omitempty"`
	ShortLivedExemptionP       *bool `json:"short_lived_exemption,omitempty"`        // [ARF §6.6.3.7]: <24h validity may skip revocation
	RequireDeviceBindingSDJWTP *bool `json:"require_device_binding_sdjwt,omitempty"` // [ARF §6.6.3.8]: recommended + default-on for SD-JWT VC
	RequireSignedDCAPIP        *bool `json:"require_signed_dcapi,omitempty"`         // [OID4VP §A.2] / [OID4VP §A.3.2]: signed browser requests carry our identity, unsigned carry none
}

// RevocationFailClosed reports whether an unresolvable revocation status must
// fail the verification (default true).
func (p ClientPolicy) RevocationFailClosed() bool {
	return p.RevocationFailClosedP == nil || *p.RevocationFailClosedP
}

// ShortLivedExemption reports whether short-lived (<24h) credentials may skip
// the revocation check ([ARF §6.6.3.7]). Default true.
func (p ClientPolicy) ShortLivedExemption() bool {
	return p.ShortLivedExemptionP == nil || *p.ShortLivedExemptionP
}

// RequireDeviceBindingSDJWT reports whether SD-JWT VC device binding (KB-JWT)
// is required ([ARF §6.6.3.8]). Default true.
func (p ClientPolicy) RequireDeviceBindingSDJWT() bool {
	return p.RequireDeviceBindingSDJWTP == nil || *p.RequireDeviceBindingSDJWTP
}

// RequireSignedDCAPI reports whether this client's browser-based presentation
// requests must be signed. Default true: a signed request is the one that lets
// the wallet authenticate us through our certificate chain and registration
// data, so silence means the mode that keeps that layer rather than the one
// that drops it.
//
// It is only consulted where the deployment permits both modes; a deployment
// fixed to one mode never asks. So this can narrow a client, never widen a
// deployment.
func (p ClientPolicy) RequireSignedDCAPI() bool {
	return p.RequireSignedDCAPIP == nil || *p.RequireSignedDCAPIP
}

// Parse decodes a stored policy snapshot. An empty input is the all-defaults
// (fail-closed) policy; malformed JSON is rejected (fail closed).
func Parse(raw []byte) (ClientPolicy, error) {
	var p ClientPolicy
	if len(raw) == 0 {
		return p, nil
	}
	err := json.Unmarshal(raw, &p)
	return p, err
}
