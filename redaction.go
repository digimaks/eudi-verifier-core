package verifiercore

import "github.com/gmb-lib/go-platform-kit/observability"

// RedactionPolicy extends the fleet default with the verifier credential-PII
// list (ARF AS-RP-01-002). It is additive-only over observability.DefaultRedactionPolicy
// — every fleet-default DropKey/MaskKey is retained ("add, never
// weaken") — so it is safe to pass as platform.Options.Redaction in place of
// leaving the option nil.
//
// Matching is case-insensitive SUBSTRING on top-level field keys (see
// go-platform-kit's observability redaction) — so
// "claim" also catches "claim_value"/"claims"/"claim_values"; "disclosure"
// catches "disclosure_salt"/"disclosures". Matching is top-level-key only:
// NEVER log a nested map/struct of claims via zap.Any/zap.Reflect — the
// redacting core cannot see inside it, so sensitive keys within would bypass
// this policy entirely. Log individual scalar fields instead.
//
// Gotcha discovered writing this task's end-to-end test (redaction_test.go):
// the fleet default's DropKeys already contains "session" (substring), so a
// literal "session_id" log field is silently dropped fleet-wide, not just
// under this extension (see TestSessionIDFieldIsDroppedByFleetDefault). Do
// NOT log a "session_id"/"*session*" field expecting it to survive — identify
// a session in logs via "correlation_id" instead (bound automatically by
// github.com/gmb-lib/go-platform-kit/correlation's middleware).
func RedactionPolicy() *observability.RedactionPolicy {
	p := observability.DefaultRedactionPolicy()
	p.DropKeys = append(p.DropKeys,
		"claim",            // disclosed claim values (claim_value, claims, claim_values)
		"disclosure",       // disclosure content + salts (disclosure_salt, disclosures)
		"salt",             // disclosure salts logged standalone
		"vp_token",         // raw vp_token content
		"kb_jwt",           // KB-JWT payloads (kb_jwt_payload, kb_jwt)
		"device_signature", // mdoc device signatures
		"deviceauth",       // mdoc DeviceAuth structures
		"portrait",         // portrait images (PII bytes)
		"biometric",        // biometric templates
		"document_number",  // document numbers
		"documentnumber",
	)
	return p
}
