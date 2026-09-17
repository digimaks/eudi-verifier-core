package pipeline

import "sort"

// CredentialSummary is the value-free per-credential report entry
// (claim NAMES only).
type CredentialSummary struct {
	QueryCredID      string   `json:"query_credential_id"`
	Format           string   `json:"format"`
	DoctypeOrVCT     string   `json:"doctype_or_vct"`
	IssuerCountry    string   `json:"issuer_country,omitempty"`
	ClaimNames       []string `json:"claim_names"`
	StatusProvenance string   `json:"status_provenance,omitempty"` // provenance, verbatim
	DecoyDigests     int      `json:"decoy_digests,omitempty"`     // counted in report metadata
}

// Report is what session.save_report persists and what clients see.
type Report struct {
	SessionID   string              `json:"session_id"`
	Outcome     string              `json:"outcome"` // verified | failed
	FailCode    string              `json:"fail_code,omitempty"`
	Checks      []CheckResult       `json:"checks"`
	Credentials []CredentialSummary `json:"credentials,omitempty"`
	Policy      map[string]bool     `json:"policy"` // branches visible
}

// Builder accumulates a Report during a pipeline run. It is the ONLY writer of
// the Report type — claim values structurally cannot enter it (AddCredential
// reduces claims to names; see flattenNames).
type Builder struct{ r Report }

// NewBuilder returns a Builder seeded to the fail-closed default outcome:
// a run that never reaches Verified() persists as "failed".
func NewBuilder(sessionID string) *Builder {
	return &Builder{r: Report{SessionID: sessionID, Outcome: "failed", Policy: map[string]bool{}}}
}

// Add appends one check result, length-capping Detail as a defense-in-depth
// bound on any text a check writer places there (values must never reach it).
func (b *Builder) Add(res CheckResult) {
	if len(res.Detail) > 200 {
		res.Detail = res.Detail[:200]
	}
	b.r.Checks = append(b.r.Checks, res)
}

// AddCredential records the summary; claims are reduced to sorted flattened
// NAMES here — values never enter the Report type (structural guarantee).
func (b *Builder) AddCredential(sum CredentialSummary, claims map[string]any) {
	sum.ClaimNames = flattenNames(claims, "")
	b.r.Credentials = append(b.r.Credentials, sum)
}

// SetPolicyBranch records whether a per-client policy branch was active, so
// every relaxation is visible in the report.
func (b *Builder) SetPolicyBranch(name string, active bool) { b.r.Policy[name] = active }

// Failed marks the report failed with the given err:domain:reason code.
func (b *Builder) Failed(code string) { b.r.Outcome, b.r.FailCode = "failed", code }

// Verified marks the report verified and clears any fail code.
func (b *Builder) Verified() { b.r.Outcome, b.r.FailCode = "verified", "" }

// Build returns a copy of the accumulated report.
func (b *Builder) Build() *Report { r := b.r; return &r }

// flattenNames reduces a (possibly nested) claim map to sorted dotted NAMES,
// discarding every value. "nested.given_name" flattening keeps the
// report structurally value-free regardless of claim depth.
func flattenNames(m map[string]any, prefix string) []string {
	var out []string
	for k, v := range m {
		name := k
		if prefix != "" {
			name = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			out = append(out, flattenNames(sub, name)...)
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
