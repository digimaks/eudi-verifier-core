package pipeline

import (
	"encoding/json"
	"errors"

	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
)

// classifyFormatError attributes a monolithic sdjwt/mdoc verification error
// to the pipeline step that owns it (Locked pipeline contract). ONE table —
// never classify inline.
// Every branch uses errors.Is so a %w-wrapped sentinel classifies identically.
func classifyFormatError(err error) (step, code string) {
	switch {
	// Step 2 — structural.
	case errors.Is(err, sdjwt.ErrMalformed), errors.Is(err, mdoc.ErrMalformed):
		return CheckParse, "err:credential:parse"
	// Step 4 — digest/disclosure integrity ([ISO/IEC 18013-5 §9.1.2] / [SD-JWT §7.1]).
	// ErrDuplicateDigest/ErrClaimCollision are sdjwt's own err:credential:integrity
	// sentinels (errors.go doc comments) — same class as ErrDigestMismatch,
	// all raised inside reconstruct() during Verify (verify.go:66).
	case errors.Is(err, sdjwt.ErrDigestMismatch), errors.Is(err, mdoc.ErrIntegrity),
		errors.Is(err, sdjwt.ErrDuplicateDigest), errors.Is(err, sdjwt.ErrClaimCollision):
		return CheckDataIntegrity, "err:credential:integrity"
	// Step 6 — holder/device binding ([ARF §6.6.3.8]). No single sdjwt.ErrKB
	// sentinel exists — every real KB-class sentinel is listed
	// so a KB failure of any kind attributes here, matching the fault
	// matrix ("wrong nonce in KB" → step 6 / binding-failed). NOTE: the sdjwt
	// library's own
	// doc-comments mark ErrKBAudience/ErrKBNonce as err:presentation:nonce-mismatch,
	// not binding-failed — a real tension between the library's suggested
	// mapping and this pipeline's step attribution. ErrMissingCNF (errors.go:
	// err:credential:binding-failed) is holder-binding-required-but-absent,
	// raised both pre-KB (verify.go:58, binding required + cnf absent) and at
	// the KB gate (verify.go:83, KB present but cnf missing) — same class.
	// mdoc.ErrDeviceMacUnsupported (errors.go: maps to err:credential:binding-failed)
	// is deviceMac presented where remote flows require deviceSignature
	// (deviceauth.go:23) — a device-authentication-class failure like ErrDeviceAuth.
	case errors.Is(err, sdjwt.ErrKBRequired), errors.Is(err, sdjwt.ErrKBType),
		errors.Is(err, sdjwt.ErrKBSignature), errors.Is(err, sdjwt.ErrKBAudience),
		errors.Is(err, sdjwt.ErrKBNonce), errors.Is(err, sdjwt.ErrKBStale),
		errors.Is(err, sdjwt.ErrKBSDHash), errors.Is(err, sdjwt.ErrMissingCNF),
		errors.Is(err, mdoc.ErrDeviceAuth), errors.Is(err, mdoc.ErrDeviceMacUnsupported):
		return CheckDeviceBinding, "err:credential:binding-failed"
	// Step 3 — trust cache staleness fails closed.
	case errors.Is(err, trust.ErrCacheExpired):
		return CheckIssuerAuthenticity, "err:trust:anchor-unavailable"
	// Step 3 — validity window (MSO validityInfo / iat/exp).
	// ErrNotYetValid is ErrExpired's sibling (errors.go: both err:credential:expired;
	// verify.go:131 nbf-in-the-future vs verify.go:122 exp-in-the-past).
	// The convention pins 422; `expired` is a kit built-in (410), so the problem
	// carries WithStatus(422) at the FailCode→problem site
	// (routes/processor_pipeline.go walletFailProblem), on the problem object —
	// the wallet boundary renders OID4VP shapes, so the wallet sees 400
	// invalid_request, not this 422. The 422 still decides that it is told at
	// all: a client-visible rating is what marks the outcome a refusal to report
	// rather than a fault of ours (routes/wallet_error.go).
	case errors.Is(err, sdjwt.ErrExpired), errors.Is(err, mdoc.ErrValidity),
		errors.Is(err, sdjwt.ErrNotYetValid):
		return CheckIssuerAuthenticity, "err:credential:expired"
	// Step 3 — a certificate in the issuer path was outside its own validity
	// window at the time the configured model judged it, or the credential's
	// signing time fell outside its signer certificate's window. Distinct from
	// issuer-untrusted on purpose: nothing here is untrusted, and reporting it as
	// such is what sent external testers a certificate to declare as trusted.
	case errors.Is(err, trust.ErrChainOutOfValidity), errors.Is(err, mdoc.ErrIssuerCertValidity):
		return CheckIssuerAuthenticity, "err:credential:issuer-cert-expired"
	// Step 3 — everything else about the issuer path.
	default:
		return CheckIssuerAuthenticity, "err:credential:issuer-untrusted"
	}
}

// CredentialTrustMap classifies a credential type identifier (SD-JWT VC `vct`
// or mdoc `docType`) to the issuer trust-anchor types that may vouch for it
// ([ARF §6.6.3.6]). Config-driven (Configuration.CredentialTrustJSON →
// ParseCredentialTrust, injected via PipelineContext.CredTrust) so onboarding a
// new credential type is configuration, not a recompile. The built-in
// DefaultCredentialTrust reproduces the original hardcoded mapping.
type CredentialTrustMap struct {
	Classes  []CredentialClass  `json:"classes"`
	Fallback []trust.AnchorType `json:"fallback"` // issuance types when no class matches
}

// CredentialClass maps exact credential type identifiers to issuer anchor types
// (tried in order; first successful chain wins — order recorded in provenance).
type CredentialClass struct {
	Types    []string           `json:"types"`
	Issuance []trust.AnchorType `json:"issuance"`
	// UseCase scopes this class to an EAA use case: when non-empty, the
	// matched issuer/status anchor MUST be accredited for it (trust.Anchor.UseCases).
	// Empty = unscoped (no use-case check). Meaningful for EAA classes.
	UseCase string `json:"use_case,omitempty"`
}

// DefaultCredentialTrust reproduces the original hardcoded classification:
// PID → pid_provider; everything else → qeaa/pub_eaa/eaa provider.
func DefaultCredentialTrust() CredentialTrustMap {
	return CredentialTrustMap{
		Classes: []CredentialClass{{
			Types:    []string{"eu.europa.ec.eudi.pid.1", "urn:eudi:pid:1"},
			Issuance: []trust.AnchorType{trust.PIDProvider},
		}},
		Fallback: []trust.AnchorType{
			trust.QEAAProvider, trust.PubEAAProvider, trust.EAAProvider,
		},
	}
}

// ParseCredentialTrust builds the map from config JSON, prepending configured
// classes ahead of the Default classes (config wins on match); a non-empty
// configured fallback overrides the default. Empty ⇒ DefaultCredentialTrust.
func ParseCredentialTrust(raw []byte) (CredentialTrustMap, error) {
	def := DefaultCredentialTrust()
	if len(raw) == 0 {
		return def, nil
	}
	var cfg CredentialTrustMap
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return CredentialTrustMap{}, err
	}
	m := CredentialTrustMap{Classes: append(cfg.Classes, def.Classes...), Fallback: def.Fallback}
	if len(cfg.Fallback) > 0 {
		m.Fallback = cfg.Fallback
	}
	return m, nil
}

// Issuance returns the issuer anchor types that may vouch for a credential type
// (issuer authenticity, [ARF §6.6.3.6]). Replaces the old anchorTypesFor switch.
func (m CredentialTrustMap) Issuance(doctypeOrVCT string) []trust.AnchorType {
	for _, c := range m.Classes {
		for _, t := range c.Types {
			if t == doctypeOrVCT {
				return c.Issuance
			}
		}
	}
	return m.Fallback
}

// Status returns the anchor types for the credential's status-list signer:
// each issuance type's *_status counterpart first (derived
// via trust.StatusType — no hardcoded string pairing), then the issuance types
// as fallback for deployments where the status signer == issuer. resolveByTypes
// records the matched set in provenance; neither → ErrChainUntrusted (fail
// closed). Replaces the old statusAnchorTypesFor switch.
func (m CredentialTrustMap) Status(doctypeOrVCT string) []trust.AnchorType {
	issuance := m.Issuance(doctypeOrVCT)
	out := make([]trust.AnchorType, 0, len(issuance)*2)
	for _, t := range issuance {
		if s, ok := trust.StatusType(t); ok {
			out = append(out, s)
		}
	}
	return append(out, issuance...)
}

// UseCaseFor returns the EAA use case a credential type is scoped to,
// or "" if unscoped. When non-empty, issuer/status resolution requires the
// matched anchor to be accredited for it.
func (m CredentialTrustMap) UseCaseFor(doctypeOrVCT string) string {
	for _, c := range m.Classes {
		for _, t := range c.Types {
			if t == doctypeOrVCT {
				return c.UseCase
			}
		}
	}
	return ""
}
