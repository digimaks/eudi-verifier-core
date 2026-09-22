package pipeline

import (
	stdcrypto "crypto"
	"crypto/x509"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
	statuslist "github.com/gmb-eudi/go-statuslist"
)

// CredentialTrustMap and CredentialClass (the credential-type → trust-anchor
// classification) are defined in errclass.go alongside the
// DefaultCredentialTrust built-in, the ParseCredentialTrust config parser, and
// the resolution helpers (resolveIssuerFor / resolveStatusSignerFor /
// useCaseAllowed) that consume them.

// Credential is the per-credential pipeline envelope. Attribute values live
// only in SD/MD until step 10 packages them into Result; they are then zeroed.
type Credential struct {
	Pres oid4vp.Presentation

	// Step 2 (structural peek). []*x509.Certificate to match the real
	// sdjwt.Peek shape (the "Add x5c + Peek" decision) — NOT [][]byte;
	// callers resolving through go-eudi-trust (chain [][]byte) must convert
	// via cert.Raw (see verifySDJWT).
	X5C []*x509.Certificate
	// IAT is the SD-JWT signing time as read by Peek — UNVERIFIED, nil when the
	// credential carries none. It selects the certificate-path validation time;
	// the verified value is re-read from the Verify result and the two must agree.
	IAT *time.Time

	// Step 3 (single library verification; deferred attribution — see the
	// Locked pipeline contract note).
	SD           *sdjwt.VerifiedCredential
	MD           *mdoc.VerifiedDocument
	IssuerKey    stdcrypto.PublicKey
	Issuer       trust.ResolvedIssuer
	DeferredStep string // check name a deferred failure belongs to; "" = fully verified
	DeferredErr  error

	// Step 5.
	StatusRef        *statuslist.StatusRef
	StatusResult     statuslist.Status
	StatusProvenance string

	// Step 6.
	HolderBound        bool
	DeviceBindingCheck Outcome // pass|fail|skipped — user_binding (7) consumes it
}

// Claims returns the disclosed claims map regardless of format.
func (c *Credential) Claims() map[string]any {
	switch {
	case c.SD != nil:
		return c.SD.Claims
	case c.MD != nil:
		out := make(map[string]any, len(c.MD.Namespaces))
		for ns, elems := range c.MD.Namespaces {
			m := make(map[string]any, len(elems))
			for k, v := range elems {
				m[k] = v
			}
			out[ns] = m
		}
		return out
	default:
		return nil
	}
}

// DoctypeOrVCT returns the credential type identifier.
func (c *Credential) DoctypeOrVCT() string {
	switch {
	case c.SD != nil:
		return c.SD.VCT
	case c.MD != nil:
		return c.MD.DocType
	default:
		return ""
	}
}

// Result is the forward-and-delete payload: the ONLY place attribute values
// exist outside pipeline memory, and only until the handoff TTL.
type Result struct {
	SessionID   string             `json:"session_id"`
	Outcome     string             `json:"outcome"`
	Report      *Report            `json:"report"`
	Credentials []ResultCredential `json:"credentials,omitempty"`
}

// ResultCredential carries one credential's disclosed claim VALUES to the
// delivery sink (step 10). This is the sole value-bearing report type; it
// never touches PostgreSQL and is deleted after handoff.
type ResultCredential struct {
	QueryCredentialID string         `json:"query_credential_id"`
	Format            string         `json:"format"`
	DoctypeOrVCT      string         `json:"doctype_or_vct"`
	Claims            map[string]any `json:"claims"`
}
