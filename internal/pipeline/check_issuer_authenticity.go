package pipeline

import (
	"context"
	stdcrypto "crypto"
	"errors"
	"fmt"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
)

// No "encoding/base64" import here — ProcessResponse already
// decoded mdoc payloads; decoding them again is the fixed double-decode bug.
type issuerAuthenticity struct{}

// IssuerAuthenticity is step 3. // [ARF §6.6.3.6]: verify IssuerAuth/MSO or the
// SD-JWT issuer signature and chain to a trust anchor of the right type via
// go-eudi-trust. The credential's own validity window is enforced here as well —
// this service's own rule, not part of the ARF clause. Both formats verify in ONE
// library call whose digest/binding-class failures are DEFERRED to steps 4/6
// (Locked pipeline contract). SD-JWT
// is NOT split into a "phase 1" (RequireKB=false) call here plus a "phase 2"
// (RequireKB=true) call in check_device_binding — real sdjwt.Verify verifies
// a PRESENT KB regardless of RequireKB (verify.go:78), so that split simply
// re-verified the same KB-JWT twice with contradictory RequireKB values.
// RequireKB is decided ONCE, here, from the static per-query policy/DCQL
// value (queryRequiresBinding) — never toggled across two calls.
func IssuerAuthenticity() Check { return issuerAuthenticity{} }

func (issuerAuthenticity) Name() string { return CheckIssuerAuthenticity }

func (issuerAuthenticity) Run(ctx context.Context, pc *PipelineContext) (CheckResult, error) {
	for _, cred := range pc.Credentials {
		var verr error
		switch cred.Pres.Format {
		case dcql.FormatSDJWT:
			verr = verifySDJWT(ctx, pc, cred)
		case dcql.FormatMdoc:
			verr = verifyMdoc(ctx, pc, cred)
		}
		if verr == nil {
			continue
		}
		step, code := classifyFormatError(verr)
		if step == CheckIssuerAuthenticity || step == CheckParse {
			// Parse-class at this stage means Peek accepted what Verify
			// rejects — report it here as this step's failure, keeping the
			// parse attribution code.
			return CheckResult{Outcome: OutcomeFail, Code: code, Detail: safeDetail(verr)}, nil
		}
		// Digest / binding failures are deferred to their designated step.
		cred.DeferredStep, cred.DeferredErr = step, verr
	}
	return CheckResult{Outcome: OutcomePass}, nil
}

func verifySDJWT(ctx context.Context, pc *PipelineContext, cred *Credential) error {
	peekVCT := vctFromQuery(pc, cred.Pres.QueryCredID)
	// cred.X5C is []*x509.Certificate (Peek shape); go-eudi-trust's
	// ResolveIssuerKey takes chain [][]byte (raw DER) — convert here.
	chain := make([][]byte, len(cred.X5C))
	for i, c := range cred.X5C {
		chain[i] = c.Raw
	}
	// The signing time selects the instant the certificate path is judged at. It
	// comes from Peek, so it is unverified here; the verified value is compared
	// below, once Verify has authenticated the credential.
	var claimedIAT time.Time
	if cred.IAT != nil {
		claimedIAT = *cred.IAT
	}
	at := pc.IssuerValidity.PathValidationTime(claimedIAT, trust.Now(pc.Anchors))
	key, issuer, err := resolveIssuerFor(pc, chain, peekVCT, at)
	if err != nil {
		return err
	}
	cred.IssuerKey, cred.Issuer = key, issuer
	// ONE call. RequireKB is the same static per-query value
	// check_device_binding.go (step 6) uses to decide skip-vs-report — never
	// a phase toggle. A resulting KB-class error is deferred and attributed
	// to step 6 by classifyFormatError, same as any other deferred class.
	required := pc.Policy.RequireDeviceBindingSDJWT() && queryRequiresBinding(pc, cred.Pres.QueryCredID)
	vc, err := pc.SDJWT.Verify(ctx, sdjwt.VerifyInput{
		Presentation:  cred.Pres.Payload,
		IssuerKey:     key,
		ExpectedAud:   expectedKBAudience(pc, cred),
		ExpectedNonce: cred.Pres.Nonce,
		RequireKB:     required,
	})
	if err != nil {
		return err
	}
	// The issuer path was judged at a time read before this signature verified.
	// Require the authenticated value to be that same time, so the certificate
	// window was not judged against a number an attacker supplied.
	if pc.IssuerValidity.SigningTimeUsed(claimedIAT) && !vc.IssuedAt.Equal(claimedIAT) {
		return fmt.Errorf("%w: signing time differs between the presented and the verified credential", sdjwt.ErrMalformed)
	}
	cred.SD = vc
	return nil
}

// expectedKBAudience is the audience a Key Binding JWT must carry.
//
// For a browser-based presentation it is the calling origin, prefixed with
// "origin:" — [OID4VP §A.4] states this "is the case even for signed
// requests" and that the Client Identifier is therefore NOT used as the
// audience there. The mdoc path already binds the origin the same way through
// its own handover (verifyMdoc below); this is the SD-JWT half of the same
// rule.
//
// The consequence that makes it load-bearing rather than cosmetic: an unsigned
// browser request carries no Client Identifier at all ([OID4VP §A.2]), so
// a Client-Identifier audience is not merely non-conformant there — there is
// nothing to compare against, and every key-bound SD-JWT would fail.
//
// Every other flow keeps the Client Identifier: the wallet reached us through a
// request_uri, and that identifier is what it authenticated.
func expectedKBAudience(pc *PipelineContext, cred *Credential) string {
	if pc.Origin != "" {
		return "origin:" + pc.Origin
	}
	return cred.Pres.ClientID
}

func verifyMdoc(ctx context.Context, pc *PipelineContext, cred *Credential) error {
	// oid4vp.ProcessResponse (and ProcessDCAPIResponse) already
	// base64url-decoded the mdoc payload into Presentation.Payload — decoding
	// it again here fails on raw CBOR. Use it verbatim.
	raw := cred.Pres.Payload
	var st mdoc.SessionTranscript
	if pc.Origin != "" {
		// OID4VP Annex B.2.6.2 DCAPI handover: (origin, nonce,
		// jwkThumbprint) — no client_id/response_uri in this variant.
		st = mdoc.OID4VPDCAPIHandover(pc.Origin, cred.Pres.Nonce, cred.Pres.JWKThumbprint)
	} else {
		// OID4VP Annex B.2.6.1: (client_id, nonce, jwkThumbprint, response_uri).
		// JWKThumbprint is the RP's OWN ephemeral encryption key thumbprint,
		// computed by ProcessResponse as raw digest bytes — the handover carries
		// it as a CBOR byte string. client_id keeps its Client Identifier Prefix.
		st = mdoc.OID4VPHandover(cred.Pres.ClientID, cred.Pres.Nonce,
			cred.Pres.JWKThumbprint, cred.Pres.ResponseURI)
	}
	// go-mdoc wraps a resolver error with %v (verify.go verifyIssuerAuth), so
	// the trust sentinel (ErrCacheExpired / ErrChainUntrusted) does NOT survive
	// errors.Is through the returned ErrIssuerAuth. Capture the root cause here
	// so classifyFormatError sees the real trust error and preserves the
	// precise code (anchor-unavailable stays anchor-unavailable,
	// not a generic issuer-untrusted). Symmetric with the SD-JWT path, where
	// resolveIssuerFor returns the trust error directly before Verify runs.
	docs, err := pc.MDoc.Verify(ctx, mdoc.VerifyInput{
		DeviceResponse:    raw,
		SessionTranscript: st,
		IssuerTrust: &issuerTrust{
			pc:      pc,
			doctype: doctypeFromQuery(pc, cred.Pres.QueryCredID),
			cred:    cred,
		},
	})
	if err != nil {
		return err
	}
	if len(docs) != 1 {
		return fmt.Errorf("%w: expected 1 document, got %d", mdoc.ErrMalformed, len(docs))
	}
	cred.MD = &docs[0]
	return nil
}

// resolveByTypes tries anchor types in ARF order; first chain wins.
// trust.ErrCacheExpired short-circuits immediately (fail closed).
func resolveByTypes(src trust.AnchorSource, chain [][]byte, types []trust.AnchorType, at time.Time) (stdcrypto.PublicKey, trust.ResolvedIssuer, error) {
	var lastErr error
	for _, t := range types {
		key, issuer, err := trust.ResolveIssuerKey(src, chain, t, at)
		if err == nil {
			return key, issuer, nil
		}
		if errors.Is(err, trust.ErrCacheExpired) {
			return nil, trust.ResolvedIssuer{}, err
		}
		lastErr = err
	}
	if lastErr == nil {
		// No types offered (empty issuance set) — fail closed rather than
		// silently accepting an unresolved chain.
		lastErr = fmt.Errorf("%w: no anchor types configured for credential", trust.ErrChainUntrusted)
	}
	return nil, trust.ResolvedIssuer{}, lastErr
}

// useCaseAllowed reports whether an anchor accredited for `have` use cases may
// vouch for a credential scoped to `required`. required=="" ⇒ always
// (unscoped class). A use-case-scoped credential requires explicit membership;
// an anchor with no declared use cases is NOT implicitly accredited (fail
// closed).
func useCaseAllowed(required string, have []string) bool {
	if required == "" {
		return true
	}
	for _, u := range have {
		if u == required {
			return true
		}
	}
	return false
}

// resolveIssuerFor resolves the issuer key for a credential type and enforces
// EAA use-case scoping: if the type maps to a use-case-scoped class,
// the matched anchor MUST be accredited for that use case. Reuses
// trust.ErrChainUntrusted so a use-case mismatch surfaces as issuer-untrusted
// with a distinct detail (no new reason code).
func resolveIssuerFor(pc *PipelineContext, chain [][]byte, doctypeOrVCT string, at time.Time) (stdcrypto.PublicKey, trust.ResolvedIssuer, error) {
	key, issuer, err := resolveByTypes(pc.Anchors, chain, pc.CredTrust.Issuance(doctypeOrVCT), at)
	if err != nil {
		return nil, trust.ResolvedIssuer{}, err
	}
	if uc := pc.CredTrust.UseCaseFor(doctypeOrVCT); !useCaseAllowed(uc, issuer.UseCases) {
		return nil, trust.ResolvedIssuer{}, fmt.Errorf("%w: issuer not accredited for use case %q", trust.ErrChainUntrusted, uc)
	}
	return key, issuer, nil
}

// resolveStatusSignerFor resolves the status-list signer key with the same
// use-case scoping as the issuer. Consumed by the revocation check
// (step 5, check_revocation.go); declared here alongside resolveIssuerFor
// because both derive from CredTrust and share resolveByTypes/useCaseAllowed.
func resolveStatusSignerFor(pc *PipelineContext, chain [][]byte, doctypeOrVCT string) (stdcrypto.PublicKey, error) {
	// Deliberately the current time, whichever model is configured: a status list
	// token is a freshly-issued artefact fetched now, so its signer must be valid
	// now. The signing-time question does not arise for it.
	key, issuer, err := resolveByTypes(pc.Anchors, chain, pc.CredTrust.Status(doctypeOrVCT), trust.Now(pc.Anchors))
	if err != nil {
		return nil, err
	}
	if uc := pc.CredTrust.UseCaseFor(doctypeOrVCT); !useCaseAllowed(uc, issuer.UseCases) {
		return nil, fmt.Errorf("%w: status signer not accredited for use case %q", trust.ErrChainUntrusted, uc)
	}
	return key, nil
}

func vctFromQuery(pc *PipelineContext, queryCredID string) string {
	for i := range pc.Session.Query.Credentials {
		cq := &pc.Session.Query.Credentials[i]
		if cq.ID == queryCredID && cq.Meta != nil && len(cq.Meta.VCTValues) > 0 {
			return cq.Meta.VCTValues[0]
		}
	}
	return ""
}

func doctypeFromQuery(pc *PipelineContext, queryCredID string) string {
	for i := range pc.Session.Query.Credentials {
		cq := &pc.Session.Query.Credentials[i]
		if cq.ID == queryCredID && cq.Meta != nil {
			return cq.Meta.DoctypeValue
		}
	}
	return ""
}

// queryRequiresBinding reports the DCQL query's own
// require_cryptographic_holder_binding for a credential query id ([OID4VP §6.1],
// default true). Moved here (from check_device_binding.go)
// because verifySDJWT (step 3) now needs this SAME value, computed ONCE, to
// decide RequireKB for the single sdjwt.Verify call — check_device_binding.go
// (step 6) calls this identical function again only to decide skip-vs-report,
// never to re-verify.
func queryRequiresBinding(pc *PipelineContext, queryCredID string) bool {
	for i := range pc.Session.Query.Credentials {
		if pc.Session.Query.Credentials[i].ID == queryCredID {
			return pc.Session.Query.Credentials[i].HolderBindingRequired() // [OID4VP §6.1] default true
		}
	}
	return true
}

// issuerTrust is the mdoc trust boundary: it turns the deployment's validity
// model into the instant a credential's certificate path is judged at, and
// records the resolved issuer on the credential for the report.
//
// go-mdoc hands it the signing time the credential claims. That value is
// unverified at this point and is treated as a choice of validation time only —
// go-mdoc separately asserts the time falls inside the signer certificate's own
// window, and re-asserts it against the authenticated copy once the signature
// verifies.
type issuerTrust struct {
	pc      *PipelineContext
	doctype string
	cred    *Credential
}

func (t *issuerTrust) ResolveIssuerKey(x5chain [][]byte, signed time.Time) (stdcrypto.PublicKey, error) {
	at := t.pc.IssuerValidity.PathValidationTime(signed, trust.Now(t.pc.Anchors))
	key, issuer, err := resolveIssuerFor(t.pc, x5chain, t.doctype, at)
	if err != nil {
		return nil, err
	}
	t.cred.IssuerKey, t.cred.Issuer = key, issuer
	return key, nil
}
