package pipeline

import (
	"context"
	stdcrypto "crypto"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	statuslist "github.com/gmb-eudi/go-statuslist"
)

type revocation struct{}

// Revocation is step 5. // [ARF §6.6.3.7]: Token Status List per credential,
// fail-open/fail-closed per client policy, <24h validity exempt. Policy
// branches surface in the report; the provenance
// string appears VERBATIM.
func Revocation() Check { return revocation{} }

func (revocation) Name() string { return CheckRevocation }

func (revocation) Run(ctx context.Context, pc *PipelineContext) (CheckResult, error) {
	pc.Report.SetPolicyBranch("revocation_fail_closed", pc.Policy.RevocationFailClosed())
	pc.Report.SetPolicyBranch("short_lived_exemption", pc.Policy.ShortLivedExemption())

	anySkipped := false
	for _, cred := range pc.Credentials {
		if cred.DeferredStep == CheckDeviceBinding {
			// Binding-deferred credential: verification produced no trusted
			// parse, so no trustworthy StatusRef exists. Visible skip; the
			// pipeline stops at step 6 anyway.
			cred.StatusProvenance = "not-evaluated-binding-pending"
			anySkipped = true
			continue
		}
		ref := statusRefOf(cred)
		if ref == nil {
			cred.StatusProvenance = "no-status-ref"
			continue // ARF: revocation data is recommended, not mandatory
		}
		// Record ref popularity so trust-cache-worker prefetches this list
		// (the worker reads the ZSET trust:statuslist:refs). Best-effort —
		// never blocks or fails verification; done for every referenced list,
		// including short-lived-exempt ones, so the worker keeps them warm.
		if pc.StatusRefs != nil {
			_ = pc.StatusRefs.Record(ctx, ref.URI)
		}
		// The [ARF §6.6.3.7] <24h exemption is built into
		// Checker.Check via CheckInput.CredentialValidity (checker.go) — it is
		// NOT reimplemented here. The client policy gate (ShortLivedExemption)
		// controls whether the checker is even TOLD the credential's remaining
		// validity: zero means "unknown, never skip".
		var credValidity time.Duration
		if pc.Policy.ShortLivedExemption() {
			credValidity = validityWindow(cred)
		}
		status, prov, err := pc.Status.Check(ctx, statuslist.CheckInput{
			Ref: *ref,
			// Real KeyResolver is func(ctx, listURI string, token
			// []byte) (crypto.PublicKey, error) — go-statuslist hands us the
			// raw (unverified) token; go-eudi-crypto's structural header-peek
			// (ParseJWSHeader/X5CFromHeader — pre-trust, never a trust decision
			// on its own) extracts x5c from IT, not a parameter.
			IssuerKeyResolver: func(_ context.Context, _ string, token []byte) (stdcrypto.PublicKey, error) {
				hdr, herr := crypto.ParseJWSHeader(token)
				if herr != nil {
					return nil, herr
				}
				certs, cerr := crypto.X5CFromHeader(hdr)
				if cerr != nil {
					return nil, cerr
				}
				chain := make([][]byte, len(certs))
				for i, c := range certs {
					chain[i] = c.Raw
				}
				// Status signer resolves against *_status
				// anchors first, then issuer provider fallback. Same
				// EAA use-case scoping applied as for the issuer.
				return resolveStatusSignerFor(pc, chain, cred.DoctypeOrVCT())
			},
			// Real Policy is {AllowFailOpen bool; MaxStale
			// time.Duration} — not FailClosed.
			Policy:             statuslist.Policy{AllowFailOpen: !pc.Policy.RevocationFailClosed(), MaxStale: 5 * time.Minute},
			CredentialValidity: credValidity,
		})
		cred.StatusResult, cred.StatusProvenance = status, string(prov.Outcome)
		switch {
		case prov.Outcome == statuslist.OutcomeSkippedShortLived:
			// The report-facing string is prov.Outcome
			// ("skipped-short-lived"), never string(statuslist.StatusSkippedShortLived)
			// (an int→string rune-conversion bug) nor the originally
			// pinned "status-skipped-short-lived".
			anySkipped = true
		case prov.Outcome == statuslist.OutcomeSkippedFailOpen:
			// Explicit fail-open. go-statuslist routes
			// EVERY inconclusive result through Checker.failClosed, which — when
			// AllowFailOpen is true — records the skip in Provenance
			// (OutcomeSkippedFailOpen, "skipped-fail-open") and returns a NIL
			// error. Keying the fail-open branch on err != nil (as this switch
			// originally did) is therefore dead: the skip fell through to
			// OutcomePass and the fail-closed posture was violated (a skip silently recorded
			// as a pass). Match the library's own provenance instead; the verbatim
			// "skipped-fail-open" string is already in cred.StatusProvenance
			// above, so the relaxation is VISIBLE in the report.
			anySkipped = true
		case err != nil:
			// Fail-closed: the library surfaces the cause ONLY when fail-open is
			// off (AllowFailOpen == !RevocationFailClosed()), so any error here is
			// an unresolvable status under a fail-closed policy ⇒ fail.
			return CheckResult{Outcome: OutcomeFail, Code: "err:revocation:unavailable",
				Detail: safeDetail(err), StatusListURI: ref.URI}, nil
		case status == statuslist.StatusRevoked, status == statuslist.StatusSuspended:
			// Decision: suspension maps to revoked with suspended detail.
			detail := "credential " + cred.Pres.QueryCredID + " revoked"
			if status == statuslist.StatusSuspended {
				detail = "credential " + cred.Pres.QueryCredID + " suspended=true"
			}
			return CheckResult{Outcome: OutcomeFail, Code: "err:revocation:revoked", Detail: detail}, nil
		case status == statuslist.StatusUnknown && pc.Policy.RevocationFailClosed():
			return CheckResult{Outcome: OutcomeFail, Code: "err:revocation:unavailable",
				Detail: "status unknown", StatusListURI: ref.URI}, nil
		}
	}
	if anySkipped {
		return CheckResult{Outcome: OutcomeSkipped, Code: "revocation-partially-skipped"}, nil
	}
	return CheckResult{Outcome: OutcomePass}, nil
}

// statusRefOf extracts the credential's Token Status List reference (Kind
// defaults to RefTokenStatusList). mdoc's Index is uint — narrowed
// to statuslist.StatusRef.Index (int).
func statusRefOf(cred *Credential) *statuslist.StatusRef {
	switch {
	case cred.SD != nil && cred.SD.Status != nil:
		return &statuslist.StatusRef{URI: cred.SD.Status.URI, Index: cred.SD.Status.Index}
	case cred.MD != nil && cred.MD.Status != nil:
		return &statuslist.StatusRef{URI: cred.MD.Status.URI, Index: int(cred.MD.Status.Index)}
	default:
		return nil
	}
}

// validityWindow returns the credential's remaining technical validity window
// span. sdjwt.VerifiedCredential has NO ValidityWindow sub-struct —
// NotBefore/Expiry are top-level fields.
func validityWindow(cred *Credential) time.Duration {
	switch {
	case cred.SD != nil:
		return cred.SD.Expiry.Sub(cred.SD.NotBefore)
	case cred.MD != nil:
		return cred.MD.ValidityInfo.ValidUntil.Sub(cred.MD.ValidityInfo.ValidFrom)
	default:
		return 0
	}
}
