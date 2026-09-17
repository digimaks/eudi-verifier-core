package pipeline

import (
	"context"
	"fmt"

	dcql "github.com/gmb-eudi/go-dcql"
)

type queryFulfilment struct{}

// QueryFulfilment is step 8. // [OID4VP §6]: the verified credentials must
// actually satisfy the DCQL query; over-disclosure fails closed (Decision:
// a candidate for an unknown query id makes the result
// unsatisfied). Matcher operates post-verification only — steps 3–6 are done.
func QueryFulfilment() Check { return queryFulfilment{} }

func (queryFulfilment) Name() string { return CheckQueryFulfilment }

func (queryFulfilment) Run(_ context.Context, pc *PipelineContext) (CheckResult, error) {
	cands := make([]dcql.Candidate, 0, len(pc.Credentials))
	for _, cred := range pc.Credentials {
		cands = append(cands, dcql.Candidate{
			QueryCredID:  cred.Pres.QueryCredID,
			Format:       cred.Pres.Format,
			DoctypeOrVCT: cred.DoctypeOrVCT(),
			Claims:       cred.Claims(),
			HolderBound:  cred.HolderBound,
			// KNOWN LIMITATION:
			// trust.ResolvedIssuer has NO AKIs/TrustedListURIs/SnapshotID
			// fields — the original design assumed cred.Issuer.AKIs/
			// .TrustedListURIs, which do not exist and would not compile.
			// Left zero-valued: a DCQL query's trusted_authorities constraint is
			// NOT enforced by this pipeline today. Confirmed against
			// go-dcql/authority.go's authorityMatches (called from match.go's
			// candidateSatisfies): a non-empty trusted_authorities constraint
			// against a zero-valued AuthorityRef deterministically returns
			// false — every `have` slice (AKIs/TrustedListURIs/FederationIDs) is
			// nil, so the inner value-membership loop never matches — which
			// match.go maps to UnmetAuthority. So a request that USES
			// trusted_authorities fails closed (query-unfulfilled), it is never
			// silently ignored; a request that omits it is unaffected
			// (authorityMatches short-circuits true on an empty constraint
			// list). Revisit if go-eudi-trust's ResolvedIssuer gains AKI/TL-URI
			// provenance, so trusted_authorities can actually be satisfied.
			IssuerAuthority: dcql.AuthorityRef{},
		})
	}
	res := pc.Session.Query.Match(cands)
	if !res.Satisfied {
		// Unmet carries PATHS only — safe for the report.
		detail := ""
		for _, u := range res.Unmet {
			detail += fmt.Sprintf("[%s %s %v]", u.CredentialID, u.Reason, u.Paths)
		}
		return CheckResult{Outcome: OutcomeFail, Code: "err:presentation:query-unfulfilled",
			Detail: detail}, nil
	}
	return CheckResult{Outcome: OutcomePass}, nil
}
