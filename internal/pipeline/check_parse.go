package pipeline

import (
	"context"
	"fmt"

	dcql "github.com/gmb-eudi/go-dcql"
	mdoc "github.com/gmb-eudi/go-mdoc"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
)

type parseCheck struct{}

// Parse is step 2: structural parse of every presentation.
// // [ISO/IEC 18013-5 §8.3] (DeviceResponse CBOR) / SD-JWT combined format.
// Fail closed on the first malformed credential — nothing downstream may
// touch bytes that did not parse.
func Parse() Check { return parseCheck{} }

func (parseCheck) Name() string { return CheckParse }

func (parseCheck) Run(_ context.Context, pc *PipelineContext) (CheckResult, error) {
	for _, pres := range pc.Presentations {
		cred := &Credential{Pres: pres}
		switch pres.Format {
		case dcql.FormatSDJWT:
			peek, err := sdjwt.Peek(pres.Payload)
			if err != nil {
				return failParse(pres.QueryCredID, err), nil
			}
			cred.X5C = peek.X5C // []*x509.Certificate (Peek shape)
			cred.IAT = peek.IAT // claimed signing time, unverified (nil when absent)
		case dcql.FormatMdoc:
			// pres.Payload is ALREADY base64url-decoded by
			// oid4vp.ProcessResponse/ProcessDCAPIResponse — decoding it again
			// here is the fixed double-decode bug; DecodeDeviceResponse takes
			// the raw CBOR directly. (DocumentCount() does not exist on
			// *DeviceResponse — so it is never called here.)
			if _, err := mdoc.DecodeDeviceResponse(pres.Payload); err != nil {
				return failParse(pres.QueryCredID, err), nil
			}
			// mdoc x5chain is inside IssuerAuth — resolved via the
			// IssuerChainResolver callback in step 3.
		default:
			return failParse(pres.QueryCredID, fmt.Errorf("unsupported format %q", pres.Format)), nil
		}
		pc.Credentials = append(pc.Credentials, cred)
	}
	if len(pc.Credentials) == 0 {
		return CheckResult{Outcome: OutcomeFail, Code: "err:presentation:invalid-response",
			Detail: "empty vp_token"}, nil
	}
	return CheckResult{Outcome: OutcomePass}, nil
}

func failParse(queryCredID string, err error) CheckResult {
	return CheckResult{Outcome: OutcomeFail, Code: "err:credential:parse",
		Detail: "credential " + queryCredID + ": " + safeDetail(err)}
}
