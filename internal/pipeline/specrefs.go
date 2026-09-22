package pipeline

// Check names — the VerificationReport check enum (locked).
const (
	CheckResponseIntegrity  = "response_integrity"
	CheckParse              = "parse"
	CheckIssuerAuthenticity = "issuer_authenticity"
	CheckDataIntegrity      = "data_integrity"
	CheckRevocation         = "revocation"
	CheckDeviceBinding      = "device_binding"
	CheckUserBinding        = "user_binding"
	CheckQueryFulfilment    = "query_fulfilment"
	CheckCombinedChecks     = "combined_checks"
	CheckAssembleForward    = "assemble_forward"
)

// AllChecks in pipeline order.
var AllChecks = []string{
	CheckResponseIntegrity, CheckParse, CheckIssuerAuthenticity, CheckDataIntegrity,
	CheckRevocation, CheckDeviceBinding, CheckUserBinding, CheckQueryFulfilment,
	CheckCombinedChecks, CheckAssembleForward,
}

// SpecRefs is the SINGLE source of the client-visible specRef strings
// (they appear to clients; never inline spec strings
// in check code or reports anywhere else).
var SpecRefs = map[string]string{
	CheckResponseIntegrity:  "OID4VP §8.2",
	CheckParse:              "ISO/IEC 18013-5 §8.3 / IETF SD-JWT VC",
	CheckIssuerAuthenticity: "ARF §6.6.3.6",
	CheckDataIntegrity:      "ISO/IEC 18013-5 §9.1.2 / SD-JWT",
	CheckRevocation:         "ARF §6.6.3.7",
	CheckDeviceBinding:      "ARF §6.6.3.8",
	CheckUserBinding:        "ARF §6.6.3.9",
	CheckQueryFulfilment:    "OID4VP §6",
	CheckCombinedChecks:     "ARF Topic 18",
	CheckAssembleForward:    "ARF AS-RP-51-008/011/013",
}
