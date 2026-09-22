package pipeline

import "time"

// IssuerValidityModel decides WHEN the issuer's certificate chain has to be
// valid. It is deployment-wide configuration, not a per-client policy: it
// expresses what this relying party will honour, and a client cannot widen it.
//
// The question it answers: a wallet presents a credential that was signed while
// its issuer's signing certificate was valid, but that certificate has since
// expired. Issuers rotate signing certificates while the credentials they signed
// stay in wallets far longer, so without this choice every credential fails
// weeks after issuance.
//
// The two names are the validity models of [ETSI EN 319 102-1 §5.2.6.4], kept so
// the setting maps to the clause an auditor will look up. They are borrowed
// vocabulary: that document governs signature validation, where a signature
// outlives its certificate only on the strength of a time-stamp, and a
// credential carries none — so what makes the signing-time model correct here is
// [ISO/IEC 18013-5 §9.3.1] step 5 for the signer's own certificate, and this
// relying party's stated policy for the rest of the path.
type IssuerValidityModel string

const (
	// ValidityAtSigningTime judges the certificate path at the credential's own
	// signing time. Required by [ISO/IEC 18013-5 §9.3.1] step 5 for the signer
	// certificate, and the only value under which a wallet still verifies after
	// its issuer rotates a document signer.
	ValidityAtSigningTime IssuerValidityModel = "chain"
	// ValidityAtCurrentTime judges the certificate path at the current time.
	// Stricter: it refuses every credential signed before the issuer's last
	// rotation. A legitimate risk appetite for a relying party that will not
	// honour a certificate past its expiry.
	ValidityAtCurrentTime IssuerValidityModel = "shell"
)

// PathValidationTime returns the instant to validate the issuer certificate path
// at for a credential that claims to have been signed at signed.
//
// A zero signed falls back to now, and that is deliberate rather than
// defensive: an SD-JWT VC need not carry a signing time at all (iat is OPTIONAL
// in [IETF SD-JWT VC §2.2.2.3]), and a validity window cannot be relaxed using a
// time we do not have. The fallback is therefore the stricter of the two models,
// never the looser one.
func (m IssuerValidityModel) PathValidationTime(signed, now time.Time) time.Time {
	if m == ValidityAtSigningTime && !signed.IsZero() {
		return signed
	}
	return now
}

// SigningTimeUsed reports whether PathValidationTime would use the credential's
// own signing time, so the verification report can record which instant the
// decision rested on instead of leaving it to be inferred.
func (m IssuerValidityModel) SigningTimeUsed(signed time.Time) bool {
	return m == ValidityAtSigningTime && !signed.IsZero()
}
