package verifiercore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"azugo.io/core/validation"
	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

// TestConfigurationSecretFileConvention asserts the opaque secrets POSTGRES_DSN
// and INTERNAL_API_TOKEN honor the platform's Vault-agent <NAME>_FILE
// secret-file convention (loadSecret → LoadRemoteSecret), so a Swarm/Vault
// secret file can carry them instead of a plaintext env var. LoadRemoteSecret
// trims surrounding whitespace, so a trailing newline in the mounted file is
// not baked into the value.
func TestConfigurationSecretFileConvention(t *testing.T) {
	dir := t.TempDir()
	dsnFile := filepath.Join(dir, "dsn")
	tokFile := filepath.Join(dir, "tok")
	qt.Assert(t, qt.IsNil(os.WriteFile(dsnFile, []byte("postgres://verifier_core_public:filepw@db/verifier\n"), 0o600)))
	qt.Assert(t, qt.IsNil(os.WriteFile(tokFile, []byte("  token-from-file\n"), 0o600)))

	t.Setenv("POSTGRES_DSN_FILE", dsnFile)
	t.Setenv("INTERNAL_API_TOKEN_FILE", tokFile)

	v := viper.New()
	NewConfiguration().Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), "postgres://verifier_core_public:filepw@db/verifier"))
	qt.Check(t, qt.Equals(v.GetString("internal_api_token"), "token-from-file"))
}

// TestConfigurationPlainEnvOverridesSecretFile asserts an explicit plain env
// var still wins over the _FILE default (loadSecret only registers a viper
// default, which env bindings outrank).
func TestConfigurationPlainEnvOverridesSecretFile(t *testing.T) {
	dir := t.TempDir()
	dsnFile := filepath.Join(dir, "dsn")
	qt.Assert(t, qt.IsNil(os.WriteFile(dsnFile, []byte("postgres://from-file@db/verifier"), 0o600)))

	t.Setenv("POSTGRES_DSN_FILE", dsnFile)
	t.Setenv("POSTGRES_DSN", "postgres://from-env@db/verifier")

	v := viper.New()
	NewConfiguration().Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), "postgres://from-env@db/verifier"))
}

// TestDCAPIRequestModeRejectsUnknownValue: the browser-request ceiling decides
// whether a wallet can authenticate this verifier at all, so a typo in it must
// stop the process rather than quietly resolve to one of the two postures.
// Startup validation is where that happens — nothing downstream re-checks it.
func TestDCAPIRequestModeRejectsUnknownValue(t *testing.T) {
	base := func(t *testing.T) *Configuration {
		t.Helper()
		c := NewConfiguration()
		c.PostgresDSN = "postgres://verifier_core_public:pw@db/verifier"
		c.ValkeyURL = "redis://valkey:6379"
		c.PublicBaseURL = "https://verifier.test"
		c.RequestSigningKeyFile = "/keys/req.pem"
		c.HandoffEncKeyFile = "/keys/handoff.pem"
		c.WebhookSigningKeyFile = "/keys/webhook.pem"
		c.WRPACChainFile = "/keys/wrpac-chain.pem"
		c.ClientDNSName = "verifier.test"
		c.UniversalLinkBase = "https://wallet.test/authorize"
		c.ServiceName = "eudi-verifier-core"
		c.SessionTTL = time.Minute
		c.ResponseCodeTTL = time.Minute
		c.HandoffTTL = time.Hour
		c.MaxResponseBodyBytes = 1 << 20
		c.IssuerValidityModel = "chain"
		return c
	}

	for _, mode := range []string{"signed", "unsigned", "both"} {
		t.Run("accepts "+mode, func(t *testing.T) {
			c := base(t)
			c.DCAPIRequestMode = mode
			qt.Check(t, qt.IsNil(c.Validate(validation.New())))
		})
	}

	// A near miss, a plural, an empty value and an invented third posture all
	// have to fail — "unsigned" being one character from "unsigne" is exactly
	// the kind of edit that would otherwise ship silently.
	for _, mode := range []string{"", "Signed", "unsigne", "none", "all", "signed,unsigned"} {
		t.Run("rejects "+mode, func(t *testing.T) {
			c := base(t)
			c.DCAPIRequestMode = mode
			qt.Check(t, qt.IsNotNil(c.Validate(validation.New())))
		})
	}
}

// TestDCAPIRequestModeDefaultsToSigned: an operator who sets nothing gets the
// mode that keeps the wallet able to authenticate us.
func TestDCAPIRequestModeDefaultsToSigned(t *testing.T) {
	v := viper.New()
	NewConfiguration().Bind("", v)
	qt.Check(t, qt.Equals(v.GetString("dcapi_request_mode"), "signed"))

	t.Setenv("DCAPI_REQUEST_MODE", "both")
	v2 := viper.New()
	NewConfiguration().Bind("", v2)
	qt.Check(t, qt.Equals(v2.GetString("dcapi_request_mode"), "both"))
}

// TestResponseEncryptionEnvOverride asserts the response-encryption support
// declaration is overridable from the environment. It is a DEPLOYMENT
// declaration — which content-encryption values we advertise as acceptable —
// so a container deployment must be able to widen or narrow it without a
// rebuild. The list case matters most: viper hands an env var over as a single
// string, and only the default decoder's comma-splitting hook turns it into the
// []string the field needs.
func TestResponseEncryptionEnvOverride(t *testing.T) {
	t.Setenv("RESPONSE_ENCRYPTION_CURVE", "P-384")
	t.Setenv("RESPONSE_ENCRYPTION_ALG", "ECDH-ES+A256KW")
	t.Setenv("RESPONSE_ENCRYPTION_ENCVALUES", "A128GCM,A256GCM")

	v := viper.New()
	c := NewConfiguration()
	c.Bind("", v)
	qt.Assert(t, qt.IsNil(v.Unmarshal(c)))

	qt.Check(t, qt.Equals(c.ResponseEncryption.Curve, "P-384"))
	qt.Check(t, qt.Equals(c.ResponseEncryption.Alg, "ECDH-ES+A256KW"))
	qt.Check(t, qt.DeepEquals(c.ResponseEncryption.EncValues, []string{"A128GCM", "A256GCM"}))
}

// TestResponseEncryptionDefaultsWithoutEnv asserts the shipped default survives
// when nothing overrides it — the env binding must not blank the declaration.
func TestResponseEncryptionDefaultsWithoutEnv(t *testing.T) {
	v := viper.New()
	c := NewConfiguration()
	c.Bind("", v)
	qt.Assert(t, qt.IsNil(v.Unmarshal(c)))

	qt.Check(t, qt.Equals(c.ResponseEncryption.Curve, "P-256"))
	qt.Check(t, qt.Equals(c.ResponseEncryption.Alg, "ECDH-ES"))
	qt.Check(t, qt.DeepEquals(c.ResponseEncryption.EncValues, []string{"A128GCM"}))
}

// The issuer-certificate validity model decides whether a credential signed by a
// since-rotated document signer verifies at all, so a typo must stop the service
// rather than resolve to a posture nobody chose — the same discipline the
// browser-request mode gets, for the same reason.
func TestIssuerValidityModelRejectsUnknownValue(t *testing.T) {
	base := func(t *testing.T) *Configuration {
		t.Helper()
		c := NewConfiguration()
		c.PostgresDSN = "postgres://verifier_core_public:pw@db/verifier"
		c.ValkeyURL = "redis://valkey:6379"
		c.PublicBaseURL = "https://verifier.test"
		c.RequestSigningKeyFile = "/keys/req.pem"
		c.HandoffEncKeyFile = "/keys/handoff.pem"
		c.WebhookSigningKeyFile = "/keys/webhook.pem"
		c.WRPACChainFile = "/keys/wrpac-chain.pem"
		c.ClientDNSName = "verifier.test"
		c.UniversalLinkBase = "https://wallet.test/authorize"
		c.ServiceName = "eudi-verifier-core"
		c.SessionTTL = time.Minute
		c.ResponseCodeTTL = time.Minute
		c.HandoffTTL = time.Hour
		c.MaxResponseBodyBytes = 1 << 20
		c.DCAPIRequestMode = "signed"
		return c
	}

	for _, model := range []string{"chain", "shell"} {
		t.Run("accepts "+model, func(t *testing.T) {
			c := base(t)
			c.IssuerValidityModel = model
			qt.Check(t, qt.IsNil(c.Validate(validation.New())))
		})
	}

	for _, model := range []string{"", "Chain", "chai", "signing-time", "now", "chain,shell"} {
		t.Run("rejects "+model, func(t *testing.T) {
			c := base(t)
			c.IssuerValidityModel = model
			qt.Check(t, qt.IsNotNil(c.Validate(validation.New())))
		})
	}
}

// The default is the conformant one: a deployment that sets nothing judges the
// issuer chain at the credential's signing time, which is the only value under
// which wallets keep working after their issuer rotates a signer.
func TestIssuerValidityModelDefaultsToChain(t *testing.T) {
	v := viper.New()
	NewConfiguration().Bind("", v)
	qt.Check(t, qt.Equals(v.GetString("issuer_validity_model"), "chain"))

	t.Setenv("ISSUER_VALIDITY_MODEL", "shell")
	v2 := viper.New()
	NewConfiguration().Bind("", v2)
	qt.Check(t, qt.Equals(v2.GetString("issuer_validity_model"), "shell"))
}
