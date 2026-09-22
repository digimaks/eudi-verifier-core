package verifiercore

import (
	"time"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"

	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is eudi-verifier-core's service configuration: it embeds the kit's
// shared base (service identity, telemetry, broker) and adds this service's
// own DB/cache/key/pipeline settings.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	PostgresDSN string `mapstructure:"postgres_dsn" validate:"required"`

	// ValkeyURL is the shared Valkey/Redis as a redis:// or rediss:// URL
	// (user, database index and TLS options ride in the URL).
	ValkeyURL string `mapstructure:"valkey_url" validate:"required"`
	// ValkeyPassword, when set, overrides the password in ValkeyURL. Also
	// readable through the VALKEY_PASSWORD_FILE indirection so a platform can
	// mount it. Secret — must never appear in logs, events, or error messages.
	ValkeyPassword string `mapstructure:"valkey_password"`
	// ValkeyKeyPrefix is prepended (as "<prefix>:") to every Valkey key. Set it
	// when the instance confines this user to a key pattern; every service
	// sharing the cache must carry the same value. Empty = no prefix.
	ValkeyKeyPrefix string `mapstructure:"valkey_key_prefix"`

	// PublicBaseURL is the externally reachable base of THIS service —
	// request_uri/response_uri are minted under it ([OID4VP §5]).
	PublicBaseURL string `mapstructure:"public_base_url" validate:"required,url"`

	// Key material (go-eudi-crypto filekeys provider; keyID → PEM path).
	RequestSigningKeyFile string `mapstructure:"request_signing_key_file" validate:"required"`
	HandoffEncKeyFile     string `mapstructure:"handoff_enc_key_file" validate:"required"`
	WebhookSigningKeyFile string `mapstructure:"webhook_signing_key_file" validate:"required"`
	WRPACChainFile        string `mapstructure:"wrpac_chain_file" validate:"required"`

	// Additional oid4vp.Config fields. ClientDNSName MUST be a SAN dNSName of the
	// WRPACChainFile leaf, and RequestSigningKeyFile's key MUST equal that
	// same leaf's public key (oid4vp.New fails closed otherwise). Deployment
	// declares its own ECCG-allowed curve/algorithm support here —
	// oid4vp.New policy-validates ResponseEncryption/VPFormats against
	// crypto.ECCG() at construction (the
	// allow-list check itself still lives only in go-eudi-crypto).
	ClientDNSName      string                    `mapstructure:"client_dns_name" validate:"required,fqdn"`
	UniversalLinkBase  string                    `mapstructure:"universal_link_base" validate:"required,url"`
	ResponseEncryption oid4vp.ResponseEncryption `mapstructure:"response_encryption"`
	VPFormats          oid4vp.VPFormats          `mapstructure:"vp_formats"`

	SessionTTL           time.Duration `mapstructure:"session_ttl" validate:"required,gt=0"`
	ResponseCodeTTL      time.Duration `mapstructure:"response_code_ttl" validate:"required,gt=0"`
	HandoffTTL           time.Duration `mapstructure:"handoff_ttl" validate:"required,gt=0,lte=24h"` // hard cap
	MaxResponseBodyBytes int           `mapstructure:"max_response_body_bytes" validate:"required,gt=0"`
	AnchorGrace          time.Duration `mapstructure:"anchor_grace" validate:"gte=0"` // extra tolerance on trust:anchors valid_until for /readyz only (never for verification)

	// CredentialTrustJSON (optional) is JSON that extends/overrides the
	// built-in credential-type → trust-anchor classification (pipeline.CredentialTrustMap).
	// Empty ⇒ pipeline.DefaultCredentialTrust (PID → pid_provider; else qeaa/pub_eaa/eaa).
	// app.go parses it ONCE at startup via pipeline.ParseCredentialTrust and exposes
	// App.CredTrust() pipeline.CredentialTrustMap; a parse error fails startup (fail closed).
	CredentialTrustJSON string `mapstructure:"credential_trust_json"`

	// DCAPIRequestMode is the deployment-wide ceiling on how browser-based
	// presentation requests are built: "signed", "unsigned", or "both".
	//
	// A signed request lets the wallet authenticate this verifier through its
	// certificate chain and registration data, on top of the web origin the
	// browser asserts; an unsigned one carries neither, leaving the origin as
	// the only identity the wallet gets ([OID4VP §A.2] / [OID4VP §A.3.2]). Both are
	// permitted — [HAIP §5.2] requires a verifier to support at least one — and
	// which of them is appropriate is a property of the deployment, not of this
	// code: where relying-party registration is the basis of trust, unsigned
	// discards the whole of it.
	//
	// "signed" and "unsigned" fix the mode for every client. "both" is the only
	// value that lets a client choose, through its own stored policy; a client
	// that has not chosen still gets signed. So this is a ceiling, never an
	// instruction: a client recorded as unsigned in a deployment set to
	// "signed" is issued signed requests anyway, and no per-client setting can
	// widen what the deployment allows.
	//
	// Defaults to "signed" — the mode that keeps the wallet's ability to
	// authenticate us — and an unrecognised value stops the process rather than
	// falling back to one (a typo must not silently pick a security posture).
	DCAPIRequestMode string `mapstructure:"dcapi_request_mode" validate:"required,oneof=signed unsigned both"`

	// IssuerValidityModel decides WHEN the issuer's certificate chain has to be
	// valid when a credential is verified.
	//
	// A wallet can present a credential that was signed while its issuer's
	// signing certificate was valid, but that certificate has since expired.
	// Issuers rotate signing certificates while the credentials they signed stay
	// in wallets far longer, so this decides whether such a credential is
	// accepted:
	//
	//   chain (default) — the chain must have been valid on the day the
	//                     credential was signed. What ISO/IEC 18013-5 requires
	//                     for the signer's own certificate, and the only value
	//                     under which normal wallets keep working after a
	//                     rotation.
	//   shell           — the chain must be valid right now. Stricter: every
	//                     credential signed before the issuer's last rotation is
	//                     refused. A legitimate risk appetite for a relying
	//                     party that will not honour an expired certificate.
	//
	// Enforced in both, and not configurable: the credential's own validity
	// window against the current time, and that the signing date falls inside
	// the signer certificate's own window (so a certificate already expired when
	// it signed is always refused).
	//
	// The two names are the validity models of [ETSI EN 319 102-1 §5.2.6.4],
	// which also requires the model be stated as an explicit validation
	// constraint rather than left implicit. An unrecognised value stops the
	// process instead of falling back to one.
	IssuerValidityModel string `mapstructure:"issuer_validity_model" validate:"required,oneof=chain shell"`

	// InternalAPIToken guards the /internal/v1 session API (create
	// transport). Empty (the default) = the internal surface is NOT registered
	// at all — fail closed. Cluster-internal secret; prefer the Vault-agent
	// INTERNAL_API_TOKEN_FILE form (an explicit INTERNAL_API_TOKEN still wins).
	InternalAPIToken string `mapstructure:"internal_api_token"`
}

// NewConfiguration returns a Configuration with the embedded kit base
// configuration initialized.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// Bind registers defaults and environment-variable bindings with viper;
// it must call the embedded BaseConfiguration.Bind first.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)

	v.SetDefault("session_ttl", 5*time.Minute)
	v.SetDefault("response_code_ttl", 5*time.Minute)
	v.SetDefault("handoff_ttl", 6*time.Hour)
	v.SetDefault("max_response_body_bytes", 1<<20) // 1 MiB: JWE of a multi-credential vp_token fits comfortably
	v.SetDefault("anchor_grace", 0)
	v.SetDefault("dcapi_request_mode", "signed")   // the mode that keeps the wallet able to authenticate us
	v.SetDefault("issuer_validity_model", "chain") // judge the issuer chain at the credential's signing time

	// ResponseEncryption/VPFormats are deployment algorithm/curve support
	// declarations. They default to the HAIP 1.0 / ECCG v2.0
	// baseline (P-256, ECDH-ES, A128GCM; ES256 JWS; COSE ES256=-7) so a
	// deployment is functional out of the box. This does NOT weaken
	// fail-closed behavior: oid4vp.New still policy-validates every value against
	// crypto.ECCG() at construction — the allow-list check lives only in
	// go-eudi-crypto, and any value outside it is still rejected (ErrConfig).
	// Operators override per deployment; the map keys are the lowercased
	// oid4vp struct field names (the oid4vp types carry no mapstructure tags).
	v.SetDefault("response_encryption", map[string]any{
		"curve":     "P-256",
		"alg":       "ECDH-ES",
		"encvalues": []string{"A128GCM"},
	})
	v.SetDefault("vp_formats", map[string]any{
		"sdjwtalgvalues":          []string{"ES256"},
		"kbjwtalgvalues":          []string{"ES256"},
		"mdocissuerauthalgvalues": []int64{-7},
		"mdocdeviceauthalgvalues": []int64{-7},
	})

	// Secrets: prefer the Vault-agent <NAME>_FILE convention (loadSecret sets a
	// viper default from the file's content); an explicit plain env var still
	// overrides it. POSTGRES_DSN carries the DB password; INTERNAL_API_TOKEN is
	// the shared cluster-internal secret. The *_KEY_FILE vars below are PEM
	// PATHS, not this convention, and are deliberately left as plain binds.
	loadSecret(v, "postgres_dsn", "POSTGRES_DSN")
	loadSecret(v, "internal_api_token", "INTERNAL_API_TOKEN")
	loadSecret(v, "valkey_password", "VALKEY_PASSWORD")

	_ = v.BindEnv("postgres_dsn", "POSTGRES_DSN")
	_ = v.BindEnv("valkey_url", "VALKEY_URL")
	_ = v.BindEnv("valkey_password", "VALKEY_PASSWORD")
	_ = v.BindEnv("valkey_key_prefix", "VALKEY_KEY_PREFIX")
	_ = v.BindEnv("public_base_url", "PUBLIC_BASE_URL")
	_ = v.BindEnv("request_signing_key_file", "REQUEST_SIGNING_KEY_FILE")
	_ = v.BindEnv("handoff_enc_key_file", "HANDOFF_ENC_KEY_FILE")
	_ = v.BindEnv("webhook_signing_key_file", "WEBHOOK_SIGNING_KEY_FILE")
	_ = v.BindEnv("wrpac_chain_file", "WRPAC_CHAIN_FILE")
	_ = v.BindEnv("client_dns_name", "CLIENT_DNS_NAME")
	_ = v.BindEnv("universal_link_base", "UNIVERSAL_LINK_BASE")
	// ResponseEncryption is a deployment support declaration — which curve,
	// key-agreement algorithm and content-encryption values we advertise as
	// acceptable — so a container deployment must be able to change it without a
	// rebuild. Viper's env binding does not reach nested struct leaves, so each
	// leaf is bound individually; the key names are the lowercased oid4vp field
	// names, since those types carry no mapstructure tags. ENCVALUES takes a
	// comma-separated list (viper's default decoder splits it into the []string
	// the field needs). Defaults stay in SetDefault above, and oid4vp.New still
	// policy-validates whatever arrives against crypto.ECCG(), so an override
	// cannot introduce a value outside the allow-list — it fails closed at
	// construction instead.
	_ = v.BindEnv("response_encryption.curve", "RESPONSE_ENCRYPTION_CURVE")
	_ = v.BindEnv("response_encryption.alg", "RESPONSE_ENCRYPTION_ALG")
	_ = v.BindEnv("response_encryption.encvalues", "RESPONSE_ENCRYPTION_ENCVALUES")
	// VPFormats stays config-file-only for now — same nested-leaf limitation,
	// and its mdoc leaves are COSE integer lists, which need their own decode
	// story before they can ride an env var.
	_ = v.BindEnv("session_ttl", "SESSION_TTL")
	_ = v.BindEnv("response_code_ttl", "RESPONSE_CODE_TTL")
	_ = v.BindEnv("handoff_ttl", "HANDOFF_TTL")
	_ = v.BindEnv("max_response_body_bytes", "MAX_RESPONSE_BODY_BYTES")
	_ = v.BindEnv("anchor_grace", "ANCHOR_GRACE")
	// Scalar, so it binds from the environment — a container deployment has no
	// other way to set it. The oneof tag rejects anything but the three known
	// values at startup.
	_ = v.BindEnv("dcapi_request_mode", "DCAPI_REQUEST_MODE")
	// Same reasoning: scalar, env-bindable, and the oneof tag rejects a typo at
	// startup rather than resolving it to a trust posture nobody chose.
	_ = v.BindEnv("issuer_validity_model", "ISSUER_VALIDITY_MODEL")
	// Credential-type → trust-anchor override: scalar JSON string, so it
	// is env-bindable (overridable at deploy
	// time — required in an env-var-only container deployment).
	_ = v.BindEnv("credential_trust_json", "CREDENTIAL_TRUST_JSON")
	// No validate:"required" and no SetDefault: empty is the fail-closed
	// default (the internal API surface is not registered at all — see
	// routes/router.go Init and InternalAPIToken's doc comment).
	_ = v.BindEnv("internal_api_token", "INTERNAL_API_TOKEN")
}

// Validate validates the embedded base configuration, then this service's own
// fields.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	return valid.Struct(c)
}

// loadSecret resolves a secret from the secret store (Vault agent ->
// <NAME>_FILE) and registers it as a viper default, so an explicit plain env
// var still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}
