// Package verifiercore is the verifier's wallet-facing Azugo service: it
// serves signed Request Objects, accepts the wallet's presentation response,
// and runs the ten-step verification pipeline.
package verifiercore

import (
	"context"
	"fmt"
	"os"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-eudi-crypto/filekeys"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
	statuslist "github.com/gmb-eudi/go-statuslist"
	"github.com/gmb-lib/go-platform-kit/httpclient"
	"github.com/gmb-lib/go-platform-kit/platform"

	"github.com/dativa-lv/eudi-verifier-core/internal/anchors"
	"github.com/dativa-lv/eudi-verifier-core/internal/handoff"
	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
	"github.com/dativa-lv/eudi-verifier-core/internal/obs"
	"github.com/dativa-lv/eudi-verifier-core/internal/pipeline"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessiondb"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessions"
	"github.com/dativa-lv/eudi-verifier-core/internal/statuscache"
	"github.com/dativa-lv/eudi-verifier-core/internal/valkeystore"
	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"
	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
)

// Fixed key IDs: all code refers to keys by these; deployment maps files.
// KeyHandoffEnc/KeyWebhookSigning alias the handoffwire cross-service
// constants — they are shared with eudi-api-management, which
// imports handoffwire directly; KeyRequestSigning stays a local literal
// because it is not cross-service (only the Engine uses it).
const (
	KeyRequestSigning = "request-signing"         // JAR signing (Engine)
	KeyHandoffEnc     = handoffwire.KeyHandoffEnc // handoff payload JWE
	KeyWebhookSigning = handoffwire.KeyWebhookSigning
)

// App is the eudi-verifier-core application container: it embeds
// *azugo.App and holds every service-level dependency (config, cache, DB,
// keys). Later tasks append Sessions(), SessionDB(), Engine(), Pipeline(),
// Anchors(), Handoff() accessors.
type App struct {
	*azugo.App

	config    *Configuration
	valkey    redis.UniversalClient
	db        *pgxpool.Pool
	dbPing    func(context.Context) error // Postgres liveness probe for /readyz; a field so readyz is unit-testable without a real Postgres (init sets the real pgxpool ping)
	keys      crypto.KeyProvider
	sessions  *valkeystore.Store
	sessionDB sessiondb.MetadataStore

	engine        *oid4vp.Engine         // OID4VP protocol engine, built from config in init
	wrpac         *rpcert.WRPAC          // parsed + profile-validated WRPAC (TS 119 411-8)
	respondTokens sessions.RespondTokens // routing-token index (token → oid4vp.Session.ID)
	creator       *sessions.Creator      // in-process session-creation seam (lazy: see SessionCreator)

	walletProcessor any // routes.Processor for the response endpoint (minimal, then full pipeline)

	// Verification pipeline wiring: the format verifiers, the
	// revocation checker + ref recorder, the credential-type→anchor
	// classification, the ten-step engine, and the delivery sink.
	sdjwtVerifier *sdjwt.Verifier
	mdocVerifier  *mdoc.Verifier
	statusChecker *statuslist.Checker
	statusRefs    pipeline.StatusRefRecorder
	credTrust     pipeline.CredentialTrustMap
	pipeline      *pipeline.Engine
	resultSink    pipeline.ResultSink

	// Trust seam. anchorSource is the go-eudi-trust AnchorSource the pipeline
	// resolves chains against; statusFetcherOverride, when set, replaces the
	// prod kit-httpclient status-list fetcher. SeedTestTrust (testing.go) fills
	// both with the in-memory harness; production backfills the real Valkey-backed
	// AnchorSource + fetcher fed by trust-cache-worker.
	anchorSource          trust.AnchorSource
	statusFetcherOverride statuslist.Fetcher

	// Test-only trust seam kept for the routes-test fixture stability across
	// tasks (SeedTestTrust also records them here).
	testAnchors       []trust.Anchor
	testStatusFetcher statuslist.Fetcher

	// testMR is the in-process miniredis handle backing TestApp's Valkey client
	// (set by TestApp in testing.go; nil in production). It lets the
	// verified-deletion canary grep every Valkey key/value directly. Typed as
	// `any` (not *miniredis.Miniredis) so this production file carries no
	// import of the test-only miniredis/gopher-lua dependency tree — testing.go
	// is gated behind //go:build testhelpers specifically so
	// the prod binary's dependency closure excludes it; a concretely-typed
	// field here would have defeated that by importing miniredis
	// unconditionally regardless of the build tag. TestMiniredis() in
	// testing.go type-asserts back to *miniredis.Miniredis.
	testMR any
}

// New builds the eudi-verifier-core App: server.New wires Azugo, then init layers
// platform.Setup and the service's own dependencies on top.
func New(cmd *cobra.Command, version string) (*App, error) {
	RegisterReasons() // before platform.Setup

	config := NewConfiguration()
	a, err := server.New(cmd, server.Options{
		AppName:       "EUDI Verifier Core",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	instance := &App{App: a, config: config}
	if err := instance.init(); err != nil {
		return nil, err
	}
	return instance, nil
}

func (a *App) init() error {
	// FIRST after server.New — before any routes.
	// Redaction: verifier credential-PII list layered onto the kit fleet
	// default (RedactionPolicy in redaction.go) — installed here,
	// before any pipeline code exists to log a claim value.
	// PublicErrors is explicitly false: eudi-verifier-core's non-wallet endpoints
	// (health, JWKS) return the full internal envelope — only
	// eudi-api-management/eudi-api-registration are the public
	// boundary. Wallet endpoints render OID4VP error shapes instead
	// of this renderer entirely.
	if err := platform.Setup(a.App, platform.Options{
		Config:       a.config.BaseConfiguration,
		Redaction:    RedactionPolicy(),
		PublicErrors: false,
	}); err != nil {
		return err
	}

	// Browser-mediated presentations reach this service cross-origin: the page
	// that asked the wallet for credentials lives on the relying party's own
	// origin, while the wallet's answer is posted here. That POST carries a
	// JSON body, which is not one of the content types a browser may send
	// without asking first — so the preflight has to be told Content-Type is
	// allowed, or the answer never arrives and the flow stalls with nothing in
	// our logs. Which origins may ask at all stays deployment configuration
	// (CORS_ORIGINS) and is empty by default, so an unconfigured deployment
	// answers no cross-origin caller.
	a.RouterOptions().CORS.SetHeaders("Content-Type")

	opts, err := redis.ParseURL(a.config.ValkeyURL)
	if err != nil {
		return err
	}
	if a.config.ValkeyPassword != "" {
		opts.Password = a.config.ValkeyPassword // a mounted secret wins over one embedded in the URL
	}
	a.valkey = redis.NewClient(opts)
	// One deployment prefix for every Valkey key this service touches; the
	// worker that writes the trust keys must be configured with the same one.
	keyPrefix := keyspace.New(a.config.ValkeyKeyPrefix)
	a.sessions = valkeystore.New(a.valkey, a.config.SessionTTL, time.Now).
		WithResponseCodeTTL(a.config.ResponseCodeTTL).
		WithKeyPrefix(keyPrefix)

	a.db, err = pgxpool.New(a.BackgroundContext(), a.config.PostgresDSN)
	if err != nil {
		return err
	}
	a.dbPing = a.db.Ping // real Postgres probe; readyz unit tests swap it (SetDBPingForTest)
	a.sessionDB = sessiondb.NewPG(a.db)

	a.keys, err = filekeys.New(map[string]string{
		KeyRequestSigning: a.config.RequestSigningKeyFile,
		KeyHandoffEnc:     a.config.HandoffEncKeyFile,
		KeyWebhookSigning: a.config.WebhookSigningKeyFile,
	})
	if err != nil {
		return err
	}

	// WRPAC chain (leaf first): profile-validated once at startup
	// ([ETSI TS 119 411-8 §4.2.2]). Fail closed on a broken
	// profile — a verifier that cannot present a valid WRPAC must not start.
	chainPEM, err := os.ReadFile(a.config.WRPACChainFile) // #nosec G304 -- operator-configured path
	if err != nil {
		return fmt.Errorf("wrpac chain: %w", err)
	}
	certs, err := crypto.ParseCertChain(chainPEM)
	if err != nil {
		return fmt.Errorf("wrpac chain: %w", err)
	}
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	a.wrpac, err = rpcert.LoadWRPAC(chain)
	if err != nil {
		return fmt.Errorf("wrpac: %w", err)
	}
	// The real constructor is
	// oid4vp.New(ctx, oid4vp.Config{...}) — no NewEngine/EngineConfig, no
	// Store field (the Engine is stateless; the service Save/Load/ConsumeOnces
	// itself), no PublicBaseURL (split into RequestURIBase/UniversalLinkBase),
	// WRPACChain []*x509.Certificate + ClientDNSName instead of *rpcert.WRPAC,
	// and ResponseEncryption/VPFormats are REQUIRED (policy-validated in New;
	// ErrConfig otherwise). New ALSO requires the signing key
	// (a.keys/KeyRequestSigning) to equal the WRPACChain leaf's public key,
	// and ClientDNSName to be a SAN dNSName of that same leaf
	// (engine.go:113-130) — the deployment's key file and WRPAC chain file
	// MUST be a matched (leaf-cert, leaf-key) pair; the test PKI (testing.go)
	// supplies one for tests.
	// The actually-bound wallet-facing fetch
	// route is "/wallet/{sessionID}/request.jwt" (routes/wallet.go
	// bindWallet), not "{PublicBaseURL}/{sessionID}" — RequestURIBase alone
	// produced a request_uri a real wallet would 404 on. RequestURIFunc
	// (go-oid4vp v0.0.3+) lets this service own the exact URL shape; it uses
	// the SAME formula internal/sessions/creator.go computes for
	// Created.RequestURI (from the same a.config.PublicBaseURL), so the
	// invocation's embedded request_uri and Created.RequestURI are always
	// byte-identical (asserted by TestCreateMintsOneIDEverywhere).
	// RequestURIBase is left set too: harmless (RequestURIFunc takes
	// precedence in invocation()) and keeps New's config valid even if
	// RequestURIFunc were ever removed.
	a.engine, err = oid4vp.New(context.Background(), oid4vp.Config{
		Keys: a.keys, SigningKeyID: KeyRequestSigning,
		WRPACChain: certs, ClientDNSName: a.config.ClientDNSName,
		Policy: crypto.ECCG(), Clock: time.Now,
		RequestURIBase: a.config.PublicBaseURL,
		RequestURIFunc: func(sessionID string) string {
			return fmt.Sprintf("%s/wallet/%s/request.jwt", a.config.PublicBaseURL, sessionID)
		},
		UniversalLinkBase: a.config.UniversalLinkBase,
		SessionTTL:        a.config.SessionTTL, MaxResponseBody: a.config.MaxResponseBodyBytes,
		ResponseEncryption: a.config.ResponseEncryption, VPFormats: a.config.VPFormats,
	})
	if err != nil {
		return err
	}
	a.respondTokens = sessions.NewValkeyRespondTokens(a.valkey).WithKeyPrefix(keyPrefix)

	// Credential-type → trust-anchor classification, parsed once at
	// startup (empty config ⇒ DefaultCredentialTrust). Fail closed on a bad map.
	a.credTrust, err = pipeline.ParseCredentialTrust([]byte(a.config.CredentialTrustJSON))
	if err != nil {
		return fmt.Errorf("credential trust map: %w", err)
	}

	// Format verifiers and the revocation checker (crypto policy centralized in
	// go-eudi-crypto). All three are variadic-options constructors.
	a.sdjwtVerifier = sdjwt.NewVerifier(sdjwt.WithPolicy(crypto.ECCG()), sdjwt.WithClock(time.Now))
	a.mdocVerifier = mdoc.NewVerifier(mdoc.WithClock(time.Now))
	// NewChecker(fetcher, cache, opts ...Option) — the clock is
	// statuslist.WithClock(time.Now), not a third positional arg. The fetcher is
	// resolved lazily per call (statusFetcher), so the SeedTestTrust override —
	// installed after New() — is honored.
	a.statusChecker = statuslist.NewChecker(a.statusFetcher(), statuscache.NewCache(a.valkey, time.Now).WithKeyPrefix(keyPrefix), statuslist.WithClock(time.Now))
	a.statusRefs = statuscache.NewRefRecorder(a.valkey, time.Now).WithKeyPrefix(keyPrefix) // ZADD trust:statuslist:refs

	// The ten-step engine. WithRecorder
	// adds per-check outcome counters + spans and the full-pipeline
	// latency histogram; it does not alter verification behavior (see
	// pipeline.Engine.Run's doc comment).
	a.pipeline = pipeline.New(
		pipeline.ResponseIntegrity(), pipeline.Parse(), pipeline.IssuerAuthenticity(),
		pipeline.DataIntegrity(), pipeline.Revocation(), pipeline.DeviceBinding(),
		pipeline.UserBinding(), pipeline.QueryFulfilment(), pipeline.CombinedChecks(),
		pipeline.AssembleForward(),
	).WithRecorder(obs.NewRecorder())
	// Production result sink: the encrypted Valkey handoff queue that
	// eudi-api-management consumes. result_jwe carries the
	// ONLY copy of the presented attribute values, JWE-encrypted to the operator
	// handoff-enc key (crypto.EncryptJWE); the queue enforces the 24h TTL hard
	// cap. NopSink is no longer wired in the production path — it stays in
	// pipeline/finalize.go for unit tests only (SetResultSink still swaps it in).
	handoffPub, err := a.keys.Public(a.BackgroundContext(), KeyHandoffEnc)
	if err != nil {
		return fmt.Errorf("handoff key: %w", err)
	}
	a.resultSink = handoff.NewQueue(a.valkey, handoffPub, a.config.HandoffTTL, time.Now).WithKeyPrefix(keyPrefix)

	// Production AnchorSource: the trustcache.Reader fed by
	// trust-cache-worker, bridged to go-eudi-trust via anchors.Valkey.
	// Fail closed on a stale/expired cache. Tests overwrite this
	// with anchors.Static via SeedTestTrust AFTER New() returns — so production
	// never depends on the test fake, and the test seam always wins in tests.
	vk := anchors.NewValkey(anchors.RedisGetter{RDB: a.valkey, Prefix: keyPrefix}, a.config.AnchorGrace, time.Now)
	a.anchorSource = vk

	// Per-type seconds-until-expiry gauge (negative = stale), read
	// from the same trust-cache freshness data /readyz uses (AnchorFreshness).
	// Registered against the just-built anchors.Valkey, BEFORE SeedTestTrust
	// (tests) can swap a.anchorSource to the static test source — see
	// obs.RegisterAnchorStalenessGauges's doc comment for why that ordering is
	// safe even across many TestApp() calls in one test binary.
	obs.RegisterAnchorStalenessGauges(anchors.TypeKeyList(), func(typ string) float64 {
		fr := vk.Freshness(a.BackgroundContext())
		f, ok := fr[typ]
		if !ok {
			return -1
		}
		return time.Until(f.ValidUntil).Seconds()
	})

	// State the browser-request ceiling once, at startup. Whether a wallet can
	// authenticate this verifier through its certificate chain is not something
	// an operator should have to infer from captured traffic, and under the
	// fixed modes nothing else records it: only "both" leaves the decision in a
	// client's own stored policy, where it can be read back later.
	a.Log().Info("browser presentation requests: " + effectiveDCAPIModeNote(a.config.DCAPIRequestMode))
	// And the issuer-certificate validity model, for the same reason: it decides
	// whether a credential signed by a since-rotated document signer verifies,
	// and an operator reading a rejection needs to know which posture produced
	// it without reading the configuration back out of the container.
	a.Log().Info("issuer certificate validity: " + effectiveIssuerValidityNote(a.config.IssuerValidityModel))
	return nil
}

// effectiveDCAPIModeNote renders the startup notice for the browser-request
// ceiling — a sentence an operator can act on rather than a bare enum value.
func effectiveDCAPIModeNote(mode string) string {
	switch mode {
	case sessions.DCAPIModeUnsigned:
		return "UNSIGNED for every client (the wallet cannot authenticate this verifier; the calling web origin is the only identity it gets)"
	case sessions.DCAPIModeBoth:
		return "signed by default, unsigned where a client is registered for it"
	default:
		return "signed for every client (a client registered as unsigned is issued signed requests anyway)"
	}
}

// effectiveIssuerValidityNote renders the startup notice for the issuer-
// certificate validity model — the sentence an operator can act on, with the
// standard's own name for the model kept in it so it can be looked up.
func effectiveIssuerValidityNote(model string) string {
	if pipeline.IssuerValidityModel(model) == pipeline.ValidityAtCurrentTime {
		return "checked at the current time (shell model) — a credential signed before its issuer's last certificate rotation is refused"
	}
	return "checked at the credential's signing time (chain model) — a signer certificate that has since expired is honoured for credentials it signed while valid"
}

// IssuerValidityModel is the deployment's issuer-certificate validity model, as
// the pipeline consumes it. Validated at startup, so it is one of the two known
// values by the time anything reads it.
func (a *App) IssuerValidityModel() pipeline.IssuerValidityModel {
	return pipeline.IssuerValidityModel(a.config.IssuerValidityModel)
}

// statusFetch is the App's statuslist.Fetcher. It prefers the SeedTestTrust
// override (in-memory harness); in prod it fetches over the kit httpclient
// (correlation-propagating) using the *azugo.Context that flows
// down through the pipeline as the plain context.Context. The checker's cache
// is the Valkey-backed statuscache wired alongside it in init. A non-azugo context
// (never the case on the wallet response path) fails closed.
type statusFetch struct{ app *App }

func (f statusFetch) Get(ctx context.Context, rawurl string) ([]byte, error) {
	if f.app.statusFetcherOverride != nil {
		return f.app.statusFetcherOverride.Get(ctx, rawurl)
	}
	azCtx, ok := ctx.(*azugo.Context)
	if !ok {
		return nil, fmt.Errorf("statuscache: prod status-list fetch requires an azugo request context")
	}
	// Empty base + absolute URL ⇒ the client uses rawurl verbatim (azugo/core
	// http joins only relative paths). CorrelationOptions propagates the id.
	return httpclient.Outbound(azCtx, "").Get(rawurl, httpclient.CorrelationOptions(azCtx)...)
}

// statusFetcher returns the App's lazily-dispatching statuslist.Fetcher (see
// statusFetch): the SeedTestTrust override when present, else the kit
// httpclient. Deferring the override lookup to call time is what lets
// SeedTestTrust install it after the checker is constructed in init.
func (a *App) statusFetcher() statuslist.Fetcher { return statusFetch{app: a} }

// Config returns the loaded service configuration.
func (a *App) Config() *Configuration { return a.config }

// Valkey returns the shared Valkey/Redis client (sessions, caches, queues).
func (a *App) Valkey() redis.UniversalClient { return a.valkey }

// DB returns the Postgres connection pool (session metadata).
func (a *App) DB() *pgxpool.Pool { return a.db }

// Keys returns the operator key provider (request signing, handoff
// encryption, webhook signing — see the Key* constants above).
func (a *App) Keys() crypto.KeyProvider { return a.keys }

// Sessions returns the Valkey-backed oid4vp.SessionStore, which
// also carries the request_uri single-use marker and the response_code
// store used by the wallet-facing routes and eudi-api-management.
func (a *App) Sessions() *valkeystore.Store { return a.sessions }

// SessionDB returns the Postgres session-metadata store (session-schema
// SECURITY DEFINER procedures via the JSONB envelope). Services
// call procedures only — never tables directly.
func (a *App) SessionDB() sessiondb.MetadataStore { return a.sessionDB }

// SetSessionDB swaps the session-metadata store. Test-only seam (testing.go):
// TestApp installs sessiondb.NewFake() so unit tests never dial Postgres. It
// also resets the lazily-built creator so a later SessionCreator() call picks
// up the swapped store.
func (a *App) SetSessionDB(s sessiondb.MetadataStore) {
	a.sessionDB = s
	a.creator = nil
}

// Engine returns the OID4VP protocol engine. It is stateless between
// calls: all per-verification state lives in the persisted oid4vp.Session.
func (a *App) Engine() *oid4vp.Engine { return a.engine }

// WRPAC returns the parsed, profile-validated WRPAC (TS 119 411-8). Its chain
// is what the engine embeds in every signed request object's x5c header.
func (a *App) WRPAC() *rpcert.WRPAC { return a.wrpac }

// RespondTokens returns the routing-token index (opaque response-route
// token → real oid4vp.Session.ID). Consumed by the response handler.
func (a *App) RespondTokens() sessions.RespondTokens { return a.respondTokens }

// SessionCreator returns the in-process session-creation seam. It is built
// lazily so it binds the current session-metadata store (TestApp swaps in the
// fake via SetSessionDB before the first call).
func (a *App) SessionCreator() *sessions.Creator {
	if a.creator == nil {
		a.creator = sessions.NewCreator(a.engine, a.sessions, a.sessionDB, a.respondTokens, a.config.PublicBaseURL, a.config.SessionTTL, time.Now).
			WithDCAPIMode(a.config.DCAPIRequestMode)
	}
	return a.creator
}

// WalletProcessor returns the response-endpoint processor as an opaque value
// (routes.Processor). It is stored untyped to avoid an app→routes import
// cycle; routes.Init installs the minimal processor when it is nil, and
// the full pipeline replaces it via SetWalletProcessor.
func (a *App) WalletProcessor() any { return a.walletProcessor }

// SetWalletProcessor installs the response-endpoint processor (see
// WalletProcessor).
func (a *App) SetWalletProcessor(p any) { a.walletProcessor = p }

// SDJWTVerifier returns the SD-JWT VC verifier (ECCG policy; step 3).
func (a *App) SDJWTVerifier() *sdjwt.Verifier { return a.sdjwtVerifier }

// MDocVerifier returns the mdoc verifier (step 3).
func (a *App) MDocVerifier() *mdoc.Verifier { return a.mdocVerifier }

// StatusChecker returns the revocation checker (Token Status List, step 5).
func (a *App) StatusChecker() *statuslist.Checker { return a.statusChecker }

// StatusRefs returns the status-ref popularity recorder (ZADDs
// trust:statuslist:refs for trust-cache-worker prefetch).
func (a *App) StatusRefs() pipeline.StatusRefRecorder { return a.statusRefs }

// CredTrust returns the credential-type → trust-anchor classification,
// parsed once at startup from Configuration.CredentialTrustJSON.
func (a *App) CredTrust() pipeline.CredentialTrustMap { return a.credTrust }

// Anchors returns the trust AnchorSource the pipeline resolves chains against.
// init() installs the production trustcache-backed anchors.Valkey; SeedTestTrust
// (tests) overwrites it with anchors.Static.
func (a *App) Anchors() trust.AnchorSource { return a.anchorSource }

// PingDB probes Postgres liveness for /readyz. It dispatches through the dbPing
// field so readyz can be unit-tested without a reachable Postgres (init sets the
// real pgxpool ping; SetDBPingForTest swaps a stub).
func (a *App) PingDB(ctx context.Context) error { return a.dbPing(ctx) }

// AnchorFreshness reports per-type trust-cache freshness for /readyz. ok is
// false unless the AnchorSource is the production anchors.Valkey (the Static
// test source has no freshness signal), so readyz reflects only real cache
// staleness.
func (a *App) AnchorFreshness(ctx context.Context) (map[string]anchors.TypeFreshness, bool) {
	v, ok := a.anchorSource.(*anchors.Valkey)
	if !ok {
		return nil, false
	}
	return v.Freshness(ctx), true
}

// AnchorSnapshotHealth surfaces the worker's snapshot telemetry (LOTL sequence,
// pending bootstrap) for /readyz. ok is false unless the AnchorSource is the
// production anchors.Valkey. A present source with an absent/unreadable snapshot
// returns (nil, true): the caller treats a nil snapshot as degraded (fail closed).
func (a *App) AnchorSnapshotHealth(ctx context.Context) (*trustcache.SnapshotHealth, bool) {
	v, ok := a.anchorSource.(*anchors.Valkey)
	if !ok {
		return nil, false
	}
	sh, err := v.SnapshotHealth(ctx)
	if err != nil {
		return nil, true
	}
	return sh, true
}

// Pipeline returns the ten-step verification engine.
func (a *App) Pipeline() *pipeline.Engine { return a.pipeline }

// ResultSink returns the delivery sink for verified results (step 10). In
// production this is the encrypted Valkey handoff queue (handoff.NewQueue)
// wired in init; tests may swap it via SetResultSink.
func (a *App) ResultSink() pipeline.ResultSink { return a.resultSink }

// SetResultSink installs the result delivery sink (test seam: unit tests use
// pipeline.NopSink() where the real handoff queue's Valkey writes are not under
// test). Production wiring never calls this — init installs handoff.NewQueue.
func (a *App) SetResultSink(s pipeline.ResultSink) { a.resultSink = s }

// TestAnchors returns the trust anchors installed by SeedTestTrust (test-only
// seam consumed by the unit-test pipeline path).
func (a *App) TestAnchors() []trust.Anchor { return a.testAnchors }

// TestStatusFetcher returns the status-list fetcher installed by SeedTestTrust
// (test-only seam).
func (a *App) TestStatusFetcher() statuslist.Fetcher { return a.testStatusFetcher }
