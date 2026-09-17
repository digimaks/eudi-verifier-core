//go:build testhelpers

package verifiercore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	trust "github.com/gmb-eudi/go-eudi-trust"
	statuslist "github.com/gmb-eudi/go-statuslist"

	"github.com/dativa-lv/eudi-verifier-core/internal/anchors"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessiondb"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
)

// WriteTestKey generates a P-256 key and writes it as PKCS#8 PEM; returns path.
func WriteTestKey(tb testing.TB, dir, name string) string {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(tb, qt.IsNil(err))
	return writeKeyPEM(tb, dir, name, k)
}

func writeKeyPEM(tb testing.TB, dir, name string, k *ecdsa.PrivateKey) string {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	qt.Assert(tb, qt.IsNil(err))
	p := filepath.Join(dir, name)
	qt.Assert(tb, qt.IsNil(os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)))
	return p
}

// writeTestWRPAC builds a WRPAC-profile-compliant chain for tests and writes
// its two coupled artifacts to dir: the chain PEM (leaf first, then the
// Access-CA root) and the leaf's private key (PKCS#8 PEM). The two are a
// matched (leaf-cert, leaf-key) pair — oid4vp.New requires the request-signing
// key to EQUAL the WRPAC leaf public key, and dnsName to be a SAN dNSName of
// that same leaf (engine.go). The leaf satisfies rpcert.LoadWRPAC's
// TS 119 411-8 profile checks:
//   - an eudiwrp certificatePolicies OID (QCP-l-eudiwrp, [ETSI TS 119 411-8 §5.3])  → hasEudiwrpPolicy
//   - a contact SAN (a URI GeneralName)                         → hasContactSAN
//   - keyUsage digitalSignature                                 → ErrKeyUsage gate
//   - no EKU (absent is allowed)                                → checkEKU
//
// This is scoped to eudi-verifier-core's own test setup: it models the VERIFIER
// (RP) side of the ecosystem, unlike internal/testwallet.PKI which models the
// wallet/issuer side and carries no WRPAC/Access-CA material.
func writeTestWRPAC(tb testing.TB, dir, dnsName string) (keyPath, chainPath string) {
	tb.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(tb, qt.IsNil(err))
	caTmpl := &x509.Certificate{
		SerialNumber:          testSerial(tb),
		Subject:               pkix.Name{CommonName: "EUDI Test Access-CA", Country: []string{"UT"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	qt.Assert(tb, qt.IsNil(err))
	caCert, err := x509.ParseCertificate(caDER)
	qt.Assert(tb, qt.IsNil(err))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(tb, qt.IsNil(err))
	contact, err := url.Parse("https://" + dnsName + "/support") // GEN-6.6.1-07 contact SAN (URI)
	qt.Assert(tb, qt.IsNil(err))
	leafTmpl := &x509.Certificate{
		SerialNumber: testSerial(tb),
		Subject:      pkix.Name{CommonName: "EUDI Test RP", Country: []string{"UT"}, Organization: []string{"EUDI Test RP GmbH"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature, // the WRPAC signs request objects
		DNSNames:     []string{dnsName},             // [OID4VP §5.9.3] x509_san_dns
		URIs:         []*url.URL{contact},           // TS 119 411-8 GEN-6.6.1-07 contact SAN
		Policies: []x509.OID{
			testOID(tb, 0, 4, 0, 194118, 1, 4), // QCP-l-eudiwrp ([ETSI TS 119 411-8 §5.3])
			testOID(tb, 0, 4, 0, 19475, 1, 1),  // Service_Provider entitlement (TS 119 475 A.2.1)
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	qt.Assert(tb, qt.IsNil(err))
	leafCert, err := x509.ParseCertificate(leafDER)
	qt.Assert(tb, qt.IsNil(err))

	chainPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...,
	)
	chainPath = filepath.Join(dir, "wrpac-chain.pem")
	qt.Assert(tb, qt.IsNil(os.WriteFile(chainPath, chainPEM, 0o600)))

	keyPath = writeKeyPEM(tb, dir, "wrpac-leaf.pem", leafKey) // matches the leaf public key
	return keyPath, chainPath
}

func testSerial(tb testing.TB) *big.Int {
	tb.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	qt.Assert(tb, qt.IsNil(err))
	return n.Add(n, big.NewInt(1)) // strictly positive
}

func testOID(tb testing.TB, ints ...uint64) x509.OID {
	tb.Helper()
	oid, err := x509.OIDFromInts(ints)
	qt.Assert(tb, qt.IsNil(err))
	return oid
}

// TestApp boots the app against an in-process miniredis and generated keys,
// with the /internal/v1 session API enabled (INTERNAL_API_TOKEN set). The
// pgx pool is created lazily on first DB use in production code
// paths; unit tests use the sessiondb fake and never touch it.
func TestApp(tb testing.TB) *App {
	tb.Helper()
	return testApp(tb, "test-internal-token")
}

// TestAppNoInternalAPI is TestApp with the /internal/v1 session API disabled
// (empty InternalAPIToken — the fail-closed default, routes/router.go Init):
// used by the "internal surface absent" acceptance (routes/internal_test.go).
func TestAppNoInternalAPI(tb testing.TB) *App {
	tb.Helper()
	return testApp(tb, "")
}

// testApp is the shared construction path behind TestApp/TestAppNoInternalAPI
// — every env var is set exactly as before this seam was extracted; only the
// internal-API-token env var varies by caller.
func testApp(tb testing.TB, internalAPIToken string) *App {
	tb.Helper()

	mr := miniredis.RunT(tb)
	dir := tb.TempDir()

	const dnsName = "verifier.test"
	// The request-signing key and the WRPAC chain MUST be a matched pair
	// (oid4vp.New: signing key == leaf public key, dnsName == leaf SAN
	// dNSName) — generate both together.
	reqKeyPath, chainPath := writeTestWRPAC(tb, dir, dnsName)

	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("SERVICE_NAME", "eudi-verifier-core")
	// Default METRICS_ENABLED off (most tests don't exercise /metrics and
	// server.New wires the Prometheus middleware once at construction time,
	// before any test could override it after the fact).
	// TestMetricsAfterE2E sets METRICS_ENABLED=true via t.Setenv BEFORE calling
	// TestApp/newFixture — respect that instead of clobbering it back to
	// false, since server.New reads it exactly once during New() below.
	if _, ok := os.LookupEnv("METRICS_ENABLED"); !ok {
		tb.Setenv("METRICS_ENABLED", "false")
	}
	tb.Setenv("POSTGRES_DSN", "postgres://verifier_core_public:test@127.0.0.1:1/verifier") // never dialed in unit tests
	tb.Setenv("VALKEY_URL", "redis://"+mr.Addr())
	tb.Setenv("PUBLIC_BASE_URL", "https://"+dnsName)
	tb.Setenv("REQUEST_SIGNING_KEY_FILE", reqKeyPath)
	tb.Setenv("HANDOFF_ENC_KEY_FILE", WriteTestKey(tb, dir, "handoff.pem"))
	tb.Setenv("WEBHOOK_SIGNING_KEY_FILE", WriteTestKey(tb, dir, "webhook.pem"))
	tb.Setenv("WRPAC_CHAIN_FILE", chainPath)
	tb.Setenv("CLIENT_DNS_NAME", dnsName)
	tb.Setenv("UNIVERSAL_LINK_BASE", "https://wallet.test/authorize")
	tb.Setenv("INTERNAL_API_TOKEN", internalAPIToken)

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))
	app.testMR = mr // expose the miniredis handle for store-wide canary greps

	// Unit tests use the in-memory session-metadata store; the pgx pool built
	// by New is never dialed (its DSN points at an unreachable port).
	app.SetSessionDB(sessiondb.NewFake())

	// pgxpool.New starts a background health-check goroutine on construction
	// and redis.NewClient owns a connection pool — both must be closed or
	// every TestApp() call across every test leaks one. Close the unexported
	// fields directly (same package) rather than via App.DB()/Valkey() to
	// avoid any nil-panic ordering concerns.
	tb.Cleanup(func() {
		app.db.Close()
		_ = app.valkey.Close()
	})

	return app
}

// SeedTestTrust installs a static trust anchor source + status-list fetcher
// for tests. It wires anchors.Static as the pipeline's AnchorSource and the
// given fetcher as the status-list fetcher override (honored lazily by
// App.statusFetcher, so the checker built in New() picks it up). Production
// backfills the real Valkey-backed AnchorSource + fetcher fed by
// trust-cache-worker; this seam mirrors the shape it will present.
func (a *App) SeedTestTrust(anchorSet []trust.Anchor, fetcher statuslist.Fetcher) {
	a.testAnchors = anchorSet
	a.testStatusFetcher = fetcher
	a.anchorSource = anchors.NewStatic(anchorSet)
	a.statusFetcherOverride = fetcher
}

// ExpireTestAnchors flips the SeedTestTrust static anchor source to fail-closed
// (subsequent AnchorsFor returns trust.ErrCacheExpired) — models a stale trust
// cache. No-op unless the current source is the
// static test source.
func (a *App) ExpireTestAnchors() {
	if s, ok := a.anchorSource.(*anchors.Static); ok {
		s.Expire()
	}
}

// SetDBPingForTest swaps the Postgres liveness probe used by /readyz. Test-only
// seam: unit tests run without a reachable Postgres (TestApp's DSN points at an
// unroutable port), so readyz tests install a stub to exercise the anchor-
// freshness and snapshot-health branches independently of the DB check.
func (a *App) SetDBPingForTest(f func(context.Context) error) { a.dbPing = f }

// TestMiniredis returns the in-process miniredis handle backing TestApp's
// Valkey client, so a store-wide canary grep (verified deletion) can
// inspect every key and value directly.
func (a *App) TestMiniredis() *miniredis.Miniredis {
	mr, _ := a.testMR.(*miniredis.Miniredis)
	return mr
}

// SessionDBFakeDump returns a JSON snapshot of every session row and stored
// report held by the in-memory session-metadata fake (installed by TestApp).
// The verified-deletion canary greps it to prove PostgreSQL carries
// claim NAMES but never attribute VALUES.
func (a *App) SessionDBFakeDump() []byte {
	f, ok := a.sessionDB.(*sessiondb.Fake)
	if !ok {
		return nil
	}
	return f.Dump()
}

// DecryptHandoffForTest decrypts a handoff result_jwe with the operator
// handoff-enc private key — the same key material the production handoff.Queue
// encrypts to (crypto.EncryptJWE). The verified-deletion canary uses it to show
// the ONLY surviving copy of the claim values is inside the encrypted payload.
// Test-only; panics if the ciphertext does not decrypt (broken test wiring).
func (a *App) DecryptHandoffForTest(jwe []byte) []byte {
	plain, _, err := crypto.DecryptJWE(context.Background(), a.keys, KeyHandoffEnc, jwe)
	if err != nil {
		panic("DecryptHandoffForTest: " + err.Error())
	}
	return plain
}
