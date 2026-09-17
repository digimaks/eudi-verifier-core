package anchors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
)

// testCertDER builds a self-signed P-256 certificate and returns its DER — the
// public material the worker caches (same pattern as internal/testwallet PKI).
func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "EUDI Test Anchor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	qt.Assert(t, qt.IsNil(err))
	return der
}

func seed(t *testing.T, mr *miniredis.Miniredis, keyType, territory string, validUntil time.Time, certDER []byte, stale bool) {
	t.Helper()
	entry := trustcache.AnchorSetEntry{
		SnapshotID: "snap-1", Type: keyType, Territory: trustcache.NormalizeTerritory(territory),
		FetchedAt: time.Now().Add(-5 * time.Minute), ValidUntil: validUntil, UpstreamStale: stale,
		Anchors: []trustcache.Anchor{{
			CertDER: certDER, Territory: trustcache.NormalizeTerritory(territory),
			Status: "granted", ValidUntil: validUntil.Add(24 * time.Hour), TLSequence: 1,
		}},
	}
	b, err := json.Marshal(entry)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(mr.Set(trustcache.AnchorSetKey(keyType, territory), string(b))))
	fr := trustcache.TypeFreshness{SnapshotID: "snap-1", FetchedAt: entry.FetchedAt, ValidUntil: validUntil, UpstreamStale: stale}
	fb, _ := json.Marshal(fr)
	qt.Assert(t, qt.IsNil(mr.Set(trustcache.FreshnessKey(keyType), string(fb))))
}

func newValkeySource(t *testing.T) (*Valkey, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewValkey(RedisGetter{RDB: rdb}, 0, time.Now), mr
}

// seedFreshnessOnly writes trust:freshness:<keyType> WITHOUT writing the
// per-territory trust:anchors:<keyType>:<territory> set, reproducing the
// worker's real output when a type's sync is fresh but a given territory
// legitimately has zero anchors.
func seedFreshnessOnly(t *testing.T, mr *miniredis.Miniredis, keyType string, validUntil time.Time, stale bool) {
	t.Helper()
	fr := trustcache.TypeFreshness{SnapshotID: "snap-1", FetchedAt: time.Now().Add(-5 * time.Minute), ValidUntil: validUntil, UpstreamStale: stale}
	fb, err := json.Marshal(fr)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(mr.Set(trustcache.FreshnessKey(keyType), string(fb))))
}

func TestFreshAnchorsServed(t *testing.T) {
	src, mr := newValkeySource(t)
	der := testCertDER(t)
	seed(t, mr, trustcache.TypePIDProvider, "LV", time.Now().Add(time.Hour), der, false)

	got, err := src.AnchorsFor(trust.PIDProvider, "LV")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(got), 1))
	qt.Assert(t, qt.Equals(got[0].Country, "LV"))
}

// Issuing-territory-then-EU resolution: a "" request tries
// the credential's territory first (caller passes it) then EU. Here the
// EU-level list answers a country="" query via NormalizeTerritory("")=="EU".
func TestEUAnchorsServedForEmptyCountry(t *testing.T) {
	src, mr := newValkeySource(t)
	seed(t, mr, trustcache.TypePIDProvider, "", time.Now().Add(time.Hour), testCertDER(t), false)
	got, err := src.AnchorsFor(trust.PIDProvider, "")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(got), 1))
	qt.Assert(t, qt.Equals(got[0].Country, "EU"))
}

// expired entry FAILS CLOSED (trustcache
// maps missing/expired keys to ErrCacheExpired; adapter re-maps to trust's).
// Both the per-territory key AND the type's freshness marker are made to
// expire together here (as they would in real degradation — a dead worker
// stops refreshing both, since they come from the same fetch cycle): that
// keeps this test asserting genuine cache degradation, distinct from
// TestMissingKeyWithFreshTypeReturnsConfirmedEmpty's confirmed-empty case
// where the territory key is missing but the type is otherwise fresh.
func TestExpiredSetFailsClosed(t *testing.T) {
	src, mr := newValkeySource(t)
	// miniredis TTL time-travel: seed with a short TTL then fast-forward.
	seed(t, mr, trustcache.TypePIDProvider, "LV", time.Now().Add(time.Hour), testCertDER(t), false)
	mr.SetTTL(trustcache.AnchorSetKey(trustcache.TypePIDProvider, "LV"), time.Minute)
	mr.SetTTL(trustcache.FreshnessKey(trustcache.TypePIDProvider), time.Minute)
	mr.FastForward(2 * time.Minute)
	_, err := src.AnchorsFor(trust.PIDProvider, "LV")
	qt.Assert(t, qt.ErrorIs(err, trust.ErrCacheExpired))
}

func TestMissingKeyFailsClosed(t *testing.T) {
	src, _ := newValkeySource(t)
	_, err := src.AnchorsFor(trust.PIDProvider, "LV")
	qt.Assert(t, qt.ErrorIs(err, trust.ErrCacheExpired))
}

// TestMissingKeyWithFreshTypeReturnsConfirmedEmpty is the
// core fix: a missing per-territory key is
// NOT automatically cache-expired. If the type's own freshness marker proves
// the worker's latest sync is fresh (not upstream-stale, not past its
// ValidUntil), the missing territory key means "confirmed zero anchors here"
// — return an empty set with nil error so go-eudi-trust's ResolveIssuerKey
// advances to the next territory instead of aborting the whole resolution
// with a false-positive trust.ErrCacheExpired.
func TestMissingKeyWithFreshTypeReturnsConfirmedEmpty(t *testing.T) {
	src, mr := newValkeySource(t)
	seedFreshnessOnly(t, mr, trustcache.TypePIDProvider, time.Now().Add(45*time.Minute), false)

	got, err := src.AnchorsFor(trust.PIDProvider, "")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(got), 0))
}

// TestMissingKeyWithStaleTypeFailsClosed: fail-closed negative #1 — the
// type's freshness marker EXISTS but reports UpstreamStale, so a missing
// territory key must still be treated as genuine cache degradation
// (never confuse "confirmed empty" with "never synced/stale").
func TestMissingKeyWithStaleTypeFailsClosed(t *testing.T) {
	src, mr := newValkeySource(t)
	seedFreshnessOnly(t, mr, trustcache.TypePIDProvider, time.Now().Add(45*time.Minute), true)

	_, err := src.AnchorsFor(trust.PIDProvider, "")
	qt.Assert(t, qt.ErrorIs(err, trust.ErrCacheExpired))
}

// TestMissingKeyWithPastValidUntilFailsClosed: fail-closed negative #2 — the
// freshness marker's ValidUntil has already passed (worker stopped syncing
// long enough ago that even the type-level record aged out), so the missing
// territory key must still fail closed, not be read as confirmed-empty.
func TestMissingKeyWithPastValidUntilFailsClosed(t *testing.T) {
	src, mr := newValkeySource(t)
	seedFreshnessOnly(t, mr, trustcache.TypePIDProvider, time.Now().Add(-time.Minute), false)

	_, err := src.AnchorsFor(trust.PIDProvider, "")
	qt.Assert(t, qt.ErrorIs(err, trust.ErrCacheExpired))
}

// TestMissingKeyIgnoresReadyzGrace: the /readyz grace window (NewValkey's
// grace parameter) must never leak into verification (doc comment on Valkey
// above: "The grace applies to /readyz reporting only, never to
// verification"). A freshness record just past its ValidUntil — within what
// would count as "fresh" for /readyz purposes under a nonzero grace — must
// still fail closed here, proving the confirmed-empty path applies NO grace.
func TestMissingKeyIgnoresReadyzGrace(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	src := NewValkey(RedisGetter{RDB: rdb}, time.Hour, time.Now) // large grace, /readyz-only
	seedFreshnessOnly(t, mr, trustcache.TypePIDProvider, time.Now().Add(-time.Minute), false)

	_, err := src.AnchorsFor(trust.PIDProvider, "")
	qt.Assert(t, qt.ErrorIs(err, trust.ErrCacheExpired))
}

// UpstreamStale (X-Trust-Stale propagated by the worker) => degraded readiness;
// verification still fails closed on the freshness signal.
func TestStaleFlagFailsClosed(t *testing.T) {
	src, mr := newValkeySource(t)
	seed(t, mr, trustcache.TypePIDProvider, "LV", time.Now().Add(time.Hour), testCertDER(t), true)
	_, err := src.AnchorsFor(trust.PIDProvider, "LV")
	qt.Assert(t, qt.ErrorIs(err, trust.ErrCacheExpired))
}

// Unknown anchor type is rejected, never served.
func TestUnknownTypeRejected(t *testing.T) {
	src, _ := newValkeySource(t)
	_, err := src.AnchorsFor(trust.AnchorType("not-a-type"), "LV")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.IsFalse(err == nil))
}

// UseCases must survive the cache round-trip into trust.Anchor, not
// silently zero out — go-eudi-trust surfaces them on the resolved anchor.
func TestUseCasesPreserved(t *testing.T) {
	src, mr := newValkeySource(t)
	entry := trustcache.AnchorSetEntry{
		SnapshotID: "snap-1", Type: trustcache.TypeEAAProvider, Territory: "LV",
		FetchedAt: time.Now().Add(-time.Minute), ValidUntil: time.Now().Add(time.Hour),
		Anchors: []trustcache.Anchor{{
			CertDER: testCertDER(t), Territory: "LV", Status: "granted",
			ValidUntil: time.Now().Add(24 * time.Hour), TLSequence: 1, UseCases: []string{"mDL", "EHIC"},
		}},
	}
	b, err := json.Marshal(entry)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(mr.Set(trustcache.AnchorSetKey(trustcache.TypeEAAProvider, "LV"), string(b))))

	got, err := src.AnchorsFor(trust.EAAProvider, "LV")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(got), 1))
	qt.Assert(t, qt.DeepEquals(got[0].UseCases, []string{"mDL", "EHIC"}))
}

func TestFreshnessReport(t *testing.T) {
	src, mr := newValkeySource(t)
	seed(t, mr, trustcache.TypePIDProvider, "LV", time.Now().Add(time.Hour), testCertDER(t), false)
	fr := src.Freshness(context.Background())
	qt.Assert(t, qt.IsTrue(fr["pid_provider"].Fresh))
	qt.Assert(t, qt.IsFalse(fr["access_ca"].Fresh)) // absent type = not fresh
	// The trust identity the freshness record carries survives the read: the
	// snapshot id and fetch time feed the trust-status diagnostic.
	qt.Assert(t, qt.Equals(fr["pid_provider"].SnapshotID, "snap-1"))
	qt.Assert(t, qt.IsFalse(fr["pid_provider"].FetchedAt.IsZero()))
	qt.Assert(t, qt.Equals(fr["access_ca"].SnapshotID, "")) // absent = no identity, never a guess
}
