package anchors

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
	"github.com/gmb-eudi/go-verifier-helpers/trustcache"
)

// wireType maps go-eudi-trust's AnchorType to the trustcache Type* wire
// string. The mapping lives HERE (not in trustcache) so the shared package
// stays free of a go-eudi-trust import.
var wireType = map[trust.AnchorType]string{
	trust.PIDProvider:    trustcache.TypePIDProvider,
	trust.QEAAProvider:   trustcache.TypeQEAAProvider,
	trust.PubEAAProvider: trustcache.TypePubEAAProvider,
	trust.EAAProvider:    trustcache.TypeEAAProvider,
	trust.WalletProvider: trustcache.TypeWalletProvider,
	trust.AccessCA:       trustcache.TypeAccessCA,
	trust.WRPRCIssuer:    trustcache.TypeWRPRCIssuer,
	// Status-signer anchor types.
	trust.PIDProviderStatus:    trustcache.TypePIDProviderStatus,
	trust.QEAAProviderStatus:   trustcache.TypeQEAAProviderStatus,
	trust.PubEAAProviderStatus: trustcache.TypePubEAAProviderStatus,
	trust.EAAProviderStatus:    trustcache.TypeEAAProviderStatus,
}

// Valkey adapts the trustcache.Reader into a go-eudi-trust AnchorSource
// (anchors ONLY via go-eudi-trust). Fail
// closed: trustcache.ErrCacheExpired (missing/expired key) => trust.ErrCacheExpired,
// UNLESS the type's own freshness marker proves the miss is a confirmed-empty
// territory rather than genuine staleness (see AnchorsFor's doc comment).
// The grace applies to /readyz
// reporting only, never to verification — including that confirmed-empty check.
type Valkey struct {
	reader *trustcache.Reader
	grace  time.Duration
	now    func() time.Time
}

// NewValkey builds a trustcache-backed AnchorSource. grace tolerates extra
// aging on /readyz freshness reporting only (never on AnchorsFor verification).
func NewValkey(getter trustcache.Getter, grace time.Duration, now func() time.Time) *Valkey {
	if now == nil {
		now = time.Now
	}
	return &Valkey{reader: trustcache.NewReader(getter, now), grace: grace, now: now}
}

// AnchorsFor implements trust.AnchorSource. // [ARF §6.6.3.6] anchor retrieval.
// The caller passes ONE territory per call (or "" for EU-level);
// trustcache.NormalizeTerritory maps "" => "EU". This method resolves a single
// territory and does NOT itself implement any issuing-then-EU fallback. That
// order lives in go-eudi-trust's ResolveIssuerKey (resolve.go):
// it derives territoryOrder(leaf) (e.g. ["LV", ""]) and calls AnchorsFor once per
// territory, in order. Crucially it advances to the next territory ONLY on an
// EMPTY anchor set; ANY error — including the trust.ErrCacheExpired this method
// returns for a missing/expired/stale key — aborts immediately and fails closed,
// never silently retrying at EU level. The pipeline reaches this
// via resolveByTypes (check_issuer_authenticity.go), which loops anchor TYPES and
// calls ResolveIssuerKey per type.
func (v *Valkey) AnchorsFor(t trust.AnchorType, country string) ([]trust.Anchor, error) {
	wt, ok := wireType[t]
	if !ok {
		return nil, fmt.Errorf("anchors: %w: %q", trust.ErrUnknownAnchorType, t)
	}
	ctx := context.Background()
	entry, err := v.reader.AnchorSet(ctx, wt, country)
	if err != nil {
		if errors.Is(err, trustcache.ErrCacheExpired) {
			// A missing trust:anchors:<type>:<territory> key is ambiguous by
			// itself: it means EITHER this type's cache sync never completed
			// / has gone stale (fail closed) OR the worker's
			// most recent sync for this type is fresh and legitimately wrote
			// no entry for this territory because it confirmed zero anchors
			// there (e.g. a fallback EU-level probe for a type this trust
			// service only ever publishes per-country). go-eudi-trust's
			// ResolveIssuerKey relies on the distinction: it treats an EMPTY
			// anchor set as "try the next territory" but ANY error as
			// "abort the whole resolution, fail closed"
			// (go-eudi-trust's resolve.go) — so conflating the two
			// turned a genuinely-untrusted issuer chain into a false-positive
			// err:trust:anchor-unavailable instead of the correct
			// err:credential:issuer-untrusted.
			// Disambiguate via the type's own freshness
			// marker — already read elsewhere in this file for /readyz
			// (Freshness, below) — WITHOUT the /readyz grace window, which
			// must never leak into verification.
			//
			// Accepted risk: this path trusts the worker's atomic
			// swap discipline — trust-cache-worker's RefreshAnchorType 304 path
			// documents a rare TTL race where a single territory blob can vanish
			// while the index/freshness stay fresh; in that window a degraded
			// territory reads as confirmed-empty. Bounded to false negatives (a
			// legitimate issuer may be misclassified as untrusted); it can never
			// accept an untrusted chain, so the fail-closed guarantee holds.
			//
			// Note: in go.work workspace-mode builds, v.reader.AnchorSet resolves
			// to the local go-verifier-helpers checkout whose Reader already
			// returns confirmed-empty itself, short-circuiting this branch; it is
			// live in GOWORK=off / tagged-dependency builds (what ships).
			if v.typeFreshForVerification(ctx, wt) {
				return []trust.Anchor{}, nil
			}
			return nil, trust.ErrCacheExpired // fail closed
		}
		return nil, fmt.Errorf("anchors: read %s/%s: %w", wt, trustcache.NormalizeTerritory(country), err)
	}
	if entry.UpstreamStale || v.now().After(entry.ValidUntil) {
		return nil, trust.ErrCacheExpired // X-Trust-Stale / past validity = degraded (fail closed)
	}
	out := make([]trust.Anchor, 0, len(entry.Anchors))
	for _, a := range entry.Anchors {
		cert, err := x509.ParseCertificate(a.CertDER)
		if err != nil {
			return nil, fmt.Errorf("anchors: bad certificate for %s: %w", wt, err)
		}
		out = append(out, trust.Anchor{
			Cert: cert, Type: t, Country: a.Territory, Status: a.Status,
			ValidUntil: a.ValidUntil, TLSequence: a.TLSequence,
			UseCases: a.UseCases, // preserve accredited EAA use cases across the cache round-trip
		})
	}
	return out, nil
}

// typeFreshForVerification reports whether wt's own cache sync is fresh
// enough to trust a missing per-territory key as "confirmed zero anchors"
// rather than "genuinely stale/never synced".
// It reads the same trust:freshness:<type> record and the
// same two fields (UpstreamStale, ValidUntil) that Freshness (below) reports
// for /readyz, but deliberately WITHOUT the v.grace window: grace exists to
// tolerate extra aging in readiness *reporting* only (NewValkey's doc
// comment) and must never let verification treat a type as fresher than it
// actually is (fail closed).
func (v *Valkey) typeFreshForVerification(ctx context.Context, wt string) bool {
	fr, err := v.reader.Freshness(ctx, wt)
	if err != nil {
		return false
	}
	return !fr.UpstreamStale && v.now().Before(fr.ValidUntil)
}

// TypeFreshness feeds /readyz, the staleness gauge and the trust-status
// diagnostic. SnapshotID/FetchedAt carry the trust identity the freshness
// record already holds — which snapshot this type's anchors came from and
// when the cache last confirmed it.
type TypeFreshness struct {
	Fresh      bool
	ValidUntil time.Time
	Stale      bool
	SnapshotID string
	FetchedAt  time.Time
}

// Freshness reads the per-type trust:freshness:<type> keys via trustcache. An
// absent/unreadable record reports Fresh=false (fail closed for readiness).
func (v *Valkey) Freshness(ctx context.Context) map[string]TypeFreshness {
	out := make(map[string]TypeFreshness, len(trustcache.AllTypes()))
	for _, wt := range trustcache.AllTypes() {
		fr, err := v.reader.Freshness(ctx, wt)
		if err != nil {
			out[wt] = TypeFreshness{Fresh: false}
			continue
		}
		out[wt] = TypeFreshness{
			Fresh:      !fr.UpstreamStale && v.now().Before(fr.ValidUntil.Add(v.grace)),
			ValidUntil: fr.ValidUntil,
			Stale:      fr.UpstreamStale,
			SnapshotID: fr.SnapshotID,
			FetchedAt:  fr.FetchedAt,
		}
	}
	return out
}

// SnapshotHealth surfaces LOTL sequence + pending-bootstrap for /readyz
// (end-to-end degraded-state visibility).
func (v *Valkey) SnapshotHealth(ctx context.Context) (*trustcache.SnapshotHealth, error) {
	return v.reader.SnapshotHealth(ctx)
}

// TypeKeyList returns the trust-anchor wire-type taxonomy (the same closed set
// Freshness keys its map by), for the anchor-staleness gauge labels.
func TypeKeyList() []string {
	return trustcache.AllTypes()
}
