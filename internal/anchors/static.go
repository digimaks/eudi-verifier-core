// Package anchors provides trust.AnchorSource implementations: Static (tests)
// and Valkey (fed by trust-cache-worker).
package anchors

import (
	"sync"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// Static serves a fixed anchor set; Expire() flips it to fail-closed
// (stale-cache tests).
type Static struct {
	mu      sync.Mutex
	anchors []trust.Anchor
	expired bool
}

// NewStatic returns a Static anchor source over the given anchors.
func NewStatic(a []trust.Anchor) *Static { return &Static{anchors: a} }

// Expire flips the source to fail-closed (subsequent AnchorsFor returns
// trust.ErrCacheExpired) — models a stale trust cache.
func (s *Static) Expire() { s.mu.Lock(); s.expired = true; s.mu.Unlock() }

// AnchorsFor implements trust.AnchorSource (fail closed on expiry).
func (s *Static) AnchorsFor(t trust.AnchorType, country string) ([]trust.Anchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expired {
		return nil, trust.ErrCacheExpired
	}
	var out []trust.Anchor
	for _, a := range s.anchors {
		if a.Type != t {
			continue
		}
		if country != "" && a.Country != country {
			continue
		}
		if time.Now().After(a.ValidUntil) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}
