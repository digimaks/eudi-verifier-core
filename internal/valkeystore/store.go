// Package valkeystore is the Valkey implementation of oid4vp.SessionStore
// plus the service-side single-use markers and the response_code store.
// Key layout is the Locked Valkey contract.
package valkeystore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/digimaks/eudi-verifier-core/internal/keyspace"
	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/redis/go-redis/v9"
)

const (
	keySession  = "vc:session:%s"
	keyServed   = "vc:session:%s:served"
	keyConsumed = "vc:session:%s:consumed"
	keyRespCode = handoffwire.RespCodeKeyFmt // shared with eudi-api-management, which GETDELs it once
)

// Store is the Valkey-backed oid4vp.SessionStore. It also carries
// the service-side single-use request_uri marker and the
// response_code → session mapping.
type Store struct {
	rdb         redis.UniversalClient
	sessionTTL  time.Duration
	respCodeTTL time.Duration
	now         func() time.Time
	prefix      keyspace.Prefix
}

// New returns a Store backed by rdb. sessionTTL bounds how long a session
// (and its single-use markers) survive in Valkey; now is the injectable
// clock used for the ExpiresAt check on Load/ConsumeOnce (tests use a fixed
// or fast-forwarded clock via miniredis).
func New(rdb redis.UniversalClient, sessionTTL time.Duration, now func() time.Time) *Store {
	return &Store{rdb: rdb, sessionTTL: sessionTTL, respCodeTTL: 5 * time.Minute, now: now}
}

// WithResponseCodeTTL overrides the vc:respcode TTL (config-driven) and
// returns the Store for chaining at construction time.
func (s *Store) WithResponseCodeTTL(ttl time.Duration) *Store {
	s.respCodeTTL = ttl
	return s
}

// WithKeyPrefix sets the deployment key prefix applied to every key this
// store touches (see keyspace) and returns the Store for chaining.
func (s *Store) WithKeyPrefix(p keyspace.Prefix) *Store {
	s.prefix = p
	return s
}

// key formats a contract key and applies the prefix.
func (s *Store) key(format, arg string) string {
	return s.prefix.Key(fmt.Sprintf(format, arg))
}

// Save persists a JSON snapshot of sess under vc:session:{id}, matching
// oid4vp.SessionStore's contract (storetest.Run: SaveRequiresID rejects both
// a nil session and an empty-id session with ErrSessionInvalid).
func (s *Store) Save(ctx context.Context, sess *oid4vp.Session) error {
	if sess == nil || sess.ID == "" {
		return oid4vp.ErrSessionInvalid
	}
	b, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("valkeystore: marshal session: %w", err)
	}
	ttl := s.sessionTTL
	if until := time.Until(sess.ExpiresAt); until > 0 && until < ttl {
		ttl = until
	}
	return s.rdb.Set(ctx, s.key(keySession, sess.ID), b, ttl).Err()
}

// Load returns an independent copy of the stored session. An unknown or
// expired id (either by Valkey TTL eviction or by sess.ExpiresAt having
// passed the injected clock) is reported as ErrSessionNotFound — the Engine
// also enforces ExpiresAt itself, but the store must fail closed on its own
// (storetest.Run: ExpiredSessionIsNotFound).
func (s *Store) Load(ctx context.Context, id string) (*oid4vp.Session, error) {
	b, err := s.rdb.Get(ctx, s.key(keySession, id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, oid4vp.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("valkeystore: load: %w", err)
	}
	var sess oid4vp.Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, fmt.Errorf("valkeystore: unmarshal session: %w", err)
	}
	if !sess.ExpiresAt.IsZero() && !s.now().Before(sess.ExpiresAt) {
		return nil, oid4vp.ErrSessionNotFound
	}
	return &sess, nil
}

// ConsumeOnce atomically claims the session for response processing
// ([OID4VP §8.2] one-time use). SET NX on the vc:session:{id}:consumed marker
// is the linearization point; exactly one caller ever sees first==true. The
// winner additionally persists Consumed=true onto the session's own record
// so that Load (and every later caller reading the session, e.g.
// ProcessResponse) observes it too — the storetest contract
// (ConsumeOnceConsumes / ConsumedMarkerSurvivesSave) requires both the
// returned AND the subsequently-loaded session to carry Consumed=true, and
// the marker must stay sticky even across a later Save of the session (the
// separate marker key, not the session's own Consumed field, is what makes
// replay detection survive that Save).
//
// If persisting Consumed=true fails after the marker was already claimed
// (e.g. a transient Valkey error on the Save), the marker is rolled back
// (best-effort DEL) before returning the error. Otherwise the marker would
// stay set for its full TTL with no session ever actually consumed, and a
// legitimate wallet retry would be rejected as ErrSessionConsumed —
// indistinguishable from a real replay (availability gap flagged in code
// review; no double-consume was ever possible either way, since the
// session was never returned to a caller in that path).
func (s *Store) ConsumeOnce(ctx context.Context, id string) (*oid4vp.Session, error) {
	sess, err := s.Load(ctx, id)
	if err != nil {
		return nil, err
	}
	consumedKey := s.key(keyConsumed, id)
	first, err := s.rdb.SetNX(ctx, consumedKey, "1", s.sessionTTL).Result()
	if err != nil {
		return nil, fmt.Errorf("valkeystore: consume: %w", err)
	}
	if !first {
		return nil, oid4vp.ErrSessionConsumed
	}
	sess.Consumed = true
	if err := s.Save(ctx, sess); err != nil {
		// Best-effort rollback: Save failed after we already claimed the
		// marker, so a legitimate retry must not be permanently locked out
		// as a false replay. If the rollback itself fails too, the
		// marker's TTL still bounds the lockout window.
		_ = s.rdb.Del(ctx, consumedKey).Err()
		return nil, fmt.Errorf("valkeystore: consume: persist Consumed: %w", err)
	}
	return sess, nil
}

// MarkRequestObjectServed enforces single-use GET of request.jwt. Single-use is
// this service's own hardening — OID4VP states no such requirement. It reports
// whether this call is the first to mark the session's request object as
// served.
func (s *Store) MarkRequestObjectServed(ctx context.Context, id string) (bool, error) {
	first, err := s.rdb.SetNX(ctx, s.key(keyServed, id), "1", s.sessionTTL).Result()
	if err != nil {
		return false, fmt.Errorf("valkeystore: mark served: %w", err)
	}
	return first, nil
}

// SaveResponseCode stores the [OID4VP §8.2] response_code → session mapping
// (vc:respcode:{code}) for eudi-api-management, which consumes it exactly once
// via GETDEL.
func (s *Store) SaveResponseCode(ctx context.Context, code oid4vp.ResponseCode, sessionID string) error {
	return s.rdb.Set(ctx, s.key(keyRespCode, string(code)), sessionID, s.respCodeTTL).Err()
}

// DeleteSession removes every session-scoped key — the verified
// deletion path (ARF AS-RP-51-011/013).
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.rdb.Del(ctx,
		s.key(keySession, id),
		s.key(keyServed, id),
		s.key(keyConsumed, id),
	).Err()
}
