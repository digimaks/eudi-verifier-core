// respondtokens.go — the vc:respondtoken:{token} routing index. See Create's
// doc comment in
// creator.go for why this indirection exists. (The package doc lives in
// creator.go.)

package sessions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
)

// ErrRespondTokenNotFound is returned when a response-route routing token is
// unknown or has expired (fail closed).
var ErrRespondTokenNotFound = errors.New("sessions: respond token not found or expired")

// RespondTokens indexes the opaque response-route routing token to the real
// oid4vp.Session.ID.
type RespondTokens interface {
	Put(ctx context.Context, token, sessionID string, ttl time.Duration) error
	Resolve(ctx context.Context, token string) (string, error)
}

// ValkeyRespondTokens implements RespondTokens against the vc:respondtoken:{token}
// STRING key.
type ValkeyRespondTokens struct {
	rdb    redis.UniversalClient
	prefix keyspace.Prefix
}

const keyRespondToken = "vc:respondtoken:"

// NewValkeyRespondTokens returns a RespondTokens backed by rdb.
func NewValkeyRespondTokens(rdb redis.UniversalClient) *ValkeyRespondTokens {
	return &ValkeyRespondTokens{rdb: rdb}
}

// WithKeyPrefix sets the deployment key prefix (see keyspace) and returns the
// index for chaining.
func (v *ValkeyRespondTokens) WithKeyPrefix(p keyspace.Prefix) *ValkeyRespondTokens {
	v.prefix = p
	return v
}

// Put records token → sessionID with the same TTL as the session, so a stale
// token cannot outlive the session it routes to.
func (v *ValkeyRespondTokens) Put(ctx context.Context, token, sessionID string, ttl time.Duration) error {
	return v.rdb.Set(ctx, v.prefix.Key(keyRespondToken+token), sessionID, ttl).Err()
}

// Resolve returns the real session id for token, or ErrRespondTokenNotFound
// when the token is unknown/expired (fail closed).
func (v *ValkeyRespondTokens) Resolve(ctx context.Context, token string) (string, error) {
	id, err := v.rdb.Get(ctx, v.prefix.Key(keyRespondToken+token)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrRespondTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("sessions: respond token: %w", err)
	}
	return id, nil
}

// newRespondToken mints a 128-bit opaque routing token — the same entropy
// class as the engine's own session/nonce/state tokens ([OID4VP §5.2] nonce
// entropy).
func newRespondToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
