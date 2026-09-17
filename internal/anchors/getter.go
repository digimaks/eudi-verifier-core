package anchors

import (
	"context"
	"errors"

	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"github.com/redis/go-redis/v9"

	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
)

// RedisGetter adapts a go-redis client to trustcache.Getter (the stdlib-only
// seam trustcache exposes so each service brings its own Valkey client). This is the
// ONE place eudi-verifier-core supplies its own client behind that seam; if the
// service later unifies on valkey-go, only this file changes.
//
// Prefix is the deployment key prefix (see keyspace); it must equal the
// worker's, or every anchor read misses and the service stays not-ready.
type RedisGetter struct {
	RDB    redis.UniversalClient
	Prefix keyspace.Prefix
}

var _ trustcache.Getter = RedisGetter{}

// Get returns (nil, nil) on a missing key — the trustcache.Getter contract:
// absence is data (the Reader turns it into ErrCacheExpired, fail closed),
// distinct from a transport error.
func (g RedisGetter) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := g.RDB.Get(ctx, g.Prefix.Key(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}
