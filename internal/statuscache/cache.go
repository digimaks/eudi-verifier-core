// Package statuscache is the Valkey-backed statuslist.Cache (seam) plus
// the status-ref popularity recorder — both sharing the trust:statuslist:*
// keyspace (trustcache): tokens at trust:statuslist:<sha256hex(uri)>, ref
// popularity in the ZSET trust:statuslist:refs. A worker-prefetched list is a
// local hit and a list this pod fetches warms the worker's next prefetch.
package statuscache

import (
	"context"
	"time"

	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"github.com/redis/go-redis/v9"

	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
)

// Cache implements go-statuslist's Cache over Valkey. The interface key is the
// list URI (as go-statuslist passes it); it is hashed to the shared key via
// trustcache.StatusListKey so the keyspace matches the worker's exactly.
type Cache struct {
	rdb    redis.UniversalClient
	ctx    context.Context
	now    func() time.Time
	prefix keyspace.Prefix
}

// NewCache returns a Valkey-backed statuslist.Cache. The go-statuslist Cache
// interface is ctx-free, so a base context is captured — acceptable for a cache.
func NewCache(rdb redis.UniversalClient, now func() time.Time) *Cache {
	return &Cache{rdb: rdb, ctx: context.Background(), now: now}
}

// WithKeyPrefix sets the deployment key prefix (see keyspace) and returns the
// Cache for chaining. It must equal the worker's, or its prefetched lists are
// invisible here.
func (c *Cache) WithKeyPrefix(p keyspace.Prefix) *Cache {
	c.prefix = p
	return c
}

// Get returns the cached token bytes for the list URI (miss on absent/expired).
func (c *Cache) Get(uri string) ([]byte, bool) {
	b, err := c.rdb.Get(c.ctx, c.prefix.Key(trustcache.StatusListKey(uri))).Bytes()
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// Set caches token bytes under the shared key with the list-driven TTL.
func (c *Cache) Set(uri string, val []byte, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	_ = c.rdb.Set(c.ctx, c.prefix.Key(trustcache.StatusListKey(uri)), val, ttl).Err()
}

// RefRecorder implements pipeline.StatusRefRecorder: ZADD the referenced URI
// with score=now so trust-cache-worker prefetches popular lists.
type RefRecorder struct {
	rdb    redis.UniversalClient
	now    func() time.Time
	prefix keyspace.Prefix
}

// NewRefRecorder returns a RefRecorder over rdb (ZADDs to trust:statuslist:refs).
func NewRefRecorder(rdb redis.UniversalClient, now func() time.Time) *RefRecorder {
	return &RefRecorder{rdb: rdb, now: now}
}

// WithKeyPrefix sets the deployment key prefix (see keyspace) and returns the
// recorder for chaining.
func (r *RefRecorder) WithKeyPrefix(p keyspace.Prefix) *RefRecorder {
	r.prefix = p
	return r
}

// Record ZADDs uri with score=now unix seconds so the worker prefetches it.
func (r *RefRecorder) Record(ctx context.Context, uri string) error {
	return r.rdb.ZAdd(ctx, r.prefix.Key(trustcache.StatusRefsKey),
		redis.Z{Score: float64(r.now().Unix()), Member: uri}).Err()
}
