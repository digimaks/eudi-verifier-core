package statuscache_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/digimaks/eudi-verifier-core/internal/statuscache"
	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
)

const listURI = "https://status.example/1"

func newRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

// The Valkey status cache shares the trust:statuslist:* keyspace: tokens
// live under trust:statuslist:<sha256hex(uri)> (trustcache.StatusListKey) and
// ref popularity in the ZSET trust:statuslist:refs (trustcache.StatusRefsKey).
func TestStatusCache(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, c *statuscache.Cache, r *statuscache.RefRecorder, mr *miniredis.Miniredis)
	}{
		{
			name: "set-get roundtrip under the shared trust-cache key",
			run: func(t *testing.T, c *statuscache.Cache, _ *statuscache.RefRecorder, mr *miniredis.Miniredis) {
				c.Set(listURI, []byte("token-bytes"), time.Minute)
				got, ok := c.Get(listURI)
				qt.Assert(t, qt.IsTrue(ok))
				qt.Assert(t, qt.DeepEquals(got, []byte("token-bytes")))
				// The physical key is exactly the hashed key — a
				// worker-warmed list is a local hit and vice-versa.
				stored, err := mr.Get(trustcache.StatusListKey(listURI))
				qt.Assert(t, qt.IsNil(err))
				qt.Assert(t, qt.Equals(stored, "token-bytes"))
			},
		},
		{
			name: "expiry honored (TTL elapsed ⇒ miss)",
			run: func(t *testing.T, c *statuscache.Cache, _ *statuscache.RefRecorder, mr *miniredis.Miniredis) {
				c.Set(listURI, []byte("token-bytes"), time.Minute)
				mr.FastForward(2 * time.Minute)
				_, ok := c.Get(listURI)
				qt.Assert(t, qt.IsFalse(ok))
			},
		},
		{
			name: "missing key is a miss",
			run: func(t *testing.T, c *statuscache.Cache, _ *statuscache.RefRecorder, _ *miniredis.Miniredis) {
				_, ok := c.Get("https://status.example/never-set")
				qt.Assert(t, qt.IsFalse(ok))
			},
		},
		{
			name: "RefRecorder ZADDs the URI into trust:statuslist:refs",
			run: func(t *testing.T, _ *statuscache.Cache, r *statuscache.RefRecorder, mr *miniredis.Miniredis) {
				qt.Assert(t, qt.IsNil(r.Record(context.Background(), listURI)))
				members, err := mr.ZMembers(trustcache.StatusRefsKey)
				qt.Assert(t, qt.IsNil(err))
				qt.Assert(t, qt.IsTrue(slices.Contains(members, listURI)))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rdb, mr := newRedis(t)
			c := statuscache.NewCache(rdb, time.Now)
			r := statuscache.NewRefRecorder(rdb, time.Now)
			tc.run(t, c, r, mr)
		})
	}
}
