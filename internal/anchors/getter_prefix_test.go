package anchors_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	"github.com/dativa-lv/eudi-verifier-core/internal/anchors"
	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
)

// The reader must look where a prefixed worker writes — and nowhere else.
func TestRedisGetterKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	qt.Assert(t, qt.IsNil(mr.Set("verifierdev:trust:freshness:x", "prefixed")))
	qt.Assert(t, qt.IsNil(mr.Set("trust:freshness:x", "bare")))

	g := anchors.RedisGetter{RDB: rdb, Prefix: keyspace.New("verifierdev")}
	b, err := g.Get(context.Background(), "trust:freshness:x")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(b), "prefixed"))

	b, err = anchors.RedisGetter{RDB: rdb}.Get(context.Background(), "trust:freshness:x")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(b), "bare"))

	b, err = g.Get(context.Background(), "trust:freshness:missing")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(b))
}
