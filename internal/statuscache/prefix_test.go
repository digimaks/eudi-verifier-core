package statuscache_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	"github.com/gmb-eudi/go-verifier-helpers/trustcache"

	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
	"github.com/dativa-lv/eudi-verifier-core/internal/statuscache"
)

func TestStatusCacheKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	p := keyspace.New("verifierdev")
	c := statuscache.NewCache(rdb, time.Now).WithKeyPrefix(p)
	r := statuscache.NewRefRecorder(rdb, time.Now).WithKeyPrefix(p)
	const uri = "https://status.example/list/1"

	c.Set(uri, []byte("tok"), time.Minute)
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:"+trustcache.StatusListKey(uri))))
	qt.Assert(t, qt.IsFalse(mr.Exists(trustcache.StatusListKey(uri))))
	got, ok := c.Get(uri)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(string(got), "tok"))

	qt.Assert(t, qt.IsNil(r.Record(context.Background(), uri)))
	members, err := mr.ZMembers("verifierdev:" + trustcache.StatusRefsKey)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(members, []string{uri}))
	qt.Assert(t, qt.IsFalse(mr.Exists(trustcache.StatusRefsKey)))
}
