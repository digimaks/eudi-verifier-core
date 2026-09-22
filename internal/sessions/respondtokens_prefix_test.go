package sessions_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	"github.com/digimaks/eudi-verifier-core/internal/keyspace"
	"github.com/digimaks/eudi-verifier-core/internal/sessions"
)

func TestRespondTokensKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	rt := sessions.NewValkeyRespondTokens(rdb).WithKeyPrefix(keyspace.New("verifierdev"))

	qt.Assert(t, qt.IsNil(rt.Put(context.Background(), "tok", "sess-1", time.Minute)))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:vc:respondtoken:tok")))
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:respondtoken:tok")))
	id, err := rt.Resolve(context.Background(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, "sess-1"))
}
