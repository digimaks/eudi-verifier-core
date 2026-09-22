package valkeystore_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/digimaks/eudi-verifier-core/internal/keyspace"
	"github.com/digimaks/eudi-verifier-core/internal/valkeystore"
)

// Every key the store writes lands under the configured prefix and nothing
// lands unprefixed — the contract names are unchanged, the prefix is added.
func TestKeyPrefixAppliesToEveryKey(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	s := valkeystore.New(rdb, 5*time.Minute, time.Now).WithKeyPrefix(keyspace.New("verifierdev"))
	ctx := context.Background()

	sess := &oid4vp.Session{ID: "s1", ExpiresAt: time.Now().Add(time.Minute), Registration: testRegistration(t, "s1")}
	qt.Assert(t, qt.IsNil(s.Save(ctx, sess)))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:vc:session:s1")))
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:session:s1")))

	loaded, err := s.Load(ctx, "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(loaded.ID, "s1"))

	first, err := s.MarkRequestObjectServed(ctx, "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(first))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:vc:session:s1:served")))

	_, err = s.ConsumeOnce(ctx, "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:vc:session:s1:consumed")))

	qt.Assert(t, qt.IsNil(s.SaveResponseCode(ctx, oid4vp.ResponseCode("c1"), "s1")))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:vc:respcode:c1")))

	qt.Assert(t, qt.IsNil(s.DeleteSession(ctx, "s1")))
	for _, k := range []string{"verifierdev:vc:session:s1", "verifierdev:vc:session:s1:served", "verifierdev:vc:session:s1:consumed"} {
		qt.Assert(t, qt.IsFalse(mr.Exists(k)), qt.Commentf("%s should be deleted", k))
	}
	qt.Assert(t, qt.DeepEquals(unprefixed(mr.Keys()), []string{}))
}

func unprefixed(keys []string) []string {
	out := []string{}
	for _, k := range keys {
		if len(k) < len("verifierdev:") || k[:len("verifierdev:")] != "verifierdev:" {
			out = append(out, k)
		}
	}
	return out
}
