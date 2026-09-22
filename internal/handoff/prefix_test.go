package handoff_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	"github.com/digimaks/eudi-verifier-core/internal/handoff"
	"github.com/digimaks/eudi-verifier-core/internal/keyspace"
	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"
)

func TestQueueKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	q := handoff.NewQueue(rdb, key.Public(), time.Hour, time.Now).WithKeyPrefix(keyspace.New("verifierdev"))

	meta := &sessiondb.Session{ID: "s1", ClientID: "c1", WebhookURL: "https://rp.example/hook"}
	qt.Assert(t, qt.IsNil(q.Deliver(context.Background(), meta, &pipeline.Result{SessionID: "s1", Outcome: "verified"})))

	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:vc:handoff:payload:s1")))
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:handoff:payload:s1")))
	ids, err := mr.List("verifierdev:vc:handoff:queue")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(ids, []string{"s1"}))
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:handoff:queue")))
}
