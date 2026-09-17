package handoff_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/dativa-lv/eudi-verifier-core/internal/handoff"
	"github.com/dativa-lv/eudi-verifier-core/internal/pipeline"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessiondb"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
)

const canary = "CANARY-CLAIM-VALUE-8813"

func setup(t *testing.T) (*handoff.Queue, *miniredis.Miniredis, *ecdsa.PrivateKey) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	q := handoff.NewQueue(rdb, key.Public(), 6*time.Hour, time.Now)
	return q, mr, key
}

func deliver(t *testing.T, q *handoff.Queue) *sessiondb.Session {
	t.Helper()
	meta := &sessiondb.Session{
		ID: "01JZXHANDOFF00000000000001", ClientID: "01JZXCLIENT000000000000001",
		CorrelationID: "corr-h1", WebhookURL: "https://client.test/hook",
	}
	res := &pipeline.Result{
		SessionID: meta.ID, Outcome: "verified",
		Report: &pipeline.Report{SessionID: meta.ID, Outcome: "verified"},
		Credentials: []pipeline.ResultCredential{{
			QueryCredentialID: "pid", Format: "dc+sd-jwt", DoctypeOrVCT: "urn:eudi:pid:1",
			Claims: map[string]any{"family_name": canary},
		}},
	}
	qt.Assert(t, qt.IsNil(q.Deliver(context.Background(), meta, res)))
	return meta
}

// The contract: LPUSH id to vc:handoff:queue; envelope JSON at
// vc:handoff:payload:{id} with TTL ≤ configured (≤24h).
func TestEnvelopeShapeAndKeys(t *testing.T) {
	q, mr, key := setup(t)
	meta := deliver(t, q)

	ids, err := mr.List("vc:handoff:queue")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(ids, []string{meta.ID}))

	raw, err := mr.Get("vc:handoff:payload:" + meta.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(mr.TTL("vc:handoff:payload:"+meta.ID) > 0))

	var env struct {
		Version       int    `json:"version"`
		SessionID     string `json:"session_id"`
		ClientID      string `json:"client_id"`
		CorrelationID string `json:"correlation_id"`
		WebhookURL    string `json:"webhook_url"`
		ResultJWE     string `json:"result_jwe"`
		EnqueuedAt    string `json:"enqueued_at"`
		ExpiresAt     string `json:"expires_at"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &env)))
	qt.Assert(t, qt.Equals(env.Version, 1))
	qt.Assert(t, qt.Equals(env.SessionID, meta.ID))
	qt.Assert(t, qt.Equals(env.CorrelationID, "corr-h1"))
	qt.Assert(t, qt.Equals(env.WebhookURL, "https://client.test/hook"))

	// The envelope (and thus the store) never carries plaintext
	// attribute values…
	qt.Assert(t, qt.IsFalse(strings.Contains(raw, canary)))

	// …but the JWE decrypts (operator handoff key) to the full Result.
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"handoff-enc": key})
	plain, _, err := crypto.DecryptJWE(context.Background(), kp, "handoff-enc", []byte(env.ResultJWE))
	qt.Assert(t, qt.IsNil(err))
	var res pipeline.Result
	qt.Assert(t, qt.IsNil(json.Unmarshal(plain, &res)))
	qt.Assert(t, qt.Equals(res.Credentials[0].Claims["family_name"], canary))
}

// TestPollOnlySessionNotEnqueuedForDelivery: a session with no webhook URL
// (poll-only) still buffers its encrypted payload for polling, but is NOT
// pushed onto the delivery queue — nothing would consume it, and a consumer
// must never attempt a webhook POST for a session that has none.
func TestPollOnlySessionNotEnqueuedForDelivery(t *testing.T) {
	q, mr, _ := setup(t)
	meta := &sessiondb.Session{
		ID: "01JZXHANDOFF00000000000002", ClientID: "01JZXCLIENT000000000000001",
		CorrelationID: "corr-poll", WebhookURL: "", // poll-only
	}
	res := &pipeline.Result{
		SessionID: meta.ID, Outcome: "verified",
		Report: &pipeline.Report{SessionID: meta.ID, Outcome: "verified"},
		Credentials: []pipeline.ResultCredential{{
			QueryCredentialID: "pid", Format: "dc+sd-jwt", DoctypeOrVCT: "urn:eudi:pid:1",
			Claims: map[string]any{"family_name": canary},
		}},
	}
	qt.Assert(t, qt.IsNil(q.Deliver(context.Background(), meta, res)))

	// No delivery-queue entry for a poll-only session…
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:handoff:queue")))

	// …but its payload IS buffered (under TTL) for polling, with no plaintext leak.
	raw, err := mr.Get("vc:handoff:payload:" + meta.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(mr.TTL("vc:handoff:payload:"+meta.ID) > 0))
	qt.Assert(t, qt.IsFalse(strings.Contains(raw, canary)))

	var env struct {
		WebhookURL string `json:"webhook_url"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &env)))
	qt.Assert(t, qt.Equals(env.WebhookURL, ""))
}

// Hard cap: TTL is clamped to 24h no matter the config.
func TestTTLHardCap(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q := handoff.NewQueue(rdb, key.Public(), 48*time.Hour, time.Now) // misconfigured

	meta := deliver(t, q)
	qt.Assert(t, qt.IsTrue(mr.TTL("vc:handoff:payload:"+meta.ID) <= 24*time.Hour))
}
