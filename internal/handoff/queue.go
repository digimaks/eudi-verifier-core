// Package handoff is eudi-verifier-core's side of result delivery:
// the encrypted result buffers in Valkey under a hard TTL; eudi-api-management
// consumes the queue and does webhook delivery + retries.
// eudi-verifier-core NEVER retries and NEVER persists attribute values.
//
// eudi-verifier-core is the sole WRITER of vc:handoff:queue / vc:handoff:payload:{id}
// (the Valkey key & queue contract); it never reads its own payloads
// back, so the envelope is not an untrusted-input parser here (the only
// decoder of these bytes is a separate service).
package handoff

import (
	"context"
	stdcrypto "crypto"
	"encoding/json"
	"fmt"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
	"github.com/dativa-lv/eudi-verifier-core/internal/pipeline"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessiondb"
	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/redis/go-redis/v9"
)

const (
	queueKey   = handoffwire.QueueKey
	payloadKey = handoffwire.PayloadKeyFmt
	hardCap    = 24 * time.Hour // hard TTL ≤ 24h, configurable down only
)

// Envelope is the consumption contract (the Valkey key & queue
// contract). Every field EXCEPT ResultJWE is structural/identifying only — no
// attribute value ever appears here. ResultJWE is a
// compact JWE (ECDH-ES + A256GCM to the operator handoff-enc key) whose
// plaintext is the pipeline.Result; the claim VALUES live only inside that
// ciphertext.
//
// Envelope is a type alias of handoffwire.Envelope (promoted to the
// importable handoffwire cross-service contract): this
// package remains the sole writer, eudi-api-management the sole reader.
type Envelope = handoffwire.Envelope

// Queue is the production pipeline.ResultSink: it encrypts the result to the
// operator handoff key and buffers it in Valkey for delivery.
type Queue struct {
	rdb    redis.UniversalClient
	encKey stdcrypto.PublicKey // operator handoff-enc public key
	ttl    time.Duration
	now    func() time.Time
	prefix keyspace.Prefix
}

// NewQueue builds the handoff queue. ttl is clamped to the 24h hard
// cap: a misconfiguration that asks for longer (or a non-positive TTL) fails
// closed to 24h, never longer — the encrypted result must not outlive the cap.
func NewQueue(rdb redis.UniversalClient, encKey stdcrypto.PublicKey, ttl time.Duration, now func() time.Time) *Queue {
	if ttl <= 0 || ttl > hardCap {
		ttl = hardCap
	}
	return &Queue{rdb: rdb, encKey: encKey, ttl: ttl, now: now}
}

// WithKeyPrefix sets the deployment key prefix (see keyspace) applied to the
// queue and payload keys, and returns the Queue for chaining.
func (q *Queue) WithKeyPrefix(p keyspace.Prefix) *Queue {
	q.prefix = p
	return q
}

// Deliver implements pipeline.ResultSink. // ARF AS-RP-51-008: forward only the
// presented attributes; expiry of the payload = delivery failure surfaced
// as err:webhook:delivery-failed — never a DB fallback.
func (q *Queue) Deliver(ctx context.Context, meta *sessiondb.Session, res *pipeline.Result) error {
	plain, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("handoff: marshal result: %w", err)
	}
	jwe, err := crypto.EncryptJWE(q.encKey, nil, plain)
	zero(plain) // plaintext buffer gone as soon as it is encrypted
	if err != nil {
		return fmt.Errorf("handoff: encrypt: %w", err)
	}
	env := Envelope{
		Version: 1, SessionID: meta.ID, ClientID: meta.ClientID,
		CorrelationID: meta.CorrelationID, WebhookURL: meta.WebhookURL,
		ResultJWE: string(jwe), EnqueuedAt: q.now(), ExpiresAt: q.now().Add(q.ttl),
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("handoff: marshal envelope: %w", err)
	}
	// Payload FIRST, then the queue id, in one MULTI/EXEC so a consumer never
	// sees an id whose payload has not landed yet (both commit atomically).
	// The queue id drives WEBHOOK delivery; a poll-only session (no webhook
	// URL) is not enqueued for delivery — its payload is still buffered above
	// so the client can retrieve the result by polling until the TTL elapses.
	pipe := q.rdb.TxPipeline()
	pipe.Set(ctx, q.prefix.Key(fmt.Sprintf(payloadKey, meta.ID)), envJSON, q.ttl)
	if meta.WebhookURL != "" {
		pipe.LPush(ctx, q.prefix.Key(queueKey), meta.ID)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("handoff: enqueue: %w", err)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
