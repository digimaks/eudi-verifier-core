package valkeystore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dativa-lv/eudi-verifier-core/internal/valkeystore"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	"github.com/gmb-eudi/go-oid4vp/storetest"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
)

// testRegistration returns a valid ARF RPRC_19a registration reference.
// oid4vp.Session embeds rpcert.RegistrationRef directly and its MarshalJSON
// rejects an incomplete/zero-value reference
// ("always present" is enforced structurally, not just documented) — so
// every Session built in these tests needs one, unlike bare literals which
// only set ID/ExpiresAt.
func testRegistration(t *testing.T, id string) rpcert.RegistrationRef {
	t.Helper()
	reg, err := rpcert.NewRegistrationRef("Example Verifier", "verifier.example.com", "https://registry.example.com/api", "intended-use-"+id)
	qt.Assert(t, qt.IsNil(err))
	return reg
}

func newStore(t *testing.T) (*valkeystore.Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return valkeystore.New(rdb, 5*time.Minute, time.Now), mr
}

// The Valkey impl passes the reusable contract
// (Save/Load roundtrip, unknown id, expiry, race-proof ConsumeOnce).
func TestSessionStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) oid4vp.SessionStore {
		s, _ := newStore(t)
		return s
	})
}

// ConsumeOnce linearizes on SET NX: exactly one of N concurrent consumers wins.
func TestConsumeOnceConcurrent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	sess := &oid4vp.Session{ID: "01JZX0SESSION0000000000001", ExpiresAt: time.Now().Add(time.Minute), Registration: testRegistration(t, "01JZX0SESSION0000000000001")}
	qt.Assert(t, qt.IsNil(s.Save(ctx, sess)))

	const n = 32
	var wg sync.WaitGroup
	wins := make(chan struct{}, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeOnce(ctx, sess.ID); err == nil {
				wins <- struct{}{}
			} else if !errors.Is(err, oid4vp.ErrSessionConsumed) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	close(wins)
	qt.Assert(t, qt.Equals(len(wins), 1))
}

func TestMarkRequestObjectServedSingleUse(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	sess := &oid4vp.Session{ID: "01JZX0SESSION0000000000002", ExpiresAt: time.Now().Add(time.Minute), Registration: testRegistration(t, "01JZX0SESSION0000000000002")}
	qt.Assert(t, qt.IsNil(s.Save(ctx, sess)))

	first, err := s.MarkRequestObjectServed(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(first))

	second, err := s.MarkRequestObjectServed(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(second))
}

func TestSaveResponseCodeKeyAndTTL(t *testing.T) {
	s, mr := newStore(t)
	ctx := context.Background()
	qt.Assert(t, qt.IsNil(s.SaveResponseCode(ctx, "code-abc", "01JZX0SESSION0000000000003")))

	// Locked contract: vc:respcode:{code} → sessionID, TTL = ResponseCodeTTL.
	got, err := mr.Get("vc:respcode:code-abc")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got, "01JZX0SESSION0000000000003"))
	qt.Assert(t, qt.IsTrue(mr.TTL("vc:respcode:code-abc") > 0))
}

// failingClient wraps a real redis.UniversalClient and, once armed, fails
// exactly the next Set call — used to simulate a transient Valkey error on
// the Save inside ConsumeOnce, after the SetNX marker claim already
// succeeded (code-review finding: partial-failure lockout).
type failingClient struct {
	redis.UniversalClient
	mu    sync.Mutex
	armed bool
}

func (f *failingClient) armFailNextSet() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed = true
}

func (f *failingClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	fail := f.armed
	f.armed = false
	f.mu.Unlock()
	if fail {
		cmd := redis.NewStatusCmd(ctx)
		cmd.SetErr(errInjectedSetFailure)
		return cmd
	}
	return f.UniversalClient.Set(ctx, key, value, expiration)
}

var errInjectedSetFailure = errors.New("valkeystore_test: injected Set failure")

// TestConsumeOnceRollsBackMarkerOnSaveFailure is the code-review regression
// test for the partial-failure lockout: SetNX on vc:session:{id}:consumed
// succeeds, but the follow-up Save (persisting Consumed=true onto the
// session) fails. Without the rollback, the marker stays set for its full
// TTL and every subsequent ConsumeOnce — including a legitimate wallet
// retry — would wrongly see ErrSessionConsumed, indistinguishable from an
// actual replay.
func TestConsumeOnceRollsBackMarkerOnSaveFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	fc := &failingClient{UniversalClient: rdb}
	s := valkeystore.New(fc, 5*time.Minute, time.Now)

	ctx := context.Background()
	sess := &oid4vp.Session{ID: "01JZX0SESSION0000000000005", ExpiresAt: time.Now().Add(time.Minute), Registration: testRegistration(t, "01JZX0SESSION0000000000005")}
	qt.Assert(t, qt.IsNil(s.Save(ctx, sess)))

	fc.armFailNextSet()
	_, err := s.ConsumeOnce(ctx, sess.ID)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.IsFalse(errors.Is(err, oid4vp.ErrSessionConsumed)))
	qt.Assert(t, qt.IsTrue(errors.Is(err, errInjectedSetFailure)))

	// The marker must have been rolled back: a legitimate retry succeeds
	// rather than being permanently locked out as a false replay.
	got, err := s.ConsumeOnce(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(got.Consumed))

	// And now that it really is consumed, a further retry correctly fails.
	_, err = s.ConsumeOnce(ctx, sess.ID)
	qt.Assert(t, qt.IsTrue(errors.Is(err, oid4vp.ErrSessionConsumed)))
}

func TestSessionExpiryHonored(t *testing.T) {
	s, mr := newStore(t)
	ctx := context.Background()
	sess := &oid4vp.Session{ID: "01JZX0SESSION0000000000004", ExpiresAt: time.Now().Add(time.Minute), Registration: testRegistration(t, "01JZX0SESSION0000000000004")}
	qt.Assert(t, qt.IsNil(s.Save(ctx, sess)))

	mr.FastForward(6 * time.Minute) // beyond store TTL
	_, err := s.Load(ctx, sess.ID)
	qt.Assert(t, qt.IsTrue(errors.Is(err, oid4vp.ErrSessionNotFound)))
}
