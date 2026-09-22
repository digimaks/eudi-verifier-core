package sessions

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
)

func newTokens(t *testing.T) (*ValkeyRespondTokens, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewValkeyRespondTokens(rdb), mr
}

func TestRespondTokenPutResolve(t *testing.T) {
	tk, _ := newTokens(t)
	token, err := newRespondToken()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(len(token) >= 22)) // 128-bit base64url raw

	qt.Assert(t, qt.IsNil(tk.Put(t.Context(), token, "session-id-1", time.Minute)))

	got, err := tk.Resolve(t.Context(), token)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got, "session-id-1"))
}

func TestRespondTokenUnknownFailsClosed(t *testing.T) {
	tk, _ := newTokens(t)
	_, err := tk.Resolve(t.Context(), "no-such-token")
	qt.Assert(t, qt.ErrorIs(err, ErrRespondTokenNotFound))
}

func TestRespondTokenExpires(t *testing.T) {
	tk, mr := newTokens(t)
	token, err := newRespondToken()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(tk.Put(t.Context(), token, "session-id-2", time.Minute)))

	mr.FastForward(2 * time.Minute) // past the TTL

	_, err = tk.Resolve(t.Context(), token)
	qt.Assert(t, qt.ErrorIs(err, ErrRespondTokenNotFound))
}

// newRespondToken must draw fresh entropy each call ([OID4VP §5.2] nonce entropy).
func TestRespondTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok, err := newRespondToken()
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsFalse(seen[tok]))
		seen[tok] = true
	}
}
