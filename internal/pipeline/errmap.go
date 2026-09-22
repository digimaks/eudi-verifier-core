package pipeline

import (
	"context"
	"errors"

	trust "github.com/gmb-eudi/go-eudi-trust"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// CodeForError maps library sentinels to the error taxonomy — the
// ONE table (extended by errclass.go for per-check attribution).
// Unknown errors map to err:pipeline:internal (500) — never leak raw text as
// a code.
func CodeForError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, oid4vp.ErrSessionNotFound):
		return "err:session:not-found"
	case errors.Is(err, oid4vp.ErrSessionConsumed):
		return "err:session:consumed"
	case errors.Is(err, trust.ErrCacheExpired):
		return "err:trust:anchor-unavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "err:pipeline:internal"
	default:
		return "err:pipeline:internal"
	}
}
