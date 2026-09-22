package pipeline

import (
	"context"

	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"
)

// Finalize delivers the result to the sink, then disposes of session-scoped
// Valkey state, and best-effort zeroes attribute values in memory
// (ARF AS-RP-51-011/013). Called by step 10 on success and by the
// processor on failure (report-only result, no credentials).
//
// Disposal is flow- AND outcome-aware (replacing the
// original design where Finalize unconditionally deleted the session and the
// processor separately re-Saved it afterward — a sequence that silently lost
// the sticky vc:session:{id}:consumed marker, reopening the [OID4VP §14.2] replay
// window for the very case, same-device, that most needs it closed). A
// SUCCESSFUL (res.Outcome == "verified") same-device run minted an [OID4VP §8.2]
// response_code (pc.ResponseCode != "") that must later be redeemed via
// Engine.ConsumeResponseCode, which needs the session record back — so
// Finalize re-Saves it INSTEAD of deleting it. oid4vp.Session is
// protocol-only (nonce/state/query/ephemeral key/response_code — never an
// attribute value), so keeping it alive does not violate the no-attribute-value guarantee.
// Crucially, Save never touches the consumed marker (only ConsumeOnce's SetNX
// sets it, only DeleteSession clears it — valkeystore/store.go), so the
// marker survives and a replay of the same routing token still hits
// ErrSessionConsumed at ConsumeOnce, before the pipeline runs again. Every
// other case — cross-device/dcapi success (no code minted) and ANY failure,
// same-device included (a mid-pipeline failure never got this far, so no code
// was ever persisted to lose) — deletes the session exactly as before.
func Finalize(ctx context.Context, pc *PipelineContext, res *Result) error {
	// Zero attribute-carrying memory on EVERY return path
	// (ARF AS-RP-51-011/013), regardless of whether Deliver or the
	// Save/DeleteSession disposal below fails: a transient sink or cleaner error
	// must never leave presented attribute values lingering in memory. Deferred
	// so it runs after the body (Deliver still sees intact data), on success and
	// on any error return alike.
	defer Zero(pc, res)
	if err := pc.Sink.Deliver(ctx, pc.Meta, res); err != nil {
		return err
	}
	if res != nil && res.Outcome == "verified" && pc.ResponseCode != "" {
		if err := pc.Cleaner.Save(ctx, pc.Session); err != nil {
			return err
		}
	} else if err := pc.Cleaner.DeleteSession(ctx, pc.SessionID); err != nil {
		return err
	}
	return nil
}

// Zero overwrites attribute-carrying memory. Best-effort (Go copies freely;
// this shrinks the exposure window, it cannot guarantee absence).
func Zero(pc *PipelineContext, res *Result) {
	for _, p := range pc.Presentations {
		zeroBytes(p.Payload)
	}
	for _, cred := range pc.Credentials {
		zeroBytes(cred.Pres.Payload)
		if cred.SD != nil {
			clearMap(cred.SD.Claims)
		}
		if cred.MD != nil {
			for _, ns := range cred.MD.Namespaces {
				clearMap(ns)
			}
		}
	}
	if res != nil {
		for i := range res.Credentials {
			clearMap(res.Credentials[i].Claims)
		}
	}
	zeroBytes(pc.Raw.Body)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func clearMap(m map[string]any) {
	for k := range m {
		m[k] = nil
		delete(m, k)
	}
}

// nopSink accepts and drops results — wiring placeholder until the
// Valkey handoff queue. Never ships enabled in prod config.
type nopSink struct{}

// NopSink returns the placeholder ResultSink (drops results) used until the
// Valkey handoff queue lands.
func NopSink() ResultSink { return nopSink{} }

func (nopSink) Deliver(context.Context, *sessiondb.Session, *Result) error { return nil }
