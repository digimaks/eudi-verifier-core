package routes

import (
	"encoding/json"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
	"github.com/gmb-lib/go-platform-kit/propagation"

	"azugo.io/azugo"
	"go.uber.org/zap"
)

// bindWallet registers the wallet-facing endpoints. Wallet boundary =
// OID4VP error shapes, never problem+json.
func bindWallet(a azugo.Router, r *router) {
	a.Get("/wallet/{sessionID}/request.jwt", r.requestObject)
	a.Post("/wallet/{sessionID}/response", r.walletResponse)
}

// walletError renders any failure as an OID4VP error response
// ([OID4VP §8.5]).
// The internal err:domain:reason code is logged by the caller for metrics.
//
// Two vocabularies meet here. go-oid4vp owns the protocol-level sentinels —
// session lifecycle, decrypt, state and nonce binding — and maps them itself.
// The verification pipeline speaks its own err:domain:reason codes, which the
// engine has never seen and cannot map; left to it they collapse to
// 500 server_error, announcing a routine and correct refusal as a server fault.
// So a refused verification is classified here first, and everything else still
// delegates.
func (r *router) walletError(ctx *azugo.Context, err error) {
	status, body, ok := verificationOutcome(err)
	if !ok {
		status, body = r.Engine().ErrorResponse(err)
	}
	ctx.StatusCode(status)
	ctx.ContentType("application/json")
	ctx.Raw(body)
	ctx.Log().Warn("wallet request failed", zap.Error(err)) // redaction active
}

// recoverCorrelation implements correlation recovery: wallet calls
// carry no correlation header — recover the id minted at session creation by
// session lookup and re-inject it via kit propagation so pipeline logs,
// traces, and outbound calls carry it.
func (r *router) recoverCorrelation(ctx *azugo.Context, sessionID string) {
	meta, err := r.SessionDB().Get(ctx, sessionID)
	if err != nil {
		return // unknown session — the handler's own load will produce the error
	}
	ctx.SetContext(propagation.WithCorrelationID(ctx.Context(), meta.CorrelationID))
	if err := ctx.AddLogFields(
		zap.String("correlation_id", meta.CorrelationID),
		zap.String("session_id", sessionID),
	); err != nil {
		ctx.Log().Warn("add correlation log fields failed", zap.Error(err))
	}
}

// requestObject serves the signed Request Object by reference.
// RFC 9101 (JAR) via request_uri; [OID4VP §5.10]. Single-use is this service's
// own hardening — OID4VP states no such requirement.
func (r *router) requestObject(ctx *azugo.Context) {
	id := ctx.Params.String("sessionID")
	r.recoverCorrelation(ctx, id)

	sess, err := r.Sessions().Load(ctx, id)
	if err != nil {
		r.walletError(ctx, err)
		return
	}
	first, err := r.Sessions().MarkRequestObjectServed(ctx, id)
	if err != nil {
		r.walletError(ctx, err)
		return
	}
	if !first {
		r.walletError(ctx, oid4vp.ErrRequestURIConsumed) // sentinel
		return
	}
	jar, err := r.Engine().RequestObjectJWT(ctx, sess)
	if err != nil {
		r.walletError(ctx, err)
		return
	}
	if err := r.SessionDB().SetStatus(ctx, id, "wallet_engaged"); err != nil {
		ctx.Log().Warn("set status wallet_engaged failed", zap.Error(err))
	}
	ctx.ContentType("application/oauth-authz-req+jwt") // [OID4VP §5.10.1] response media type
	ctx.Raw(jar)
}

// Processor is the seam between the transport handler and verification.
// minimalProcessor shipped pipeline step 1 only; the full ten-step pipeline
// swaps in behind the same seam.
type Processor interface {
	Process(ctx *azugo.Context, sess *oid4vp.Session) (redirectURI string, err error)
}

// Processor returns the installed response-endpoint processor. It is stored
// untyped on App (no app→routes import cycle) and asserted back here.
func (r *router) Processor() Processor { return r.WalletProcessor().(Processor) }

// walletResponse is the direct_post.jwt response endpoint.
// [OID4VP §8.2]: one-time consume, decrypt, verify; returns {redirect_uri}.
//
// The {sessionID} path segment here is actually the opaque routing token minted
// by sessions.Creator, NOT oid4vp.Session.ID — NewSession mints that
// internally, after ResponseURI is already validated, so ResponseURI could
// never literally contain it. Resolve token → real session id FIRST; every
// downstream call (SessionDB, SessionStore) uses the real id. The
// GET .../request.jwt handler above is UNAFFECTED — it already receives the
// real, engine-minted id.
func (r *router) walletResponse(ctx *azugo.Context) {
	token := ctx.Params.String("sessionID")
	id, err := r.RespondTokens().Resolve(ctx, token)
	if err != nil {
		// An unknown/expired routing token is, from the wallet's point of
		// view, an unknown session ([OID4VP §8.2]) — render the 404 session-not-found
		// OID4VP error, not a 500. Log the real cause for our own metrics.
		ctx.Log().Warn("respond token resolve failed", zap.Error(err))
		r.walletError(ctx, oid4vp.ErrSessionNotFound)
		return
	}
	r.recoverCorrelation(ctx, id)

	// Body cap BEFORE any parsing.
	if len(ctx.Body.Bytes()) > r.Config().MaxResponseBodyBytes {
		r.walletError(ctx, oid4vp.ErrBodyTooLarge) // oversized-body sentinel
		return
	}
	sess, err := r.Sessions().ConsumeOnce(ctx, id) // atomic single consume
	if err != nil {
		r.walletError(ctx, err)
		return
	}
	redirect, err := r.Processor().Process(ctx, sess)
	if err != nil {
		if serr := r.SessionDB().SetStatus(ctx, id, "failed"); serr != nil {
			ctx.Log().Warn("set status failed failed", zap.Error(serr))
		}
		r.walletError(ctx, err)
		return
	}
	ctx.ContentType("application/json")
	if redirect == "" {
		ctx.Raw([]byte("{}"))
		return
	}
	out, _ := json.Marshal(map[string]string{"redirect_uri": redirect})
	ctx.Raw(out)
}
