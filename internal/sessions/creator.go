// Package sessions creates verification sessions: one oid4vp engine session
// (Valkey) + one metadata row (Postgres, claim-name-only domain). In prod the
// creation transport for eudi-api-management is an open item; tests
// call this in-process.
package sessions

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/digimaks/eudi-verifier-core/internal/policy"
	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"
)

// CreateInput is the in-process session-creation request (the internal HTTP
// transport is added onto this seam; routes/internal.go).
type CreateInput struct {
	ClientID        string
	CorrelationID   string
	Flow            oid4vp.Flow
	Query           dcql.Query
	Policy          policy.ClientPolicy
	WebhookURL      string
	RedirectURI     string // same-device client return target — becomes RequestSpec.ReturnURI
	Registration    rpcert.RegistrationRef
	WRPRC           []byte   // optional
	ExpectedOrigins []string // DCAPI

	// TTL is optional; zero = the Creator's configured default; clamped to ≤
	// the configured TTL — the oid4vp engine session's own expiry is fixed at
	// engine construction, so callers may shorten, never extend.
	TTL time.Duration
}

// Created is the result of Create: the one session id (Valkey + Postgres + the
// wallet URL), the request_uri the wallet fetches, the response endpoint the
// wallet/browser POSTs to, and the flow-specific invocation payload.
//
// ResponseURI: populated for EVERY flow
// with the same token-routed URL used internally (`{baseURL}/wallet/{token}/response`)
// — it is the actual wallet-facing transport endpoint, learned out-of-band by
// the caller. For same-device/cross-device this duplicates the response_uri
// claim already inside the signed request object (harmless). For DCAPI it is
// the ONLY way to learn the endpoint: oid4vp.NewSession's validateSpec rejects
// any DCAPI RequestSpec carrying a ResponseURI/ReturnURI (DCAPI responses
// return via the browser, correlated by origin+nonce, never by a response_uri
// claim — OID4VP Annex A), so the session itself carries no such claim.
type Created struct {
	SessionID   string
	RequestURI  string
	ResponseURI string
	Invocation  oid4vp.WalletInvocation

	// ExpiresAt is the effective (post-clamp) expiry: now + the effective TTL
	// Create computed from CreateInput.TTL — the same value
	// used for the metadata row's ExpiresAt, so a caller never has to
	// recompute the clamp/clock logic itself.
	ExpiresAt time.Time
}

// Creator is the in-process session-creation seam. It owns exactly one write
// to each of the three stores per Create: the oid4vp session (Valkey), the
// routing-token index (Valkey), and the metadata row (Postgres).
type Creator struct {
	engine  *oid4vp.Engine
	store   oid4vp.SessionStore // persists the engine-minted session (the Engine is stateless)
	db      sessiondb.MetadataStore
	tokens  RespondTokens // routing-token index (respondtokens.go)
	baseURL string
	ttl     time.Duration
	now     func() time.Time

	// dcapiMode is the deployment-wide ceiling on browser-request signing
	// (DCAPIMode* below). Zero value = DCAPIModeSigned: a Creator wired
	// without an explicit mode issues signed requests, so forgetting to pass
	// the deployment setting cannot silently drop the layer that lets a wallet
	// authenticate us.
	dcapiMode string
}

// The deployment-wide ceiling on how browser-based presentation requests are
// built. Signed requests carry our certificate chain and registration data;
// unsigned ones carry neither and leave the calling web origin as the only
// identity the wallet gets ([OID4VP §A.2] / [OID4VP §A.3.2]).
//
// DCAPIModeBoth is the only value under which a client's own policy is
// consulted at all. The other two fix the mode for every client, so a client
// recorded as unsigned inside a signed-only deployment still gets signed
// requests: a per-client choice can narrow, never widen.
const (
	DCAPIModeSigned   = "signed"
	DCAPIModeUnsigned = "unsigned"
	DCAPIModeBoth     = "both"
)

// WithDCAPIMode sets the deployment-wide browser-request ceiling. An
// unrecognised value is treated as signed — the safe reading, though the
// service rejects one at startup long before it reaches here.
func (c *Creator) WithDCAPIMode(mode string) *Creator {
	c.dcapiMode = mode
	return c
}

// EffectiveDCAPIMode reports the ceiling this Creator is operating under, so
// the service can state it at startup rather than leaving operators to infer
// it from behaviour.
func (c *Creator) EffectiveDCAPIMode() string {
	if c.dcapiMode == "" {
		return DCAPIModeSigned
	}
	return c.dcapiMode
}

// signedDCAPIRequired decides one session's browser-request mode: the
// deployment ceiling first, and only under DCAPIModeBoth the client's own
// recorded choice (which itself defaults to signed when nobody has decided).
func (c *Creator) signedDCAPIRequired(p policy.ClientPolicy) bool {
	switch c.dcapiMode {
	case DCAPIModeUnsigned:
		return false
	case DCAPIModeBoth:
		return p.RequireSignedDCAPI()
	default: // DCAPIModeSigned, and any value that got past startup validation
		return true
	}
}

// NewCreator wires a Creator. store is the oid4vp.SessionStore the service
// already owns (the Engine mints but does not persist sessions — the
// Engine is stateless, the service Save/Load/ConsumeOnces itself).
func NewCreator(engine *oid4vp.Engine, store oid4vp.SessionStore, db sessiondb.MetadataStore, tokens RespondTokens, baseURL string, ttl time.Duration, now func() time.Time) *Creator {
	return &Creator{engine: engine, store: store, db: db, tokens: tokens, baseURL: baseURL, ttl: ttl, now: now}
}

// Create mints a session.
// oid4vp.NewSession mints Session.ID INTERNALLY and validates
// RequestSpec.ResponseURI as given BEFORE that id exists, so ResponseURI
// cannot be templated with it (there is no post-hoc substitution). Create
// mints its OWN opaque routing token FIRST, builds ResponseURI from that
// token, calls NewSession, persists the engine-minted session, then — once
// the real session id is known — records the token → id mapping so the
// response handler (routes/wallet.go) can resolve it. The request.jwt route
// is UNAFFECTED: RequestURI below uses the real sess.ID, which IS known by the
// time Create returns.
//
// DCAPI: the token-routed responseURL is
// computed exactly as before and always returned via Created.ResponseURI, but
// it is passed to NewSession's RequestSpec.ResponseURI ONLY for
// same-device/cross-device — validateSpec rejects a DCAPI spec carrying
// ResponseURI/ReturnURI at all (DCAPI responses return via the browser, never
// a response_uri claim — OID4VP Annex A). The wallet-facing HTTP endpoint is
// unaffected: it is always `{baseURL}/wallet/{token}/response`, whether or not
// the engine session itself knows about it.
func (c *Creator) Create(ctx context.Context, in CreateInput) (*Created, error) {
	if in.Registration == (rpcert.RegistrationRef{}) {
		// ARF RPRC_19a data is ALWAYS embedded (request without
		// RegistrationRef is impossible) — tests use a fixture.
		in.Registration = rpcert.RegistrationRef{
			ClientName: "Test Client", ClientID: in.ClientID,
			RegistryURI: "https://registrar.test", IntendedUseID: "test-intended-use",
		}
	}
	// [OID4VP §8.2]: return_uri (the same-device browser redirect target) is
	// same-device only — NewSession rejects it for cross-device/DCAPI
	// (ErrSpec). Apply the caller's RedirectURI to the spec ONLY for
	// same-device; the metadata row records it regardless (harmless there).
	returnURI := ""
	if in.Flow == oid4vp.SameDevice {
		returnURI = in.RedirectURI
	}
	// The caller may shorten the configured default TTL, never
	// extend it (CreateInput.TTL doc comment) — this affects only the
	// routing-token TTL and the metadata row's ExpiresAt below; the oid4vp
	// engine session's own expiry is fixed at engine construction (Config
	// .SessionTTL, see app.go init) and is untouched here.
	ttl := c.ttl
	if in.TTL > 0 && in.TTL < c.ttl {
		ttl = in.TTL
	}
	token, err := newRespondToken()
	if err != nil {
		return nil, fmt.Errorf("sessions: respond token: %w", err)
	}
	responseURL := fmt.Sprintf("%s/wallet/%s/response", c.baseURL, token) // token, not the (not-yet-minted) session id
	specResponseURI := responseURL
	if in.Flow == oid4vp.DCAPI {
		specResponseURI = "" // DCAPI: NewSession rejects any ResponseURI (OID4VP Annex A)
	}
	sess, inv, err := c.engine.NewSession(ctx, oid4vp.RequestSpec{
		Query:           in.Query,
		Flow:            in.Flow,
		ResponseURI:     specResponseURI,
		ReturnURI:       returnURI, // [OID4VP §8.2] same-device only (ErrSpec otherwise)
		Registration:    in.Registration,
		WRPRC:           in.WRPRC,
		ExpectedOrigins: in.ExpectedOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("sessions: engine: %w", err)
	}
	// NewSession always builds the SIGNED browser request member. Where the
	// deployment permits it and this client is recorded as unsigned, replace it
	// with the unsigned variant: the same request parameters without our
	// client_id, expected_origins and signature (OID4VP Annex A.3.1).
	//
	// Only the member handed to the browser changes. The session keeps its
	// expected origins either way, because the origin check this service makes
	// when the response comes back is ours and is required regardless of what
	// the wallet was told ([OID4VP §14.9]) — under an unsigned request the
	// wallet simply never sees that list to check it too.
	if in.Flow == oid4vp.DCAPI && !c.signedDCAPIRequired(in.Policy) {
		member, uerr := c.engine.DCAPIUnsignedRequest(sess)
		if uerr != nil {
			return nil, fmt.Errorf("sessions: unsigned dcapi request: %w", uerr)
		}
		inv.DCAPI = member
	}
	// The Engine is stateless: the service persists the session it minted.
	if err := c.store.Save(ctx, sess); err != nil {
		return nil, fmt.Errorf("sessions: save session: %w", err)
	}
	if err := c.tokens.Put(ctx, token, sess.ID, ttl); err != nil {
		return nil, fmt.Errorf("sessions: respond token: %w", err)
	}

	pol, err := json.Marshal(in.Policy)
	if err != nil {
		return nil, err
	}
	flowName := map[oid4vp.Flow]string{
		oid4vp.SameDevice: "same_device", oid4vp.CrossDevice: "cross_device", oid4vp.DCAPI: "dcapi",
	}[in.Flow]
	expiresAt := c.now().Add(ttl)
	if _, err := c.db.Create(ctx, sessiondb.CreateInput{
		ID: sess.ID, ClientID: in.ClientID, CorrelationID: in.CorrelationID,
		Flow: flowName, Policy: pol, WebhookURL: in.WebhookURL,
		RedirectURI: in.RedirectURI, ExpiresAt: expiresAt,
	}); err != nil {
		return nil, fmt.Errorf("sessions: metadata: %w", err)
	}

	return &Created{
		SessionID:   sess.ID,
		RequestURI:  fmt.Sprintf("%s/wallet/%s/request.jwt", c.baseURL, sess.ID),
		ResponseURI: responseURL,
		Invocation:  inv,
		ExpiresAt:   expiresAt,
	}, nil
}
