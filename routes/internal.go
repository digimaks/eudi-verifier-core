package routes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	verifiercore "github.com/dativa-lv/eudi-verifier-core"
	"github.com/dativa-lv/eudi-verifier-core/internal/policy"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessions"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// bindInternal registers the cluster-internal session-creation API (the
// creation transport for eudi-api-management). Init only calls this when
// Configuration .InternalAPIToken is non-empty — fail closed: an unconfigured
// deployment exposes no /internal/v1 surface at all, not an unauthenticated one.
func bindInternal(a *verifiercore.App, r *router) {
	configuredHash := sha256.Sum256([]byte(a.Config().InternalAPIToken))
	g := a.Group("/internal/v1")
	g.Use(internalBearerAuth(configuredHash))
	g.Post("/sessions", r.internalCreateSession)
	g.Delete("/sessions/{sessionID}", r.internalDeleteSession)
	g.Get("/sessions/{sessionID}/report", r.internalSessionReport)
	g.Get("/trust-status", r.internalTrustStatus)
}

// internalBearerAuth compares sha256(presented) against sha256(configured)
// with crypto/subtle.ConstantTimeCompare — hashing first so the comparison
// itself is fixed-length (32 bytes either side) and never short-circuits on
// the presented token's own length. Mismatch or a missing/malformed
// Authorization header renders the same 401 problem (pkerrors; this service
// keeps PublicErrors=false — routes/router.go/app.go — so the internal
// envelope, not a public-safe one, is what a caller sees).
func internalBearerAuth(configuredHash [sha256.Size]byte) azugo.RequestHandlerFunc {
	const scheme = "Bearer "
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			presented, ok := strings.CutPrefix(ctx.Header.Get(fasthttp.HeaderAuthorization), scheme)
			if !ok {
				presented = "" // no/malformed scheme: compare against empty, never a partial header value
			}
			presentedHash := sha256.Sum256([]byte(presented))
			if subtle.ConstantTimeCompare(presentedHash[:], configuredHash[:]) != 1 {
				ctx.Error(pkerrors.HTTP("internal-api", "unauthorized"))
				return
			}
			next(ctx)
		}
	}
}

// internalFlows maps the wire flow name to the oid4vp.Flow the engine uses
// (the same underscore/hyphen split internal/sessions/creator.go's flowName
// map already makes going the other direction).
var internalFlows = map[string]oid4vp.Flow{
	"same_device":  oid4vp.SameDevice,
	"cross_device": oid4vp.CrossDevice,
	"dcapi":        oid4vp.DCAPI,
}

// internalCreateRequest is the wire body of POST /internal/v1/sessions.
type internalCreateRequest struct {
	ClientID        string                 `json:"client_id"`
	CorrelationID   string                 `json:"correlation_id"`
	Flow            string                 `json:"flow"` // same_device|cross_device|dcapi
	DCQLQuery       json.RawMessage        `json:"dcql_query"`
	Policy          json.RawMessage        `json:"policy"`
	WebhookURL      string                 `json:"webhook_url"`
	RedirectURI     string                 `json:"redirect_uri"`
	Registration    rpcert.RegistrationRef `json:"registration"` // {name,sub,registry_uri,intended_use_id}
	WRPRC           []byte                 `json:"wrprc"`        // base64 (encoding/json []byte default)
	ExpectedOrigins []string               `json:"expected_origins"`
	TTLSeconds      int                    `json:"ttl_seconds"`
}

// internalCreateResponse is the wire body of a successful create (201).
type internalCreateResponse struct {
	SessionID   string    `json:"session_id"`
	ExpiresAt   time.Time `json:"expires_at"` // effective (post-clamp): sessions.Created.ExpiresAt
	RequestURI  string    `json:"request_uri"`
	ResponseURI string    `json:"response_uri"`
	Invocation  struct {
		SchemeURI    string          `json:"scheme_uri,omitempty"`
		WalletURL    string          `json:"wallet_url"`
		QRPayload    string          `json:"qr_payload,omitempty"`
		DCAPIRequest json.RawMessage `json:"dc_api_request,omitempty"`
	} `json:"invocation"`
}

// buildCreateInput validates the request body and maps it onto
// sessions.CreateInput. Every failure is fail-closed (422 via
// azugo.ParamInvalidError, or 400 via azugo.ParamRequiredError for an absent
// field) — plain built-in Azugo error types, deliberately not a new err:
// taxonomy code (none fit, and this task does not mint one). Registration is
// checked explicitly BEFORE Create ever runs, because Create silently
// substitutes a TEST FIXTURE RegistrationRef for the zero value — that branch
// must be unreachable from a real caller.
func buildCreateInput(req internalCreateRequest) (sessions.CreateInput, error) {
	switch {
	case req.ClientID == "":
		return sessions.CreateInput{}, azugo.ParamRequiredError{Name: "client_id"}
	case req.CorrelationID == "":
		return sessions.CreateInput{}, azugo.ParamRequiredError{Name: "correlation_id"}
	}

	flow, ok := internalFlows[req.Flow]
	if !ok {
		return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "flow", Tag: "oneof=same_device cross_device dcapi"}
	}

	if len(req.DCQLQuery) == 0 {
		return sessions.CreateInput{}, azugo.ParamRequiredError{Name: "dcql_query"}
	}
	// [OID4VP §6]: dcql.Parse is strict (unknown members rejected, UseNumber) —
	// the same parser go-dcql's own query-authoring boundary uses.
	q, err := dcql.Parse(req.DCQLQuery)
	if err != nil {
		return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "dcql_query", Tag: "dcql", Err: err}
	}
	// [OID4VP §6] / [OID4VP §7] semantic rules (Query.Validate): a query that parses but is
	// semantically invalid (empty credentials, unsupported format, …) is the
	// CALLER's error — reject it 422 here rather than letting oid4vp.NewSession's
	// own Validate call wrap it as ErrSpec and surface as a 500 (eudi-api-management
	// must be able to tell "bad request" from "eudi-verifier-core is broken"). The
	// rendered SafeError is the field/tag template only — no query contents
	// reach the response body.
	if err := q.Validate(); err != nil {
		return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "dcql_query", Tag: "dcql", Err: err}
	}

	// Browser-mediated requests carry the set of web origins allowed to invoke
	// them, and the engine enforces the same rules again when it assembles the
	// session. Checked here for the same reason the query is: a caller's
	// mistake must arrive as a caller's error, not as an unclassified fault of
	// this service. Origins are meaningful only for the browser-mediated flow,
	// so supplying them elsewhere is a caller error too rather than something
	// to ignore silently.
	if flow == oid4vp.DCAPI {
		if len(req.ExpectedOrigins) == 0 {
			return sessions.CreateInput{}, azugo.ParamRequiredError{Name: "expected_origins"}
		}
		for _, o := range req.ExpectedOrigins {
			if err := validWebOrigin(o); err != nil {
				return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "expected_origins", Tag: "origin", Err: err}
			}
		}
	} else if len(req.ExpectedOrigins) > 0 {
		return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "expected_origins", Tag: "dcapi_only"}
	}

	// The same-device return target. The engine REQUIRES it for that flow and
	// nothing here checked it, so an omitted one reached the engine and came
	// back as an unclassified fault — a 500 for what is plainly the caller's
	// missing field. Same reason the query and the origins are checked here.
	//
	// Deliberately NOT rejected on the other flows, even though the engine
	// refuses it there: the creator drops it before the engine ever sees it and
	// the session's metadata row keeps it, which is intended. Adding strictness
	// a caller does not already honour is exactly what left the redirect flows
	// unusable once origins became settable.
	if flow == oid4vp.SameDevice {
		if req.RedirectURI == "" {
			return sessions.CreateInput{}, azugo.ParamRequiredError{Name: "redirect_uri"}
		}
		if err := validHTTPSURL(req.RedirectURI); err != nil {
			return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "redirect_uri", Tag: "https_url", Err: err}
		}
	}

	if err := req.Registration.Validate(); err != nil {
		return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "registration", Tag: "rprc19a", Err: err}
	}

	var pol policy.ClientPolicy
	if len(req.Policy) > 0 {
		if err := json.Unmarshal(req.Policy, &pol); err != nil {
			return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "policy", Tag: "json", Err: err}
		}
	}

	if req.TTLSeconds < 0 {
		return sessions.CreateInput{}, azugo.ParamInvalidError{Name: "ttl_seconds", Tag: "gte=0"}
	}

	return sessions.CreateInput{
		ClientID: req.ClientID, CorrelationID: req.CorrelationID,
		Flow: flow, Query: *q, Policy: pol,
		// webhook_url is optional: an empty value creates a poll-only session
		// whose result is retrieved via GET /sessions/{id}, never delivered by
		// webhook.
		WebhookURL: req.WebhookURL, RedirectURI: req.RedirectURI,
		Registration:    req.Registration,
		WRPRC:           req.WRPRC,
		ExpectedOrigins: req.ExpectedOrigins,
		TTL:             time.Duration(req.TTLSeconds) * time.Second,
	}, nil
}

// errNotAWebOrigin states the whole rule, so a rejection is self-explaining in
// the log line that carries it.
var errNotAWebOrigin = errors.New("must be an https origin — scheme://host[:port] with no path, query, fragment or userinfo")

// errNotAnHTTPSURL states the whole rule, for the same reason.
var errNotAnHTTPSURL = errors.New("must be an absolute https URL")

// validHTTPSURL accepts an absolute https URL — unlike an origin, a path and a
// query are expected here, since it is a page the browser is sent back to.
//
// It states the presentation engine's rule for the same value, and the point of
// restating it is that a check LOOSER than the engine's would hand back the
// unclassified fault this exists to prevent. Anything the engine would refuse
// must be refused here first.
func validHTTPSURL(raw string) error {
	if raw == "" {
		return errNotAnHTTPSURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errNotAnHTTPSURL
	}
	if u.Scheme != "https" || u.Host == "" {
		return errNotAnHTTPSURL
	}
	return nil
}

// validWebOrigin accepts exactly a web origin. Kept deliberately strict:
// origins are compared literally when the browser's calling origin is checked
// against them, so a value that merely looks close (a trailing slash, a path, a
// bare hostname) would be accepted at configuration time and then never match
// at run time.
//
// NOTE: this rule is also enforced by the presentation engine when it builds
// the session, and by the registration service when the origins are set. Three
// copies is two too many; they are consolidated onto one exported helper when
// the engine is next released (tracked in the workspace backlog).
func validWebOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errNotAWebOrigin
	}
	if u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errNotAWebOrigin
	}
	return nil
}

// internalCreateSession is POST /internal/v1/sessions: it wraps
// sessions.Creator.Create for eudi-api-management, the sole caller.
func (r *router) internalCreateSession(ctx *azugo.Context) {
	ctx.SkipRequestLog() // no session ids in logs

	var req internalCreateRequest
	if err := json.Unmarshal(ctx.Body.Bytes(), &req); err != nil {
		ctx.Error(azugo.BadRequestError{Description: "malformed request body", Err: err})
		return
	}

	in, err := buildCreateInput(req)
	if err != nil {
		ctx.Error(err)
		return
	}

	// *azugo.Context implements context.Context directly (Deadline/Done/Err/
	// Value) — pass it as-is, the idiomatic pattern already used throughout
	// this package (routes/wallet.go, routes/processor_pipeline.go), rather
	// than ctx.Context() (which returns the underlying *fasthttp.RequestCtx
	// and bypasses SetContext's correlation wiring).
	created, err := r.SessionCreator().Create(ctx, in)
	if err != nil {
		// Engine/creator errors keep the internal problem envelope — this is
		// not a wallet endpoint, so no OID4VP error-shape translation.
		ctx.Error(err)
		return
	}

	resp := internalCreateResponse{
		SessionID:   created.SessionID,
		ExpiresAt:   created.ExpiresAt,
		RequestURI:  created.RequestURI,
		ResponseURI: created.ResponseURI,
	}
	resp.Invocation.SchemeURI = created.Invocation.SchemeURI
	resp.Invocation.WalletURL = created.Invocation.UniversalLink
	resp.Invocation.QRPayload = created.Invocation.QRPayload
	if len(created.Invocation.DCAPI) > 0 {
		resp.Invocation.DCAPIRequest = json.RawMessage(created.Invocation.DCAPI)
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(resp)
}

// internalDeleteSession is DELETE /internal/v1/sessions/{sessionID}: it kills
// the wallet-facing Valkey session (session+served+consumed keys —
// internal/valkeystore/store.go DeleteSession) only. Postgres status
// transitions are eudi-api-management's job, not this route's. Always 204
// on success, including "nothing to delete" — DELETE is idempotent.
func (r *router) internalDeleteSession(ctx *azugo.Context) {
	ctx.SkipRequestLog() // session ids appear in this path

	id := ctx.Params.String("sessionID")
	if err := r.Sessions().DeleteSession(ctx, id); err != nil {
		ctx.Error(err)
		return
	}
	ctx.StatusCode(fasthttp.StatusNoContent)
}

// internalSessionReport is GET /internal/v1/sessions/{sessionID}/report: the
// stored verification report for one session, verbatim.
//
// It exists because the report is the only place a check's own account of WHY
// it failed is written down, and every other way out of the service drops it:
// the wallet gets a public error code, the client-facing report carries the
// code without the detail, and the log line beside them is a log line. An
// operator diagnosing a failing wallet flow could otherwise only reach the
// cause through the database.
//
// Cluster-internal on purpose. The detail is safe text — the report is
// value-free by construction, holding claim names and never claim values —
// but it names our own infrastructure (list addresses, library errors), which
// is for us and not for a relying party. It is served behind the same bearer
// gate as the rest of this group, so a deployment that configures no internal
// token exposes no report route at all.
//
// A session with no report yet is an anomaly here rather than an empty
// success: the store says not-found and this renders 404, matching the
// sessions routes.
func (r *router) internalSessionReport(ctx *azugo.Context) {
	ctx.SkipRequestLog() // session ids appear in this path

	raw, err := r.SessionDB().GetReport(ctx, ctx.Params.String("sessionID"))
	if err != nil {
		ctx.Error(err)
		return
	}
	if len(raw) == 0 {
		ctx.Error(pkerrors.HTTP("report", "not-found"))
		return
	}
	ctx.JSON(raw)
}
