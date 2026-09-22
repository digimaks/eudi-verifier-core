// Package pipeline is the ten-step verification pipeline ([ARF §6.6.3]).
// Ordered, short-circuiting; every executed check produces a
// CheckResult in the persisted report. No attribute values leave this
// package except inside pipeline.Result (forward-and-delete).
package pipeline

import (
	"context"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
	mdoc "github.com/gmb-eudi/go-mdoc"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	sdjwt "github.com/gmb-eudi/go-sdjwt"
	statuslist "github.com/gmb-eudi/go-statuslist"

	"github.com/digimaks/eudi-verifier-core/internal/policy"
	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"
)

// Outcome is the per-check verdict recorded in the verification report.
type Outcome string

// Check outcomes (a skip is visible, never silent).
const (
	OutcomePass    Outcome = "pass"
	OutcomeFail    Outcome = "fail"
	OutcomeSkipped Outcome = "skipped"
)

// CheckResult is one row of the verification report. Detail is safe text
// (never claim values — library errors are value-free by contract,
// and Detail is additionally length-capped in Builder.Add).
type CheckResult struct {
	Check   string  `json:"name"`
	Outcome Outcome `json:"outcome"`
	Code    string  `json:"code,omitempty"`     // err:domain:reason on fail; provenance on skip
	SpecRef string  `json:"spec_ref,omitempty"` // from specrefs.go ONLY
	Detail  string  `json:"detail,omitempty"`
	// StatusListURI is the status list a revocation failure was about. It is
	// set only when a check could not resolve a credential's status, because
	// the underlying client's errors name a cause without naming the address
	// it tried ("resource not found", "context deadline exceeded"), and an
	// operator cannot act on the cause without the address.
	//
	// The list URI only, NEVER the entry index: a list is shared by many
	// credentials, while the index within it identifies one — recording it
	// would turn a diagnostic into a correlatable handle for a holder.
	StatusListURI string `json:"status_list_uri,omitempty"`
}

// Check is one pipeline step.
type Check interface {
	Name() string // matches VerificationReport check enum
	Run(ctx context.Context, pc *PipelineContext) (CheckResult, error)
}

// Cleaner disposes of session-scoped Valkey state at the end of a run (step
// 10). DeleteSession removes the session record entirely
// (forward-and-delete; used for cross-device/dcapi success and every failure).
// Save re-persists it instead (same-device SUCCESS only — see Finalize's
// flow-aware disposal): Save never touches the sticky
// vc:session:{id}:consumed marker (only ConsumeOnce's SetNX sets it, only
// DeleteSession clears it — valkeystore/store.go), so keeping the session
// alive for response_code redemption does not resurrect a
// consumable/replayable session.
type Cleaner interface {
	DeleteSession(ctx context.Context, id string) error
	Save(ctx context.Context, s *oid4vp.Session) error
}

// ResultSink receives the assembled result for delivery (step 10 seam;
// the Valkey handoff queue implements it).
type ResultSink interface {
	Deliver(ctx context.Context, meta *sessiondb.Session, res *Result) error
}

// StatusRefRecorder records a referenced status-list URI so the
// trust-cache-worker prefetches it (it reads the ZSET
// trust:statuslist:refs). Implemented in internal/statuscache over Valkey;
// nil in unit tests. Best-effort — a recording error never fails verification.
type StatusRefRecorder interface {
	Record(ctx context.Context, uri string) error
}

// PipelineContext carries per-run state through the checks. The name is locked
// by the interface (Check.Run takes *PipelineContext);
// "Context" would collide with the stdlib context package this file imports.
//
//nolint:revive // stutter is intentional — name locked by the pipeline interface (see doc above)
type PipelineContext struct {
	SessionID string
	Session   *oid4vp.Session
	Meta      *sessiondb.Session
	Raw       oid4vp.RawResponse
	Policy    policy.ClientPolicy
	Origin    string // DCAPI response origin; "" for redirect flows

	// Wiring (injected by the service in app.go).
	Engine    *oid4vp.Engine
	SDJWT     *sdjwt.Verifier
	MDoc      *mdoc.Verifier
	Status    *statuslist.Checker
	Anchors   trust.AnchorSource
	CredTrust CredentialTrustMap // vct/docType → issuer & status anchor types (config-driven)
	// IssuerValidity is the deployment's issuer-certificate validity model
	// (config). Zero value is not usable — the service injects it; a run without
	// it would silently pick a trust posture nobody chose.
	IssuerValidity IssuerValidityModel
	StatusRefs     StatusRefRecorder // ZADD to trust:statuslist:refs
	Sink           ResultSink
	Cleaner        Cleaner
	Clock          func() time.Time

	// Accumulated by checks.
	Presentations []oid4vp.Presentation
	ResponseCode  oid4vp.ResponseCode
	Credentials   []*Credential
	Report        *Builder
}

// NewContext builds a PipelineContext for one verification run, seeding the
// clock and report builder. Wiring fields are injected by the caller.
func NewContext(sessionID string, sess *oid4vp.Session, meta *sessiondb.Session) *PipelineContext {
	return &PipelineContext{
		SessionID: sessionID, Session: sess, Meta: meta,
		Clock: time.Now, Report: NewBuilder(sessionID),
	}
}

// Recorder is the pipeline's narrow observability seam. obs.Recorder
// implements it, but this package does NOT import obs — obs imports pipeline
// (for AllChecks), so the interface has to live here to avoid a cycle. A nil
// Recorder (the zero value of Engine, and every Engine built by tests that
// construct Engine{checks: …} directly) makes Run a pure no-op with respect to
// observability: existing unit tests are unaffected.
type Recorder interface {
	// StartCheck opens a span for one pipeline check named check (always one of
	// AllChecks — never wallet-derived input). The returned func records the
	// outcome (always one of OutcomePass/OutcomeFail/OutcomeSkipped) and closes
	// the span.
	StartCheck(ctx context.Context, check string) (context.Context, func(outcome string))
	// ObservePipeline records total pipeline latency for one Run call.
	ObservePipeline(d time.Duration)
}

// Engine runs the ordered checks (ordered, short-circuiting).
type Engine struct {
	checks   []Check
	recorder Recorder
}

// New builds the production engine with the ten checks in pipeline order.
func New(checks ...Check) *Engine { return &Engine{checks: checks} }

// WithRecorder installs the observability recorder and returns the
// same Engine, so callers can chain it onto New(...). A nil recorder (the
// default) leaves Run's behavior exactly as before.
func (e *Engine) WithRecorder(rec Recorder) *Engine {
	e.recorder = rec
	return e
}

// Run executes the checks in order, accumulating one CheckResult per executed
// check and short-circuiting at the first fail. A check that
// returns an error is recorded as a fail with a mapped err:domain:reason code.
//
// When a Recorder is installed, Run additionally opens one span per
// executed check and increments the per-check outcome counter, plus one
// full-run latency observation (via defer, so it fires on every return path —
// short-circuited or not). None of this changes the verification result: the
// span-scoped context StartCheck returns is deliberately NOT threaded into
// c.Run — some checks reach app.go's production status-list fetcher
// (statusFetch.Get), which type-asserts its ctx to *azugo.Context; an
// otel-wrapped context is a different concrete type and would fail that
// assertion, turning every production revocation check into an infrastructure
// failure. Checks therefore keep receiving the exact ctx they always did, and
// per-check spans are siblings of (not nested under) any parent request span —
// acceptable since no check itself opens a child span today.
func (e *Engine) Run(ctx context.Context, pc *PipelineContext) *Report {
	start := pc.Clock()
	defer func() {
		if e.recorder != nil {
			e.recorder.ObservePipeline(pc.Clock().Sub(start))
		}
	}()

	for _, c := range e.checks {
		var done func(string)
		if e.recorder != nil {
			_, done = e.recorder.StartCheck(ctx, c.Name())
		}
		res, err := c.Run(ctx, pc)
		if err != nil {
			res = CheckResult{Outcome: OutcomeFail, Code: CodeForError(err), Detail: safeDetail(err)}
		}
		res.Check = c.Name()
		if res.SpecRef == "" {
			res.SpecRef = SpecRefs[c.Name()]
		}
		if done != nil {
			done(string(res.Outcome))
		}
		pc.Report.Add(res)
		if res.Outcome == OutcomeFail {
			pc.Report.Failed(res.Code)
			return pc.Report.Build()
		}
	}
	pc.Report.Verified()
	return pc.Report.Build()
}

// safeDetail renders an error to bounded, value-free report text
// (library errors never carry attribute values; the cap bounds any wrapping).
func safeDetail(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
