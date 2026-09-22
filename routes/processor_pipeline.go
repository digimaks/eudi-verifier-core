package routes

import (
	"encoding/json"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	verifiercore "github.com/digimaks/eudi-verifier-core"
	"github.com/digimaks/eudi-verifier-core/internal/pipeline"
	"github.com/digimaks/eudi-verifier-core/internal/policy"

	"azugo.io/azugo"
	"go.uber.org/zap"
)

// pipelineProcessor runs the full ten-step pipeline, replacing the
// minimalProcessor behind the same Processor seam.
type pipelineProcessor struct{ app *verifiercore.App }

// NewPipelineProcessor builds the full-pipeline response processor.
func NewPipelineProcessor(app *verifiercore.App) Processor { return pipelineProcessor{app: app} }

func (p pipelineProcessor) Process(ctx *azugo.Context, sess *oid4vp.Session) (string, error) {
	meta, err := p.app.SessionDB().Get(ctx, sess.ID)
	if err != nil {
		return "", err
	}
	pol, err := policy.Parse(meta.Policy)
	if err != nil {
		return "", pkerrors.NewProblem("err:pipeline:internal")
	}

	pc := pipeline.NewContext(sess.ID, sess, meta)
	pc.Raw = oid4vp.RawResponse{Body: ctx.Body.Bytes()}
	pc.Policy = pol
	pc.Origin = ctx.Header.Get("Origin") // consumed only for the dcapi flow
	if meta.Flow != "dcapi" {
		pc.Origin = ""
	}
	pc.Engine, pc.SDJWT, pc.MDoc = p.app.Engine(), p.app.SDJWTVerifier(), p.app.MDocVerifier()
	pc.Status, pc.Anchors, pc.StatusRefs = p.app.StatusChecker(), p.app.Anchors(), p.app.StatusRefs()
	pc.CredTrust = p.app.CredTrust() // parsed once at startup from Configuration.CredentialTrustJSON
	pc.IssuerValidity = p.app.IssuerValidityModel()
	pc.Sink, pc.Cleaner = p.app.ResultSink(), p.app.Sessions()

	rep := p.app.Pipeline().Run(ctx, pc)

	// Persist the report — claim NAMES only by Report's construction.
	if raw, merr := json.Marshal(rep); merr == nil {
		if serr := p.app.SessionDB().SaveReport(ctx, sess.ID, raw); serr != nil {
			return "", serr
		}
	}

	if rep.Outcome != "verified" {
		logFailedCheck(ctx, rep)
		_ = p.app.SessionDB().SetStatus(ctx, sess.ID, "failed")
		// ARF AS-RP-51-013: delete on failure too; the client learns the outcome
		// via a report-only result (no attribute values). The pipeline
		// short-circuited before step 10, so its Finalize never ran — do it here.
		_ = pipeline.Finalize(ctx, pc, &pipeline.Result{
			SessionID: sess.ID, Outcome: "failed", Report: rep,
		})
		return "", walletFailProblem(rep.FailCode) // → OID4VP shape via Engine.ErrorResponse
	}

	if err := p.app.SessionDB().SetStatus(ctx, sess.ID, "verified"); err != nil {
		return "", err
	}
	// ProcessResponse (pipeline step 1) minted the
	// [OID4VP §8.2] response_code onto sess but never persisted it — minimalProcessor
	// omitted the Save the engine's own contract requires (response.go).
	// Step 10's Finalize (internal/pipeline/finalize.go)
	// now does that Save itself, flow- and outcome-aware — for a same-device
	// success it re-Saves pc.Session (== sess, same pointer) INSTEAD of
	// deleting it, preserving the sticky vc:session:{id}:consumed marker so a
	// replay is rejected at ConsumeOnce rather than silently re-running the
	// pipeline. A second Save here would be redundant. Only the
	// vc:respcode:{code} index (eudi-api-management redemption) is this
	// processor's job. Cross-device/dcapi mint no code — Finalize deleted their
	// session as before, so there is nothing to index.
	if pc.ResponseCode != "" {
		if err := p.app.Sessions().SaveResponseCode(ctx, pc.ResponseCode, sess.ID); err != nil {
			return "", err
		}
	}
	if meta.Flow == "same_device" {
		// no code argument — RedirectURI reads
		// s.ResponseCode/s.ReturnURI from sess itself.
		return p.app.Engine().RedirectURI(sess)
	}
	return "", nil
}

// walletFailProblem maps a pipeline report FailCode to the problem returned for
// a failed verification. The error taxonomy pins err:credential:expired
// and err:revocation:revoked to HTTP 422; both reason strings are kit built-ins
// that otherwise resolve to 410 (gone/expired/revoked), so this is the ONE site
// that applies the documented WithStatus(422) override (the taxonomy notes in
// reasons.go and internal/pipeline/errclass.go point here). Every other FailCode
// keeps its taxonomy-derived status untouched.
//
// The 422 lives on the problem OBJECT (its problem+json status). It is NOT the
// HTTP status the wallet sees: the wallet boundary renders OID4VP error shapes
// (routes/wallet.go), so a refused verification reaches the wallet as
// 400 invalid_request.
//
// The status on this problem is what CLASSIFIES it there. A client-visible
// rating marks the outcome a refusal the wallet is entitled to be told about; a
// server rating keeps it ours and renders 500, leaking nothing
// (routes/wallet_error.go). So the override matters three ways: the persisted
// report's taxonomy correctness, any problem+json rendering of these codes, and
// whether the wallet learns its credential was refused at all.
func walletFailProblem(failCode string) error {
	switch failCode {
	// expired credential / revoked status ⇒ 422.
	case "err:credential:expired", "err:revocation:revoked":
		return pkerrors.NewProblem(failCode, pkerrors.WithStatus(422))
	default:
		return pkerrors.NewProblem(failCode)
	}
}

// logFailedCheck writes the one line that says WHY a verification failed.
//
// The wallet-facing response and the log line beside it carry the public
// error code only, and one code covers many distinct causes — a status list
// that could not be fetched, one signed by an unresolvable key, one whose
// token is past its freshness window. The check that failed computed the
// actual cause and put it in the report; without this line the only copy of
// it is the persisted report, which needs database access to read.
//
// One line per failed verification, never per request, and only the check
// that failed: the pipeline stops at the first failure, so that is the last
// entry in the report.
//
// The report is value-free by construction (claim names only, and check
// detail comes from library errors that carry no attribute values), so every
// field logged here is safe to log. The status list URI is included; the
// entry index inside that list is deliberately not.
func logFailedCheck(ctx *azugo.Context, rep *pipeline.Report) {
	if rep == nil || len(rep.Checks) == 0 {
		return
	}
	failed := rep.Checks[len(rep.Checks)-1]
	fields := []zap.Field{
		zap.String("check", failed.Check),
		zap.String("code", failed.Code),
		zap.String("cause", failed.Detail),
	}
	if failed.SpecRef != "" {
		fields = append(fields, zap.String("spec_ref", failed.SpecRef))
	}
	if failed.StatusListURI != "" {
		fields = append(fields, zap.String("status_list_uri", failed.StatusListURI))
	}
	ctx.Log().Warn("verification failed", fields...)
}
