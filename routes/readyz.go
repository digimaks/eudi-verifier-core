package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// requiredAnchorTypes are the anchor types the pipeline actually depends on for
// readiness. wallet_provider and wrprc_issuer are consumed by other services;
// access_ca is a eudi-api-management concern — eudi-verifier-core degrades only on ISSUER
// anchor staleness.
var requiredAnchorTypes = []string{"pid_provider", "qeaa_provider", "pub_eaa_provider", "eaa_provider"}

// readyz reports liveness of Postgres + Valkey + AnchorSource freshness
// (end-to-end degraded-state visibility). Any degraded dependency => 503 with
// the failing components listed (fail closed).
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	var degraded []string
	if err := r.PingDB(ctx); err != nil {
		degraded = append(degraded, "postgres")
	}
	if err := r.Valkey().Ping(ctx).Err(); err != nil {
		degraded = append(degraded, "valkey")
	}
	if fr, ok := r.AnchorFreshness(ctx); ok {
		for _, t := range requiredAnchorTypes {
			if !fr[t].Fresh {
				degraded = append(degraded, "anchors:"+t)
			}
		}
	}
	// Snapshot health (trust:freshness:snapshot via trustcache): a pending
	// upstream bootstrap => treat as degraded (fail closed — the trust
	// service reports "no active bootstrap upstream" as not-ready). Absent = degraded.
	if sh, ok := r.AnchorSnapshotHealth(ctx); !ok || sh == nil || sh.PendingBootstrap || sh.UpstreamStale {
		degraded = append(degraded, "trust-snapshot")
	}
	if len(degraded) > 0 {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.JSON(map[string]any{"status": "degraded", "components": degraded})
		return
	}
	ctx.JSON(map[string]string{"status": "ok"})
}
