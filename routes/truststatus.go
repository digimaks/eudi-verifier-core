package routes

import (
	"azugo.io/azugo"
)

// internalTrustStatus is the diagnostic trust-identity route: which trust
// snapshot this verifier is enforcing, overall and per anchor type, read
// from the same cache records /readyz consumes. Deliberately a route and not
// health or metrics: a snapshot id must never be a metric label (ids churn a
// time series per value), and identity in the health body would grow it
// with the trust set. O(anchor types) forever.
func (r *router) internalTrustStatus(ctx *azugo.Context) {
	fr, frOK := r.AnchorFreshness(ctx)
	sh, shOK := r.AnchorSnapshotHealth(ctx)

	// cacheReadable=false: the anchor source carries no freshness signal
	// (not the production cache-backed source) — the honest answer is "this
	// process cannot name its trust identity", never a guess.
	body := map[string]any{"cacheReadable": frOK || shOK}

	if sh != nil {
		body["snapshotId"] = sh.SnapshotID
		body["lotlSequence"] = sh.LOTLSequence
		body["checkedAt"] = sh.CheckedAt.UTC()
		body["upstreamStale"] = sh.UpstreamStale
		body["pendingBootstrap"] = sh.PendingBootstrap
	}
	if frOK {
		types := make(map[string]any, len(fr))
		for t, f := range fr {
			e := map[string]any{"fresh": f.Fresh}
			if f.SnapshotID != "" {
				e["snapshotId"] = f.SnapshotID
			}
			if !f.FetchedAt.IsZero() {
				e["fetchedAt"] = f.FetchedAt.UTC()
			}
			if !f.ValidUntil.IsZero() {
				e["validUntil"] = f.ValidUntil.UTC()
			}
			if f.Stale {
				e["upstreamStale"] = true
			}
			types[t] = e
		}
		body["types"] = types
	}
	ctx.JSON(body)
}
