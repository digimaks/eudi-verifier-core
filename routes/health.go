package routes

import "azugo.io/azugo"

// healthz is liveness only — no dependency probing (that is /readyz).
// Tiny body + skip access log.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.JSON(map[string]string{"status": "ok"})
}
