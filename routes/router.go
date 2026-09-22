// Package routes registers eudi-verifier-core's HTTP routes: wallet endpoints,
// JWKS, health/readiness.
package routes

import (
	verifiercore "github.com/digimaks/eudi-verifier-core"
)

type router struct {
	*verifiercore.App
}

// Init registers all eudi-verifier-core routes. Wallet endpoints, JWKS
// and readyz are added by their tasks.
func Init(a *verifiercore.App) error {
	r := &router{App: a}

	// This installs the full ten-step pipeline processor behind the Processor
	// seam (replacing the minimalProcessor, now deleted). The handlers
	// are unchanged. A test may pre-install its own processor before Init.
	if a.WalletProcessor() == nil {
		a.SetWalletProcessor(NewPipelineProcessor(a))
	}

	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)
	a.Get("/.well-known/verifier-jwks.json", r.jwks)
	bindWallet(a, r)
	// Fail closed by ABSENCE — an unconfigured InternalAPIToken
	// means the /internal/v1 surface is never registered, not registered and
	// unauthenticated.
	if a.Config().InternalAPIToken != "" {
		bindInternal(a, r)
	}
	return nil
}
