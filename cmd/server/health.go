package main

import (
	verifiercore "github.com/digimaks/eudi-verifier-core"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "EUDI Verifier Core",
		AppVer:        Version,
		Configuration: verifiercore.NewConfiguration(),
	}))
}
