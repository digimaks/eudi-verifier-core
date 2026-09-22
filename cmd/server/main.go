// Command eudi-verifier-core is the wallet-facing EUDI Wallet verifier service
// entrypoint.
package main

import (
	"os"

	"azugo.io/core/cli"
)

// Version is overridden at build time via -ldflags.
var Version = "0.1.0-dev"

func main() {
	if _, ok := os.LookupEnv("SERVER_URLS"); !ok {
		_ = os.Setenv("SERVER_URLS", "http://0.0.0.0:8080")
	}
	cli.Run(cli.Options{
		Use:     "eudi-verifier-core",
		Short:   "EUDI Wallet verifier core (wallet-facing)",
		Version: Version,
	})
}
