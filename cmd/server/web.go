package main

import (
	verifiercore "github.com/dativa-lv/eudi-verifier-core"
	"github.com/dativa-lv/eudi-verifier-core/routes"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
	"github.com/spf13/cobra"
)

func runWeb(cmd *cobra.Command, _ []string) error {
	a, err := verifiercore.New(cmd, Version)
	if err != nil {
		return err
	}
	if err = routes.Init(a); err != nil {
		return err
	}
	server.RunContext(cmd.Context(), a)
	return nil
}

func init() {
	cli.Register(&cobra.Command{Use: "web", Short: "Start web server", RunE: runWeb}, cli.AsDefault())
}
