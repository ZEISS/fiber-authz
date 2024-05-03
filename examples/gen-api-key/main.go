package main

import (
	"context"
	"log"

	"github.com/zeiss/fiber-authz/utils"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func init() {
	rootCmd.SilenceUsage = true
}

func run(_ context.Context) error {
	key, err := utils.NewAPIKey()
	if err != nil {
		return err
	}

	log.Printf("API Key: %s\n", key)

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
