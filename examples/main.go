package main

import (
	"context"
	"log"
	"os"

	"github.com/openfga/go-sdk/client"
	authz "github.com/zeiss/fiber-authz"

	"github.com/gofiber/fiber/v2"
	ll "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/katallaxie/pkg/logger"
	"github.com/spf13/cobra"
)

// Config ...
type Config struct {
	Flags *Flags
}

// Flags ...
type Flags struct {
	Addr string
	DB   *DB
}

// DB ...
type DB struct {
	Username string
	Password string
	Port     int
	Database string
}

var cfg = &Config{
	Flags: &Flags{
		DB: &DB{},
	},
}

var rootCmd = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.Addr, "addr", ":8084", "addr")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Database, "db-database", cfg.Flags.DB.Database, "Database name")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Username, "db-username", cfg.Flags.DB.Username, "Database user")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Password, "db-password", cfg.Flags.DB.Password, "Database password")
	rootCmd.PersistentFlags().IntVar(&cfg.Flags.DB.Port, "db-port", cfg.Flags.DB.Port, "Database port")

	rootCmd.SilenceUsage = true
}

func run(_ context.Context) error {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	logger.RedirectStdLog(logger.LogSink)

	fgaClient, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl:               os.Getenv("FGA_API_URL"),  // required, e.g. https://api.fga.example
		StoreId:              os.Getenv("FGA_STORE_ID"), // optional, not needed for \`CreateStore\` and \`ListStores\`, required before calling for all other methods
		AuthorizationModelId: os.Getenv("FGA_MODEL_ID"), // Optional, can be overridden per request
	})
	if err != nil {
		panic(err)
	}

	client := authz.NewFGA(fgaClient)

	app := fiber.New()
	app.Use(requestid.New())
	app.Use(ll.New())

	config := authz.Config{
		Checker: client,
	}

	app.Post("/check", authz.NewCheckerHandler(config))

	err = app.Listen(cfg.Flags.Addr)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
