package main

import (
	"context"
	"html/template"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/katallaxie/pkg/logger"
	"github.com/spf13/cobra"
	authz "github.com/zeiss/fiber-authz"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.Addr, "addr", ":8080", "addr")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Database, "db-database", cfg.Flags.DB.Database, "Database name")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Username, "db-username", cfg.Flags.DB.Username, "Database user")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Password, "db-password", cfg.Flags.DB.Password, "Database password")
	rootCmd.PersistentFlags().IntVar(&cfg.Flags.DB.Port, "db-port", cfg.Flags.DB.Port, "Database port")

	rootCmd.SilenceUsage = true
}

func run(ctx context.Context) error {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	logger.RedirectStdLog(logger.LogSink)

	dsn := "host=host.docker.internal user=example password=example dbname=example port=5432 sslmode=disable"
	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	err = authz.RunMigrations(conn)
	if err != nil {
		return err
	}

	app := fiber.New()
	engine := template.New("views")

	t, err := engine.Parse(indexTemplate)
	if err != nil {
		log.Fatal(err)
	}

	fn := func(ctx context.Context) (authz.AuthzPrincipal, authz.AuthzUser, error) {
		return authz.AuthzNoPrincipial, authz.AuthzNoUser, nil // this is for testing
	}

	app.Use(authz.SetAuthzHandler(fn))

	index := func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return t.Execute(c.Response().BodyWriter(), struct{}{})
	}

	config := authz.Config{Checker: authz.DefaultChecker(conn)}
	app.Get("/", authz.NewProtectedHandler(index, authz.Read, config))

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

var indexTemplate = `<div>Hooray!</div>`
