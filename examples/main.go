package main

import (
	"context"
	"html/template"
	"log"
	"os"
	"sort"

	authz "github.com/zeiss/fiber-authz"

	"github.com/gofiber/fiber/v2"
	ll "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/katallaxie/pkg/logger"
	"github.com/spf13/cobra"
	goth "github.com/zeiss/fiber-goth"
	gorm_adapter "github.com/zeiss/fiber-goth/adapters/gorm"
	"github.com/zeiss/fiber-goth/providers"
	"github.com/zeiss/fiber-goth/providers/github"
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
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.Addr, "addr", ":3000", "addr")
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

	ga, err := gorm_adapter.New(conn)
	if err != nil {
		return err
	}

	m := map[string]string{
		"amazon":          "Amazon",
		"apple":           "Apple",
		"auth0":           "Auth0",
		"azuread":         "Azure AD",
		"battlenet":       "Battle.net",
		"bitbucket":       "Bitbucket",
		"box":             "Box",
		"dailymotion":     "Dailymotion",
		"deezer":          "Deezer",
		"digitalocean":    "Digital Ocean",
		"discord":         "Discord",
		"dropbox":         "Dropbox",
		"eveonline":       "Eve Online",
		"facebook":        "Facebook",
		"fitbit":          "Fitbit",
		"gitea":           "Gitea",
		"github":          "Github",
		"gitlab":          "Gitlab",
		"google":          "Google",
		"gplus":           "Google Plus",
		"heroku":          "Heroku",
		"instagram":       "Instagram",
		"intercom":        "Intercom",
		"kakao":           "Kakao",
		"lastfm":          "Last FM",
		"line":            "LINE",
		"linkedin":        "LinkedIn",
		"mastodon":        "Mastodon",
		"meetup":          "Meetup.com",
		"microsoftonline": "Microsoft Online",
		"naver":           "Naver",
		"nextcloud":       "NextCloud",
		"okta":            "Okta",
		"onedrive":        "Onedrive",
		"openid-connect":  "OpenID Connect",
		"patreon":         "Patreon",
		"paypal":          "Paypal",
		"salesforce":      "Salesforce",
		"seatalk":         "SeaTalk",
		"shopify":         "Shopify",
		"slack":           "Slack",
		"soundcloud":      "SoundCloud",
		"spotify":         "Spotify",
		"steam":           "Steam",
		"strava":          "Strava",
		"stripe":          "Stripe",
		"tiktok":          "TikTok",
		"twitch":          "Twitch",
		"twitter":         "Twitter",
		"twitterv2":       "Twitter",
		"typetalk":        "Typetalk",
		"uber":            "Uber",
		"vk":              "VK",
		"wecom":           "WeCom",
		"wepay":           "Wepay",
		"xero":            "Xero",
		"yahoo":           "Yahoo",
		"yammer":          "Yammer",
		"yandex":          "Yandex",
		"zoom":            "Zoom",
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	providers.RegisterProvider(github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "http://localhost:3000/auth/github/callback"))

	err = authz.RunMigrations(conn)
	if err != nil {
		return err
	}

	app := fiber.New()
	app.Use(requestid.New())
	app.Use(ll.New())

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}
	engine := template.New("views")

	t, err := engine.Parse(indexTemplate)
	if err != nil {
		log.Fatal(err)
	}

	gothConfig := goth.Config{
		Adapter:        ga,
		Secret:         goth.GenerateKey(),
		CookieHTTPOnly: true,
	}

	app.Use(goth.NewProtectMiddleware(gothConfig))
	app.Use(authz.SetAuthzHandler(authz.NewNoopObjectResolver(), authz.NewNoopActionResolver(), authz.NewGothAuthzPrincipalResolver()))

	config := authz.Config{
		Checker: authz.NewTBAC(conn),
	}

	indexHandler := func(c *fiber.Ctx) error {
		session, err := goth.SessionFromContext(c)
		if err != nil {
			return err
		}

		return c.JSON(session)
	}

	app.Get("/login", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return t.Execute(c.Response().BodyWriter(), providerIndex)
	})

	app.Get("/:team", authz.NewTBACHandler(indexHandler, authz.AuthzAction("admin"), "team", config))
	app.Get("/login/:provider", goth.NewBeginAuthHandler(gothConfig))
	app.Get("/auth/:provider/callback", goth.NewCompleteAuthHandler(gothConfig))
	app.Get("/logout", goth.NewLogoutHandler(gothConfig))

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

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

var indexTemplate = `{{range $key,$value:=.Providers}}
    <p><a href="/login/{{$value}}">Log in with {{index $.ProvidersMap $value}}</a></p>
{{end}}`
