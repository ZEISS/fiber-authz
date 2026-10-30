package huma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/danielgtaylor/huma/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-retryablehttp"
)

// DefaultTimeout is the default timeout for the Perplexity API.
const DefaultTimeout = 30 * time.Second

// DefaultClient is the default HTTP client for the Perplexity API.
var DefaultClient = &http.Client{
	Timeout: DefaultTimeout,
}

var jwkRefreshInterval = 48 * time.Hour

// OIDCConfig holds the OIDC configuration.
type OIDCConfig struct {
	// Issuer is the OIDC issuer URL.
	Issuer string `json:"issuer"`
	// JWKsURI is the URI of the JWKS.
	JWKsURI string `json:"jwks_uri"`
}

// HumanOpts holds the OIDC configuration for the Huma middleware.
type HumanOpts struct {
	// Issuer is the OIDC issuer URL.
	Issuer string `json:"issuer"`
	// Audience is the OIDC audience.
	Audience string `json:"audience"`
	// Client is the HTTP client to use for fetching the JWKS.
	Client *retryablehttp.Client `json:"-"`
}

// HumanOpt is the configuration for the Huma middleware.
type HumanOpt func(*HumanOpts)

// HumanDefaults returns the default configuration for the Huma middleware.
func HumanDefaults() *HumanOpts {
	client := retryablehttp.NewClient()
	client.HTTPClient = DefaultClient
	client.Logger = nil

	return &HumanOpts{
		Issuer:   "",
		Audience: "",
		Client:   client,
	}
}

// GetKeys fetches the JWKS from the given URI using the provided HTTP client.
func GetKeys(client *http.Client, jwksURI string) (*keyfunc.JWKS, error) {
	jwks, err := keyfunc.Get(jwksURI, keyfunc.Options{
		Client:          client,
		RefreshInterval: jwkRefreshInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching keys from %v: %w", jwksURI, err)
	}

	return jwks, nil
}

// NewAuthMiddleware returns a middleware that validates OIDC tokens.
func NewHumanMiddleware(api huma.API, opts ...HumanOpt) func(ctx huma.Context, next func(huma.Context)) {
	config := HumanDefaults()
	for _, opt := range opts {
		opt(config)
	}

	var JWKs *keyfunc.JWKS
	var JwksURI string

	return func(ctx huma.Context, next func(huma.Context)) {
		oidcConfig, err := GetConfiguration(ctx.Context(), config.Client, config.Issuer)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		JwksURI = oidcConfig.JWKsURI
		jwks, err := GetKeys(config.Client.StandardClient(), JwksURI)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		JWKs = jwks

		jwtParser := jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
		)

		jws := strings.TrimPrefix(ctx.Header("Authorization"), "Bearer ")
		if len(jws) == 0 {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}

		token, err := jwtParser.Parse(jws, func(token *jwt.Token) (any, error) {
			return JWKs.Keyfunc(token)
		})

		if err != nil || !token.Valid {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}

		validIssuers := make([]string, 0, 1)
		validIssuers = append(validIssuers, config.Issuer)

		ok = slices.ContainsFunc(validIssuers, func(issuer string) bool {
			v := jwt.NewValidator(jwt.WithIssuer(issuer))
			err := v.Validate(claims)
			return err == nil
		})

		if !ok {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if err := jwt.NewValidator(jwt.WithAudience(config.Audience)).Validate(claims); err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}

		next(ctx)
	}
}

// GetConfiguration fetches the OIDC configuration from the given URL using the provided HTTP client.
func GetConfiguration(ctx context.Context, client *retryablehttp.Client, url string) (*OIDCConfig, error) {
	wellKnown := strings.TrimSuffix(url, "/") + "/.well-known/openid-configuration"

	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("error forming request to get OIDC: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting OIDC: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code getting OIDC: %v", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	oidcConfig := &OIDCConfig{}
	if err := json.Unmarshal(body, oidcConfig); err != nil {
		return nil, fmt.Errorf("failed parsing document: %w", err)
	}

	if oidcConfig.Issuer == "" {
		return nil, errors.New("missing issuer value")
	}

	if oidcConfig.JWKsURI == "" {
		return nil, errors.New("missing jwks_uri value")
	}

	return oidcConfig, nil
}
