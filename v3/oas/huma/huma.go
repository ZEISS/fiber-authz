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

const (
	// OidcDiscoveryEndpoint is the endpoint that serves the OIDC discovery document
	OidcDiscoveryEndpoint = "/.well-known/openid-configuration"
)

// OidcTokenKey is the key used to extract the OIDC token from the request
const OidcTokenKey = iota

// DefaultClient is the default HTTP client for the Perplexity API.
var DefaultClient = retryablehttp.NewClient()

var jwkRefreshInterval = 48 * time.Hour

// WellknownConfig holds the well-known OIDC configuration.
type WellknownConfig struct {
	// Issuer is the OIDC issuer URL.
	Issuer string `json:"issuer"`
	// JWKsURI is the URI of the JWKS.
	JWKsURI string `json:"jwks_uri"`
	// TokenEndpoint is the URI of the token endpoint.
	TokenEndpoint string `json:"token_endpoint"`
	// AuthorizationEndpoint is the URI of the authorization endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// UserInfoEndpoint is the URI of the user info endpoint.
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	// DeviceAuthorizationEndpoint is the URI of the device authorization endpoint.
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	// IntrospectionEndpoint is the URI of the introspection endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// HumanOpts holds the OIDC configuration for the Huma middleware.
type HumanOpts struct {
	// WellKnownConfig holds the well-known OIDC configuration.
	WellKnownConfig *WellknownConfig `json:"well_known_config"`
	// Audience is the OIDC audience.
	Audience string `json:"audience"`
	// Client is the HTTP client to use for fetching the JWKS.
	Client *retryablehttp.Client `json:"-"`
}

// HumanOpt is the configuration for the Huma middleware.
type HumanOpt func(*HumanOpts)

// HumanDefaults returns the default configuration for the Huma middleware.
func HumanDefaults() *HumanOpts {
	return &HumanOpts{
		Audience:        "",
		WellKnownConfig: &WellknownConfig{},
		Client:          DefaultClient,
	}
}

// WithAudience returns an option that sets the OIDC audience.
func WithAudience(audience string) HumanOpt {
	return func(opts *HumanOpts) {
		opts.Audience = audience
	}
}

// WithWellknownConfig returns an option that sets the well-known OIDC configuration.
func WithWellknownConfig(config *WellknownConfig) HumanOpt {
	return func(opts *HumanOpts) {
		opts.WellKnownConfig = config
	}
}

// WithClient returns an option that sets the HTTP client.
func WithClient(client *retryablehttp.Client) HumanOpt {
	return func(opts *HumanOpts) {
		opts.Client = client
	}
}

// NewAuthMiddleware returns a middleware that validates OIDC tokens.
func NewHumanMiddleware(api huma.API, opts ...HumanOpt) func(ctx huma.Context, next func(huma.Context)) {
	config := HumanDefaults()
	for _, opt := range opts {
		opt(config)
	}

	var JWKs *keyfunc.JWKS

	return func(ctx huma.Context, next func(huma.Context)) {
		jwks, err := GetKeys(config.Client.StandardClient(), config.WellKnownConfig.JWKsURI)
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
		validIssuers = append(validIssuers, config.WellKnownConfig.Issuer)

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

		ctx = huma.WithValue(ctx, OidcTokenKey, token)

		next(ctx)
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

// GetConfiguration fetches the OIDC configuration from the given URL using the provided HTTP client.
func GetConfiguration(ctx context.Context, client *retryablehttp.Client, url string) (*WellknownConfig, error) {
	wellKnown := strings.TrimSuffix(url, "/") + OidcDiscoveryEndpoint

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

	wellKnownConfig := &WellknownConfig{}
	if err := json.Unmarshal(body, wellKnownConfig); err != nil {
		return nil, fmt.Errorf("failed parsing document: %w", err)
	}

	if wellKnownConfig.Issuer == "" {
		return nil, errors.New("missing issuer value")
	}

	if wellKnownConfig.JWKsURI == "" {
		return nil, errors.New("missing jwks_uri value")
	}

	return wellKnownConfig, nil
}
