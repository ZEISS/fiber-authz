package oas

import (
	"context"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
)

var (
	ErrUnauthenticated    = fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
	ErrMissingBearerToken = fiber.NewError(fiber.StatusUnauthorized, "missing bearer token")
)

// Authenticator is an interface for authenticating a subject.
type Authenticator interface {
	// Authenticate returns a nil error and the AuthClaims info (if available) if the subject is authenticated or a
	// non-nil error with an appropriate error cause otherwise.
	Authenticate(requestContext context.Context) (*AuthClaims, error)

	// Close Cleans up the authenticator.
	Close()
}

type NoopAuthenticator struct{}

var _ Authenticator = (*NoopAuthenticator)(nil)

func (n NoopAuthenticator) Authenticate(requestContext context.Context) (*AuthClaims, error) {
	return &AuthClaims{
		Subject: "",
		Scopes:  nil,
	}, nil
}

func (n NoopAuthenticator) Close() {}

// AuthClaims contains claims that are included in OIDC standard claims. https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type AuthClaims struct {
	Subject string
	Scopes  map[string]bool
}

// OidcConfig contains authorization server metadata. See https://datatracker.ietf.org/doc/html/rfc8414#section-2
type OidcConfig struct {
	Issuer  string `json:"issuer"`
	JWKsURI string `json:"jwks_uri"`
}

// OidcAuthenticator is an interface for OIDC authentication.
type OidcAuthenticator interface {
	GetConfiguration() (*OidcConfig, error)
	GetKeys() (*keyfunc.JWKS, error)
}

// AuthenticatorOpts is a function that sets the configuration for the authenticator.
type AuthenticatorOpts struct {
	Schemas map[string]openapi3filter.AuthenticationFunc
}

// Configure sets the configuration for the authenticator.
func (c *AuthenticatorOpts) Configure(opts ...AuthenticatorOpt) {
	for _, opt := range opts {
		opt(c)
	}
}

// AuthenticatorOpt is a function that sets the configuration for the authenticator.
type AuthenticatorOpt func(*AuthenticatorOpts)

// DefaultAuthenticatorOpts returns the default authenticator options.
func DefaultAuthenticatorOpts() AuthenticatorOpts {
	return AuthenticatorOpts{
		Schemas: map[string]openapi3filter.AuthenticationFunc{},
	}
}

// WithSchema sets the authentication schema for the authenticator.
func WithSchema(schema string, auth openapi3filter.AuthenticationFunc) AuthenticatorOpt {
	return func(o *AuthenticatorOpts) {
		o.Schemas[schema] = auth
	}
}

// WithOIDCSchema sets the OIDC authentication schema for the authenticator.
func WithOIDCSchema(auth openapi3filter.AuthenticationFunc) AuthenticatorOpt {
	return WithSchema("openIdConnect", auth)
}

// WithBasicSchema sets the basic authentication schema for the authenticator.
func WithBasicAuthSchema(auth openapi3filter.AuthenticationFunc) AuthenticatorOpt {
	return WithSchema("basic", auth)
}

// Authenticate returns a nil error and the AuthClaims info (if available) if the subject is authenticated or a
func Authenticate(opts ...AuthenticatorOpt) openapi3filter.AuthenticationFunc {
	options := DefaultAuthenticatorOpts()
	options.Configure(opts...)

	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		auth, ok := options.Schemas[input.SecurityScheme.Type]
		if !ok {
			return fiber.ErrForbidden
		}

		return auth(ctx, input)
	}
}
