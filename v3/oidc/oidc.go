package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-retryablehttp"
	slicesx "github.com/zeiss/pkg/slices"
)

// DefaultClient is the default HTTP client for the Perplexity API.
var DefaultClient = retryablehttp.NewClient()

var (
	jwkRefreshInterval  = 48 * time.Hour
	jwkRefreshRateLimit = 1 * time.Minute
)

var (
	// ErrMissingIssuer is returned when the issuer is not provided.
	ErrMissingIssuer = errors.New("oidc: missing issuer")
	// ErrMissingAudience is returned when the audience is not provided.
	ErrMissingAudience = errors.New("oidc: missing audience")
	// ErrIssuerNotFound is returned when the issuer is not found.
	ErrIssuerNotFound = errors.New("oidc: issuer not found")
	// ErrInvalidClaims is returned when the claims are invalid.
	ErrInvalidClaims = errors.New("oidc: invalid claims")
)

// DefaultSigningAlgorithms are the JWT signing algorithms accepted when none are configured.
var DefaultSigningAlgorithms = []string{"RS256"}

// supportedSigningAlgorithms are the asymmetric JWT signing algorithms that can be configured.
// Symmetric (HMAC) algorithms and "none" are intentionally not supported, since the keys are
// fetched from the issuer's public JWKS.
var supportedSigningAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// OidcConfig contains authorization server metadata. See https://datatracker.ietf.org/doc/html/rfc8414#section-2
type OidcConfig struct {
	// Issuer is the OIDC issuer URL.
	Issuer string `json:"issuer"`
	// JWKsURI is the URL of the JWKS endpoint.
	JWKsURI string `json:"jwks_uri"`
}

// OidcAuthClaim contains the claims for an OIDC authentication request.
type OidcAuthClaim struct {
	Subject  string
	Scopes   map[string]bool
	ClientID string
}

// OidcIssuer is an interface for OIDC authentication.
type OidcIssuer interface {
	// GetConfiguration returns the OIDC configuration.
	GetConfiguration() (*OidcConfig, error)
	// GetKeys returns the JWKS for the OIDC configuration.
	GetKeys() (*keyfunc.JWKS, error)
}

// NewOidcIssuer creates a new OidcIssuer.
func NewOidcIssuer(url string, aliases []string, audience string, subjects []string, clientIDClaims []string, validSigningAlgorithms []string) (OidcIssuer, error) {
	issuer := &oidcIssuer{
		URL:                    url,
		Aliases:                aliases,
		Audience:               audience,
		Subjects:               subjects,
		ClientIDClaims:         clientIDClaims,
		ValidSigningAlgorithms: validSigningAlgorithms,
		client:                 DefaultClient.StandardClient(),
	}

	if err := issuer.init(); err != nil {
		return nil, err
	}

	return issuer, nil
}

var _ OidcIssuer = (*oidcIssuer)(nil)

type oidcIssuer struct {
	// URL is the OIDC issuer URL.
	URL string
	// Aliases are alternative issuer URLs that are accepted.
	Aliases []string
	// Audience is the OIDC audience.
	Audience string
	// Subjects are the OIDC subjects.
	Subjects []string
	// ClientIDClaims are the OIDC client ID claims.
	ClientIDClaims []string
	// ValidSigningAlgorithms lists the JWT signing algorithms (the `alg` header) that are accepted.
	// It defaults to RS256.
	ValidSigningAlgorithms []string
	// JwksURI is the URL of the JWKS endpoint.
	JwksURI string
	// JWKs is the parsed JWKS.
	JWKs *keyfunc.JWKS
	// OidcConfig is the parsed OIDC configuration.
	OidcConfig *OidcConfig

	client *http.Client
}

// GetKeys fetches the JWKS from the configured JwksURI.
func (o *oidcIssuer) GetKeys() (*keyfunc.JWKS, error) {
	jwks, err := keyfunc.Get(o.JwksURI, keyfunc.Options{
		Client:            o.client,
		RefreshInterval:   jwkRefreshInterval,
		RefreshUnknownKID: true,
		RefreshRateLimit:  jwkRefreshRateLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching keys from %v: %w", o.JwksURI, err)
	}

	return jwks, nil
}

// GetConfiguration fetches the OIDC configuration from the configured Issuer.
func (o *oidcIssuer) GetConfiguration() (*OidcConfig, error) {
	wellKnown := strings.TrimSuffix(o.URL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("error forming request to get OIDC: %w", err)
	}

	res, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting OIDC: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode > http.StatusOK {
		return nil, fmt.Errorf("unexpected status code getting OIDC: %v", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	oidcConfig := &OidcConfig{}
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

// Close ends the background goroutine for the JWKS.
func (o *oidcIssuer) Close() {
	o.JWKs.EndBackground()
}

func (o *oidcIssuer) init() error {
	oidcConfig, err := o.GetConfiguration()
	if err != nil {
		return fmt.Errorf("error fetching OIDC configuration: %w", err)
	}
	o.OidcConfig = oidcConfig

	jwks, err := o.GetKeys()
	if err != nil {
		return fmt.Errorf("error fetching OIDC keys: %w", err)
	}
	o.JWKs = jwks

	return nil
}

// FederatedAuthenticator is an interface for federated authentication.
type FederatedAuthenticator struct {
	issuers map[string]oidcIssuer
}

// NewFederatedAuthenticator creates a new FederatedAuthenticator.
func NewFederatedAuthenticator(issuers ...oidcIssuer) *FederatedAuthenticator {
	issuerMap := map[string]oidcIssuer{}
	for _, issuer := range issuers {
		issuerMap[issuer.OidcConfig.Issuer] = issuer
	}

	return &FederatedAuthenticator{
		issuers: issuerMap,
	}
}

type userData struct {
	jwt.RegisteredClaims

	Email   string `json:"email"`
	Subject string `json:"sub"` // userID
}

// Authenticate authenticates a token against the configured OIDC issuers.
func (f *FederatedAuthenticator) Authenticate(rawToken string) (*OidcAuthClaim, error) {
	jwtParser := jwt.NewParser()
	userData := userData{}

	_, _, err := jwtParser.ParseUnverified(rawToken, &userData)
	if err != nil {
		return nil, err
	}

	issuer, ok := f.issuers[userData.Issuer]
	if !ok {
		return nil, ErrIssuerNotFound
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods(issuer.ValidSigningAlgorithms),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	}

	// constructor enforces non-empty Audience; unconditional to make the invariant explicit
	options = append(options, jwt.WithAudience(issuer.Audience))

	jwtParser = jwt.NewParser(options...)

	token, err := jwtParser.Parse(rawToken, func(token *jwt.Token) (any, error) {
		return issuer.JWKs.Keyfunc(token)
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidClaims
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	validIssuers := []string{
		issuer.OidcConfig.Issuer,
	}
	validIssuers = append(validIssuers, issuer.Aliases...)

	ok = slices.ContainsFunc(validIssuers, func(issuer string) bool {
		v := jwt.NewValidator(jwt.WithIssuer(issuer))
		err := v.Validate(claims)
		return err == nil
	})

	if !ok {
		return nil, ErrInvalidClaims
	}

	if slicesx.GreaterThen(0, issuer.Subjects...) {
		ok = slices.ContainsFunc(issuer.Subjects, func(subject string) bool {
			v := jwt.NewValidator(jwt.WithSubject(subject))
			err := v.Validate(claims)
			return err == nil
		})
		if !ok {
			return nil, ErrInvalidClaims
		}
	}

	var subject = ""
	if subjectClaim, ok := claims["sub"]; ok {
		if subject, ok = subjectClaim.(string); !ok {
			return nil, ErrInvalidClaims
		}
	}

	clientID := ""
	for _, claimString := range issuer.ClientIDClaims {
		clientID, ok = claims[claimString].(string)
		if ok {
			break
		}
	}

	claim := &OidcAuthClaim{
		Subject:  subject,
		Scopes:   make(map[string]bool),
		ClientID: clientID,
	}

	if scopeKey, ok := claims["scope"]; ok {
		if scope, ok := scopeKey.(string); ok {
			for s := range strings.SplitSeq(scope, " ") {
				claim.Scopes[s] = true
			}
		}
	}

	return claim, nil
}
