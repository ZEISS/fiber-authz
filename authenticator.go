package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	PermissionsClaim = "perms"
)

var (
	ErrNoAuthHeader      = errors.New("authorization header is missing")
	ErrInvalidAuthHeader = errors.New("authorization header is malformed")
	ErrClaimsInvalid     = errors.New("provided claims do not match expected scopes")
)

// JWSValidator ...
type JWSValidator interface {
	ValidateJWS(jws string) (jwt.Token, error)
}

// NewAuthenticator ...
func NewAuthenticator(c AuthzChecker, v JWSValidator) openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		return Authenticate(ctx, c, v, input)
	}
}

// ErrForbidden ...
var ErrForbidden = errors.New("forbidden")

// Authenticate ...
func Authenticate(ctx context.Context, checker AuthzChecker, validate JWSValidator, input *openapi3filter.AuthenticationInput) error {
	if input.SecuritySchemeName != "BearerAuth" {
		return fmt.Errorf("security scheme %s != 'BearerAuth'", input.SecuritySchemeName)
	}

	jws, err := GetJWSFromRequest(input.RequestValidationInput.Request)
	if err != nil {
		return fmt.Errorf("getting jws: %w", err)
	}

	token, err := validate.ValidateJWS(jws)
	if err != nil {
		return fmt.Errorf("validating JWS: %w", err)
	}

	err = CheckTokenClaims(input.Scopes, token)
	if err != nil {
		return fmt.Errorf("token claims don't match: %w", err)
	}

	// allowed, err := checker.Allowed(ctx)
	// if err != nil {
	// 	return ErrForbidden
	// }

	// if allowed {
	// 	return nil
	// }

	return ErrForbidden
}

// GetClaimsFromToken ...
func GetClaimsFromToken(t jwt.Token) ([]string, error) {
	rawPerms, found := t.Get(PermissionsClaim)
	if !found {
		return make([]string, 0), nil
	}

	rawList, ok := rawPerms.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' claim is unexpected type'", PermissionsClaim)
	}

	claims := make([]string, len(rawList))

	for i, rawClaim := range rawList {
		var ok bool
		claims[i], ok = rawClaim.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] is not a string", PermissionsClaim, i)
		}
	}

	return claims, nil
}

// GetJWSFromRequest ...
func GetJWSFromRequest(req *http.Request) (string, error) {
	authHdr := req.Header.Get("Authorization")
	// Check for the Authorization header.
	if authHdr == "" {
		return "", ErrNoAuthHeader
	}

	// We expect a header value of the form "Bearer <token>", with 1 space after
	// Bearer, per spec.
	prefix := "Bearer "
	if !strings.HasPrefix(authHdr, prefix) {
		return "", ErrInvalidAuthHeader
	}

	return strings.TrimPrefix(authHdr, prefix), nil
}

// CheckTokenClaims ...
func CheckTokenClaims(expectedClaims []string, t jwt.Token) error {
	claims, err := GetClaimsFromToken(t)
	if err != nil {
		return fmt.Errorf("getting claims from token: %w", err)
	}
	// Put the claims into a map, for quick access.
	claimsMap := make(map[string]bool, len(claims))
	for _, c := range claims {
		claimsMap[c] = true
	}

	for _, e := range expectedClaims {
		if !claimsMap[e] {
			return ErrClaimsInvalid
		}
	}
	return nil
}
