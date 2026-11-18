package huma

import (
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/zeiss/pkg/utilx"
)

// HasEmail returns true if the user has an email address.
func HasEmail(ctx huma.Context) (bool, error) {
	email, err := GetClaim(ctx, "email")
	if err != nil {
		return false, err
	}

	return utilx.NotEmpty(email), nil
}

// GetClaim returns the value of the given claim from the token.
func GetClaim(ctx huma.Context, claim string) (string, error) {
	token, ok := ctx.Context().Value(OidcTokenKey).(*jwt.Token)
	if !ok {
		return "", errors.New("could not extract token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("could not extract claims")
	}

	value, ok := claims[claim].(string)
	if !ok {
		return "", errors.New("could not extract claim")
	}

	return value, nil
}
