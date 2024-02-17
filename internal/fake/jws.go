package fake

import (
	"crypto/ecdsa"
	"fmt"

	authz "github.com/zeiss/fiber-authz"

	"github.com/deepmap/oapi-codegen/v2/pkg/ecdsafile"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const PrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOzvxuSyKba6j5FPvQCqaZgi5KMgKAAPE4Edy9faahy5oAoGCCqGSM49
AwEHoUQDQgAE0enr2vXtwd7YoRFVNbpR9u7oHtb+aibaEhHHvR9/BdIHTyhIkwZp
ojFjRZ6fg9P+5yf093er5VWaRd5ndMFqLg==
-----END EC PRIVATE KEY-----`

const (
	KeyID            = "fake-key-id"
	FakeIssuer       = "fake-issuer"
	FakeAudience     = "fake-users"
	PermissionsClaim = "perm"
)

type FakeAuthenticator struct {
	PrivateKey *ecdsa.PrivateKey
	KeySet     jwk.Set
}

var _ authz.JWSValidator = (*FakeAuthenticator)(nil)

// NewFakeAuthenticator ...
func NewFakeAuthenticator() (*FakeAuthenticator, error) {
	privKey, err := ecdsafile.LoadEcdsaPrivateKey([]byte(PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("loading PEM private key: %w", err)
	}

	set := jwk.NewSet()
	pubKey := jwk.NewECDSAPublicKey()

	err = pubKey.FromRaw(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing jwk key: %w", err)
	}

	err = pubKey.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("setting key algorithm: %w", err)
	}

	err = pubKey.Set(jwk.KeyIDKey, KeyID)
	if err != nil {
		return nil, fmt.Errorf("setting key ID: %w", err)
	}

	set.Add(pubKey)

	return &FakeAuthenticator{PrivateKey: privKey, KeySet: set}, nil
}

// ValidateJWS ...
func (f *FakeAuthenticator) ValidateJWS(jwsString string) (jwt.Token, error) {
	return jwt.Parse([]byte(jwsString), jwt.WithKeySet(f.KeySet),
		jwt.WithAudience(FakeAudience), jwt.WithIssuer(FakeIssuer))
}

// SignToken ...
func (f *FakeAuthenticator) SignToken(t jwt.Token) ([]byte, error) {
	hdr := jws.NewHeaders()

	if err := hdr.Set(jws.AlgorithmKey, jwa.ES256); err != nil {
		return nil, fmt.Errorf("setting algorithm: %w", err)
	}

	if err := hdr.Set(jws.TypeKey, "JWT"); err != nil {
		return nil, fmt.Errorf("setting type: %w", err)
	}

	if err := hdr.Set(jws.KeyIDKey, KeyID); err != nil {
		return nil, fmt.Errorf("setting Key ID: %w", err)
	}

	return jwt.Sign(t, jwa.ES256, f.PrivateKey, jwt.WithHeaders(hdr))
}

// CreateJWSWithClaims is a helper function to create JWT's with the specified
// claims.
func (f *FakeAuthenticator) CreateJWSWithClaims(claims []string) ([]byte, error) {
	t := jwt.New()

	err := t.Set(jwt.IssuerKey, FakeIssuer)
	if err != nil {
		return nil, fmt.Errorf("setting issuer: %w", err)
	}

	err = t.Set(jwt.AudienceKey, FakeAudience)
	if err != nil {
		return nil, fmt.Errorf("setting audience: %w", err)
	}

	err = t.Set(PermissionsClaim, claims)
	if err != nil {
		return nil, fmt.Errorf("setting permissions: %w", err)
	}

	return f.SignToken(t)
}
