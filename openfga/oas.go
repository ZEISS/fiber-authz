package openfga

import (
	"context"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	middleware "github.com/oapi-codegen/fiber-middleware"
)

// OasFGAAuthzOptionComponent ...
type OasFGAAuthzOptionComponent struct {
	In   string `json:"in"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// OasFGAAuthzOption ...
type OasFGAAuthzBuilderOption struct {
	Namespace  string                       `json:"namespace"`
	Name       string                       `json:"name"`
	Separator  string                       `json:"separator"`
	Components []OasFGAAuthzOptionComponent `json:"components"`
	AuthType   string                       `json:"auth_type"`
}

// OasFGAAuthzBuilderOptions ...
type OasFGAAuthzBuilderOptions struct {
	User     OasFGAAuthzBuilderOption `json:"user"`
	Object   OasFGAAuthzBuilderOption `json:"object"`
	Relation OasFGAAuthzBuilderOption `json:"relation"`
}

// OasBuilder ...
type OasBuilder interface {
	// BuildWithContext builds a user, relation, and object with a context.
	BuildWithContext(ctx context.Context, input *openapi3filter.AuthenticationInput) (User, Relation, Object, error)
}

// OasFGAAuthzBuilder ...
type OasFGAAuthzBuilder struct {
	Options OasFGAAuthzBuilderOptions `json:"options"`
}

// BuildWithContext ...
func (f *OasFGAAuthzBuilder) BuildWithContext(ctx context.Context, input *openapi3filter.AuthenticationInput) (User, Relation, Object, error) {
	return f.User(ctx, input), f.Relation(ctx, input), f.Object(ctx, input), nil
}

// User ...
func (f *OasFGAAuthzBuilder) User(ctx context.Context, input *openapi3filter.AuthenticationInput) User {
	return NewUser(Namespace(f.Options.User.Namespace), OidcSubject(ctx))
}

// Object ...
func (f *OasFGAAuthzBuilder) Object(ctx context.Context, input *openapi3filter.AuthenticationInput) Object {
	ss := []string{}

	for _, c := range f.Options.Object.Components {
		switch c.In {
		case "path":
			ss = append(ss, PathParams(input.RequestValidationInput.PathParams, c.Name))
		default:
			ss = append(ss, "")
		}
	}

	return NewObject(Namespace(f.Options.Object.Namespace), Join(f.Options.Object.Separator, ss...))
}

// OasAuthenticateOpts ...
type OasAuthenticateOpts struct {
	Checker Checker
	Builder OasBuilder
}

// OasAuthenticateOpts ...
func (c *OasAuthenticateOpts) Configure(opts ...OasAuthenticateOpt) {
	for _, opt := range opts {
		opt(c)
	}
}

// OasAuthenticateOpt ...
type OasAuthenticateOpt func(*OasAuthenticateOpts)

// OasDefaultAuthenticateOpts ...
func OasDefaultAuthenticateOpts() OasAuthenticateOpts {
	return OasAuthenticateOpts{
		Builder: &OasFGAAuthzBuilder{},
	}
}

// WithChecker sets the checker for the authenticator.
func WithChecker(checker Checker) OasAuthenticateOpt {
	return func(o *OasAuthenticateOpts) {
		o.Checker = checker
	}
}

// OasAuthenticate ...
func OasAuthenticate(opts ...OasAuthenticateOpt) openapi3filter.AuthenticationFunc {
	options := OasDefaultAuthenticateOpts()
	options.Configure(opts...)

	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		c := middleware.GetFiberContext(ctx)

		user, relation, object, err := options.Builder.BuildWithContext(c.UserContext(), input)
		if err != nil {
			return err
		}

		allowed, err := options.Checker.Allowed(c.UserContext(), user, relation, object)
		if err != nil {
			return fiber.ErrUnauthorized
		}

		if !allowed {
			return fiber.ErrForbidden
		}

		return nil
	}
}

// PathParam ...
func PathParams(params map[string]string, name string, v ...string) string {
	s := ""

	if len(v) > 0 {
		s = v[0]
	}

	p, ok := params[name]
	if !ok {
		return s
	}

	return p
}

// Relation ...
func (f *OasFGAAuthzBuilder) Relation(ctx context.Context, input *openapi3filter.AuthenticationInput) Relation {
	return NewRelation(String(f.Options.User.Name))
}

// ResolverFunc is a function that resolves a user, relation, and object.
type ResolverFunc func(c *fiber.Ctx) (User, Relation, Object, error)

// AuthzController is a controller that handles authorization.
type AuthzController interface {
	// Authorize authorizes a user, relation, and object.
	Authorize(c *fiber.Ctx) (User, Relation, Object, error)
}

// OperationAuthorizeFunc ...
type OperationAuthorizeFunc func(ctx context.Context, input *openapi3filter.AuthenticationInput) error

// OperationAuthorizers ...
type OperationAuthorizers map[string]OperationAuthorizeFunc

// Add is a function that adds an operation authorizer.
func (o OperationAuthorizers) Add(op string, f OperationAuthorizeFunc) {
	o[op] = f
}

// AuthorizerOpts ...
type AuthorizerOpts struct {
	// Authorizers is a map of operation authorizers.
	Authorizers OperationAuthorizers
	// DefaultAuthorizer is the default authorizer.
	DefaultAuthorizer OperationAuthorizeFunc
}

// Configure sets the configuration for the authorizer.
func (c *AuthorizerOpts) Configure(opts ...AuthorizerOpt) {
	for _, opt := range opts {
		opt(c)
	}
}

// AuthorizerOpt ...
type AuthorizerOpt func(*AuthorizerOpts)

// WithAuthorizers sets the authorizers for the authorizer.
func WithAuthorizers(authorizers OperationAuthorizers) AuthorizerOpt {
	return func(o *AuthorizerOpts) {
		o.Authorizers = authorizers
	}
}

// DefaultAuthorizer ...
var DefaultAuthorizer = func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	return fiber.ErrForbidden
}

// DefaultAuthorizerOpts returns the default authorizer options.
func DefaultAuthorizerOpts() AuthorizerOpts {
	return AuthorizerOpts{
		Authorizers:       OperationAuthorizers{},
		DefaultAuthorizer: DefaultAuthorizer,
	}
}

// // Authenticate ...
// func Authenticate(opts ...AuthorizerOpt) openapi3filter.AuthenticationFunc {
//   opts := DefaultAuthorizerOpts()

// 	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
//     auth, ok := opts.Authorizers[input.SecuritySchemeName]
//     if !ok {
//       return opts.DefaultAuthorizer(ctx, input)
//     }

//     err := auth(ctx, input)
//     if err != nil {
//       return err
//     }

//     return auth(ctx, input)
// 	}
// }
