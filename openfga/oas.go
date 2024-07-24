package openfga

import (
	"context"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/mitchellh/mapstructure"
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
type OasFGAAuthzBuilder struct{}

// NewOasFGAAuthzBuilder ...
func NewOasFGAAuthzBuilder() *OasFGAAuthzBuilder {
	return &OasFGAAuthzBuilder{}
}

// BuildWithContext ...
func (f *OasFGAAuthzBuilder) BuildWithContext(ctx context.Context, input *openapi3filter.AuthenticationInput) (User, Relation, Object, error) {
	opts := &OasFGAAuthzBuilderOptions{}

	ext, ok := input.RequestValidationInput.Route.Operation.Extensions["x-fiber-authz-fga"]
	if !ok {
		return NoopUser, NoopRelation, NoopObject, fmt.Errorf("no x-fiber-authz-fga extension found")
	}

	err := mapstructure.Decode(ext, opts)
	if err != nil {
		return NoopUser, NoopRelation, NoopObject, err
	}

	return f.User(ctx, input, opts), f.Relation(ctx, input, opts), f.Object(ctx, input, opts), nil
}

// User ...
func (f *OasFGAAuthzBuilder) User(ctx context.Context, input *openapi3filter.AuthenticationInput, opts *OasFGAAuthzBuilderOptions) User {
	return NewUser(Namespace(opts.User.Namespace), OidcSubject(ctx))
}

// Object ...
func (f *OasFGAAuthzBuilder) Object(ctx context.Context, input *openapi3filter.AuthenticationInput, opts *OasFGAAuthzBuilderOptions) Object {
	ss := []string{}

	for _, c := range opts.Object.Components {
		switch c.In {
		case "path":
			ss = append(ss, PathParams(input.RequestValidationInput.PathParams, c.Name))
		default:
			ss = append(ss, "")
		}
	}

	return NewObject(Namespace(opts.Object.Namespace), String(opts.Object.Name), Join(opts.Object.Separator, ss...))
}

// Relation ...
func (f *OasFGAAuthzBuilder) Relation(ctx context.Context, input *openapi3filter.AuthenticationInput, opts *OasFGAAuthzBuilderOptions) Relation {
	return NewRelation(String(opts.Relation.Name))
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
		Builder: NewOasFGAAuthzBuilder(),
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

		// nolint:contextcheck
		user, relation, object, err := options.Builder.BuildWithContext(c.UserContext(), input)
		if err != nil {
			return err
		}

		log.Debugw("OasAuthenticate", "user", user, "relation", relation, "object", object)

		allowed, err := options.Checker.Allowed(c.Context(), user, relation, object)
		if err != nil {
			return fiber.ErrUnauthorized
		}

		log.Debugw("OasAuthenticate", "allowed", allowed)

		if !allowed {
			return fiber.ErrForbidden
		}

		return nil
	}
}

// Authenticate ...
func Authenticate(fn ...openapi3filter.AuthenticationFunc) openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		for _, f := range fn {
			if err := f(ctx, input); err != nil {
				return err
			}
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
