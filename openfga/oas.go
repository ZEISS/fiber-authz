package openfga

import (
	"context"
	"fmt"
	"net/url"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/mitchellh/mapstructure"
	middleware "github.com/oapi-codegen/fiber-middleware"
)

// DefaultExtensionName is the default extension name.
const DefaultExtensionName = "x-fiber-authz-fga"

// ErrNoFGAAuthzBuilderExtensionFound is an error that indicates that no FGA authz builder extension was found.
var ErrNoFGAAuthzBuilderExtensionFound = fmt.Errorf("no FGA authz builder extension found")

// OasFGAAuthzOptionComponent ...
type OasFGAAuthzOptionComponent struct {
	// In is the location of the component.
	In string `json:"in" mapstructure:"in"`
	// Name is the name of the component.
	Name string `json:"name" mapstructure:"name"`
	// Type is the type of the component.
	Type string `json:"type" mapstructure:"type"`
}

// OasFGAAuthzOption ...
type OasFGAAuthzOption struct {
	// Namespace is the namespace of the option.
	Namespace string `json:"namespace" mapstructure:"namespace"`
	// Name is the name of the option.
	Name string `json:"name" mapstructure:"name"`
	// Separator is the separator of the option.
	Separator string `json:"separator" mapstructure:"separator"`
	// Components is the components of the option.
	Components []OasFGAAuthzOptionComponent `json:"components" mapstructure:"components"`
	// AuthType is the auth type of the option.
	AuthType string `json:"auth_type" mapstructure:"auth_type"`
}

// OasFGAAuthzOptions ...
type OasFGAAuthzOptions struct {
	// User is the user option.
	User OasFGAAuthzOption `json:"user" mapstructure:"user"`
	// Relation is the relation option.
	Relation OasFGAAuthzOption `json:"relation" mapstructure:"relation"`
	// Object is the object option.
	Object OasFGAAuthzOption `json:"object" mapstructure:"object"`
}

// OasFGABuilder ...
type OasFGABuilder interface {
	// BuildWithContext builds a user, relation, and object with a context.
	BuildWithContext(ctx context.Context, input *openapi3filter.AuthenticationInput) (User, Relation, Object, error)
}

// OasFGAAuthzBuilder ...
type OasFGAAuthzBuilder struct {
	opts OasFGAAuthzBuilderOpts
}

// OasFGAAuthzBuilderOpts ...
type OasFGAAuthzBuilderOpts struct {
	// PropertyName ...
	PropertyName string
}

// Configure sets the configuration for the builder.
func (c *OasFGAAuthzBuilderOpts) Configure(opts ...OasFGAAuthzBuilderOpt) {
	for _, opt := range opts {
		opt(c)
	}
}

// OasFGAAuthzBuilderOpt ...
type OasFGAAuthzBuilderOpt func(*OasFGAAuthzBuilderOpts)

// NewOasFGAAuthzBuilder ...
func NewOasFGAAuthzBuilder(opts ...OasFGAAuthzBuilderOpt) *OasFGAAuthzBuilder {
	builder := new(OasFGAAuthzBuilder)

	options := DefaultOasFGAAuthzBuilderOpts()
	options.Configure(opts...)

	builder.opts = options

	return builder
}

// DefaultOasFGAAuthzBuilderOpts ...
func DefaultOasFGAAuthzBuilderOpts() OasFGAAuthzBuilderOpts {
	return OasFGAAuthzBuilderOpts{
		PropertyName: DefaultExtensionName,
	}
}

// WithOasFGAAuthzBuilderPropertyName sets the property name for the builder.
func WithOasFGAAuthzBuilderPropertyName(name string) OasFGAAuthzBuilderOpt {
	return func(o *OasFGAAuthzBuilderOpts) {
		o.PropertyName = name
	}
}

// BuildWithContext ...
func (f *OasFGAAuthzBuilder) BuildWithContext(ctx context.Context, input *openapi3filter.AuthenticationInput) (User, Relation, Object, error) {
	opts := &OasFGAAuthzOptions{}

	ext, ok := input.RequestValidationInput.Route.Operation.Extensions[f.opts.PropertyName]
	if !ok {
		return NoopUser, NoopRelation, NoopObject, ErrNoFGAAuthzBuilderExtensionFound
	}

	err := mapstructure.Decode(ext, opts)
	if err != nil {
		return NoopUser, NoopRelation, NoopObject, err
	}

	return BuildUser(ctx, input, opts), BuildRelation(ctx, input, opts), BuildObject(ctx, input, opts), nil
}

// BuildUser is a function that builds a user.
func BuildUser(ctx context.Context, input *openapi3filter.AuthenticationInput, opts *OasFGAAuthzOptions) User {
	return NewUser(Namespace(opts.User.Namespace), OidcSubject(ctx))
}

// Object ...
func BuildObject(ctx context.Context, input *openapi3filter.AuthenticationInput, opts *OasFGAAuthzOptions) Object {
	ss := []string{}

	for _, c := range opts.Object.Components {
		switch c.In {
		case "path":
			ss = append(ss, PathParams(input.RequestValidationInput.PathParams, c.Name))
		case "query":
			ss = append(ss, QueryParams(input.RequestValidationInput.GetQueryParams(), c.Name))
		default:
			ss = append(ss, "")
		}
	}

	return NewObject(Namespace(opts.Object.Namespace), String(opts.Object.Name), Join(opts.Object.Separator, ss...))
}

// BuildRelation ...
func BuildRelation(ctx context.Context, input *openapi3filter.AuthenticationInput, opts *OasFGAAuthzOptions) Relation {
	return NewRelation(Namespace(opts.Relation.Namespace), String(opts.Relation.Name))
}

// OasAuthenticateOpts is a configuration for the authenticator.
type OasAuthenticateOpts struct {
	Checker Checker
	Builder OasFGABuilder
	Next    OasAuthenticateNextFunc
}

// OasAuthenticateNextFunc is a function that determines if the next function should be called.
type OasAuthenticateNextFunc func(context.Context, *openapi3filter.AuthenticationInput) bool

// DefaultOasAuthenticateNextFunc is the default next function for the authenticator.
func DefaultOasAuthenticateNextFunc(name string) OasAuthenticateNextFunc {
	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) bool {
		_, ok := input.RequestValidationInput.Route.Operation.Extensions[name]

		return !ok
	}
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
		Next:    DefaultOasAuthenticateNextFunc(DefaultExtensionName),
	}
}

// WithBuilder sets the builder for the authenticator.
func WithBuilder(builder OasFGABuilder) OasAuthenticateOpt {
	return func(o *OasAuthenticateOpts) {
		o.Builder = builder
	}
}

// WithChecker sets the checker for the authenticator.
func WithChecker(checker Checker) OasAuthenticateOpt {
	return func(o *OasAuthenticateOpts) {
		o.Checker = checker
	}
}

// OasAuthenticate is an authentication function that uses the FGA authz builder and checker.
func OasAuthenticate(opts ...OasAuthenticateOpt) openapi3filter.AuthenticationFunc {
	options := OasDefaultAuthenticateOpts()
	options.Configure(opts...)

	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		c := middleware.GetFiberContext(ctx)

		if options.Next != nil && options.Next(ctx, input) {
			return nil
		}

		// nolint:contextcheck
		user, relation, object, err := options.Builder.BuildWithContext(c.UserContext(), input)
		if err != nil {
			return err
		}

		log.Debugw("OasAuthenticate", "user", user, "relation", relation, "object", object)

		allowed, err := options.Checker.Allowed(ctx, user, relation, object)
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

// Authenticate evalutes the authentication functions in the order they are provided.
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

// PathParams extracts the path parameter from the path parameters.
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

// QueryParams extracts the query parameter from the query parameters.
func QueryParams(values url.Values, name string, v ...string) string {
	return values.Get(name)
}
