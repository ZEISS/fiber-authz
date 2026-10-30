package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	middleware "github.com/oapi-codegen/fiber-middleware"
)

// ErrNoContext is the error returned when the context is not found.
var ErrNoContext = errors.New("no authz context")

// Context is the type of the context key.
type Context struct {
	Principal Principal
	Object    Object
	Action    Action
}

// NewContext is the constructor for the Context.
func NewContext(principal Principal, object Object, action Action) Context {
	return Context{
		Principal: principal,
		Object:    object,
		Action:    action,
	}
}

// Extractor is the interface that wraps the Extract method.
type Extractor func(c *fiber.Ctx) (Principal, Object, Action, error)

// DefaultExtractor is the default authz extractor.
func DefaultExtractor(_ *fiber.Ctx) (Principal, Object, Action, error) {
	return NoPrincipial, NoObject, NoAction, nil
}

// OpenAPIAuthenticatorOpts are the OpenAPI authenticator options.
type OpenAPIAuthenticatorOpts struct {
	AuthzPrincipalResolver PrincipalResolver
	AuthzObjectResolver    ObjectResolver
	AuthzActionResolver    ActionResolver
	AuthzChecker           Checker
}

// Conigure the OpenAPI authenticator.
func (o *OpenAPIAuthenticatorOpts) Conigure(opts ...OpenAPIAuthenticatorOpt) {
	for _, opt := range opts {
		opt(o)
	}
}

// OpenAPIAuthenticatorOpt is a function that sets an option on the OpenAPI authenticator.
type OpenAPIAuthenticatorOpt func(*OpenAPIAuthenticatorOpts)

// OpenAPIAuthenticatorDefaultOpts are the default OpenAPI authenticator options.
func OpenAPIAuthenticatorDefaultOpts() OpenAPIAuthenticatorOpts {
	return OpenAPIAuthenticatorOpts{
		AuthzChecker:           NewNoop(),
		AuthzPrincipalResolver: NewNoopPrincipalResolver(),
		AuthzObjectResolver:    NewNoopObjectResolver(),
		AuthzActionResolver:    NewNoopActionResolver(),
	}
}

// WithAuthzPrincipalResolver sets the authz extractor.
func WithAuthzPrincipalResolver(resolver PrincipalResolver) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzPrincipalResolver = resolver
	}
}

// WithAuthzObjectResolver sets the authz extractor.
func WithAuthzObjectResolver(resolver ObjectResolver) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzObjectResolver = resolver
	}
}

// WithAuthzActionResolver sets the authz extractor.
func WithAuthzActionResolver(resolver ActionResolver) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzActionResolver = resolver
	}
}

// WithAuthzChecker sets the authz checker.
func WithAuthzChecker(checker Checker) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzChecker = checker
	}
}

// NewOpenAPIErrorHandler creates a new OpenAPI error handler.
func NewOpenAPIErrorHandler() middleware.ErrorHandler {
	return func(c *fiber.Ctx, message string, statusCode int) {
		c.Status(statusCode).JSON(map[string]any{
			"message": message,
			"code":    statusCode,
		})
	}
}

// NewOpenAPIAuthenticator creates a new OpenAPI authenticator.
func NewOpenAPIAuthenticator(opts ...OpenAPIAuthenticatorOpt) openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, _ *openapi3filter.AuthenticationInput) error {
		options := OpenAPIAuthenticatorDefaultOpts()
		options.Conigure(opts...)

		c := middleware.GetFiberContext(ctx)

		principal, err := options.AuthzPrincipalResolver.Resolve(c)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Errorf("error resolving principal: %w", err).Error())
		}

		object, err := options.AuthzObjectResolver.Resolve(c)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Errorf("error resolving object: %w", err).Error())
		}

		action, err := options.AuthzActionResolver.Resolve(c)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Errorf("error resolving action: %w", err).Error())
		}

		allowed, err := options.AuthzChecker.Allowed(ctx, principal, object, action)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
		}

		if !allowed {
			return fiber.NewError(fiber.StatusForbidden, "forbidden")
		}

		// Create a new context for the authz context.
		usrCtx := c.UserContext()

		authzCtx := NewContext(principal, object, action)
		authCtx := context.WithValue(usrCtx, authzContext, authzCtx)

		c.SetUserContext(authCtx)

		return nil
	}
}

// GetContext extracts the Context from the context.
func GetContext(ctx context.Context) (Context, error) {
	key := ctx.Value(authzContext)

	if key == nil {
		return Context{}, ErrNoContext
	}

	return key.(Context), nil
}
