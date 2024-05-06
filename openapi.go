package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	middleware "github.com/oapi-codegen/fiber-middleware"
)

// ErrNoAuthzContext is the error returned when the context is not found.
var ErrNoAuthzContext = errors.New("no authz context")

// AuthzContext is the type of the context key.
type AuthzContext struct {
	Principal AuthzPrincipal
	Object    AuthzObject
	Action    AuthzAction
}

// NewAuthzContext is the constructor for the AuthzContext.
func NewAuthzContext(principal AuthzPrincipal, object AuthzObject, action AuthzAction) AuthzContext {
	return AuthzContext{
		Principal: principal,
		Object:    object,
		Action:    action,
	}
}

// AuthzExtractor is the interface that wraps the Extract method.
type AuthzExtractor func(c *fiber.Ctx) (AuthzPrincipal, AuthzObject, AuthzAction, error)

// DefaultAuthzExtractor is the default authz extractor.
func DefaultAuthzExtractor(c *fiber.Ctx) (AuthzPrincipal, AuthzObject, AuthzAction, error) {
	return AuthzNoPrincipial, AuthzNoObject, AuthzNoAction, nil
}

// OpenAPIAuthenticatorOpts are the OpenAPI authenticator options.
type OpenAPIAuthenticatorOpts struct {
	AuthzPrincipalResolver AuthzPrincipalResolver
	AuthzObjectResolver    AuthzObjectResolver
	AuthzActionResolver    AuthzActionResolver
	AuthzChecker           AuthzChecker
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
func WithAuthzPrincipalResolver(resolver AuthzPrincipalResolver) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzPrincipalResolver = resolver
	}
}

// WithAuthzObjectResolver sets the authz extractor.
func WithAuthzObjectResolver(resolver AuthzObjectResolver) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzObjectResolver = resolver
	}
}

// WithAuthzActionResolver sets the authz extractor.
func WithAuthzActionResolver(resolver AuthzActionResolver) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzActionResolver = resolver
	}
}

// WithAuthzChecker sets the authz checker.
func WithAuthzChecker(checker AuthzChecker) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.AuthzChecker = checker
	}
}

// NewOpenAPIErrorHandler creates a new OpenAPI error handler.
func NewOpenAPIErrorHandler() middleware.ErrorHandler {
	return func(c *fiber.Ctx, message string, statusCode int) {
		c.Status(statusCode).JSON(map[string]interface{}{
			"message": message,
			"code":    statusCode,
		})
	}
}

// NewOpenAPIAuthenticator creates a new OpenAPI authenticator.
func NewOpenAPIAuthenticator(opts ...OpenAPIAuthenticatorOpt) openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
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

		authzCtx := NewAuthzContext(principal, object, action)
		authCtx := context.WithValue(usrCtx, authzContext, authzCtx)

		// nolint: contextcheck
		c.SetUserContext(authCtx)

		return nil
	}
}

// GetAuthzContext extracts the AuthzContext from the context.
func GetAuthzContext(ctx context.Context) (AuthzContext, error) {
	key := ctx.Value(authzContext)

	if key == nil {
		return AuthzContext{}, ErrNoAuthzContext
	}

	return key.(AuthzContext), nil
}
