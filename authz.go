// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package authz

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

// AuthzPrincipal ...
type AuthzPrincipal string

// String ...
func (a AuthzPrincipal) String() string {
	return string(a)
}

// AuthzObject ...
type AuthzObject string

// String ...
func (a AuthzObject) String() string {
	return string(a)
}

// AuthzAction ...
type AuthzAction string

// String ...
func (a AuthzAction) String() string {
	return string(a)
}

const (
	AuthzNoPrincipial = ""
	AuthzNoObject     = ""
	AuthzNoAction     = ""
)

// AuthzActionDefaults are the default actions.
const (
	Read       AuthzAction = "read"
	Write      AuthzAction = "write"
	Admin      AuthzAction = "admin"
	SuperAdmin AuthzAction = "superadmin"
)

// AuthzChecker is the interface that wraps the Allowed method.
type AuthzChecker interface {
	// Allowed ...
	Allowed(context.Context, AuthzPrincipal, AuthzObject, AuthzAction) (bool, error)
}

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context
const (
	authzPrincipial contextKey = iota
	authzObject
	authzAction
)

// Unimplemented is the default implementation.
type Unimplemented struct{}

// Allowed is the default implementation.
func (u *Unimplemented) Allowed(_ context.Context, _ AuthzPrincipal, _ AuthzObject, _ AuthzAction) (bool, error) {
	return false, nil
}

// Config ...
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// Checker is implementing the AuthzChecker interface.
	Checker AuthzChecker

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler: defaultErrorHandler,
}

// default ErrorHandler that process return error from fiber.Handler
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrBadRequest
}

// SetAuthzHandler is a middleware that sets the principal and user in the context.
func SetAuthzHandler(fn func(ctx context.Context) (AuthzPrincipal, AuthzObject, AuthzAction, error)) func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		principal, object, action, err := fn(c.Context())
		if err != nil {
			return err
		}

		return ContextWithAuthz(c, principal, object, action).Next()
	}
}

// NewProtectedHandler ...
func NewProtectedHandler(handler fiber.Handler, action AuthzAction, config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c *fiber.Ctx) error {
		principal, user, _, err := AuthzFromContext(c)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		allowed, err := cfg.Checker.Allowed(c.Context(), principal, user, action)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		if !allowed {
			return c.SendStatus(403)
		}

		return handler(c)
	}
}

// NewCheckerHandler returns a new fiber.Handler that checks if the principal can perform the action on the object.
func NewCheckerHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c *fiber.Ctx) error {
		payload := struct {
			Principal  AuthzPrincipal `json:"principal"`
			Object     AuthzObject    `json:"object"`
			Permission AuthzAction    `json:"action"`
		}{}

		if err := c.BodyParser(&payload); err != nil {
			return defaultErrorHandler(c, err)
		}

		allowed, err := cfg.Checker.Allowed(c.Context(), payload.Principal, payload.Object, payload.Permission)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		if allowed {
			return c.SendStatus(200)
		}

		return c.SendStatus(403)
	}
}

// ContextWithAuthz ...
func ContextWithAuthz(ctx *fiber.Ctx, principal AuthzPrincipal, object AuthzObject, action AuthzAction) *fiber.Ctx {
	ctx.Locals(authzPrincipial, principal)
	ctx.Locals(authzObject, object)
	ctx.Locals(authzAction, action)

	return ctx
}

// AuthzFromContext ...
func AuthzFromContext(ctx *fiber.Ctx) (AuthzPrincipal, AuthzObject, AuthzAction, error) {
	principal := ctx.Locals(authzPrincipial)
	object := ctx.Locals(authzObject)
	action := ctx.Locals(authzAction)

	return principal.(AuthzPrincipal), object.(AuthzObject), action.(AuthzAction), nil
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	if cfg.Checker == nil {
		cfg.Checker = NewNoop()
	}

	return cfg
}
