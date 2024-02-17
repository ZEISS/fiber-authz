// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package authz

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// AuthzPrincipal ...
type AuthzPrincipal string

// String ...
func (a AuthzPrincipal) String() string {
	return string(a)
}

// AuthzUser ...
type AuthzUser string

// String ...
func (a AuthzUser) String() string {
	return string(a)
}

// AuthzPermission ...
type AuthzPermission string

// String ...
func (a AuthzPermission) String() string {
	return string(a)
}

const (
	AuthzNoPrincipial = ""
	AuthzNoUser       = ""
	AuthzNoPermission = ""
)

// AuthzPermissionDefaults are the default permissions.
const (
	Read       AuthzPermission = "read"
	Write      AuthzPermission = "write"
	Admin      AuthzPermission = "admin"
	SuperAdmin AuthzPermission = "superadmin"
)

// AuthzChecker is the interface that wraps the Allowed method.
type AuthzChecker interface {
	// Allowed ...
	Allowed(context.Context, AuthzPrincipal, AuthzUser, AuthzPermission) (bool, error)
}

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context
const (
	authzPrincipial contextKey = iota
	authzUser
	authzPermission
)

// Unimplemented is the default implementation.
type Unimplemented struct{}

// Allowed is the default implementation.
func (u *Unimplemented) Allowed(_ context.Context, _ AuthzPrincipal, _ AuthzUser, _ AuthzPermission) (bool, error) {
	return false, nil
}

var _ AuthzChecker = (*defaultChecker)(nil)

type defaultChecker struct {
	db *gorm.DB
}

// DefaultChecker returns a default implementation of the AuthzChecker interface.
func DefaultChecker(db *gorm.DB) *defaultChecker {
	return &defaultChecker{db}
}

// Allowed is the default implementation.
func (d *defaultChecker) Allowed(ctx context.Context, principal AuthzPrincipal, user AuthzUser, permission AuthzPermission) (bool, error) {
	var allowed int64
	d.db.Raw("SELECT COUNT(1) FROM vw_user_principal_permissions WHERE user_id = ? AND principal_id = ? AND permission = ?", user, principal, permission).Count(&allowed)

	if allowed > 0 {
		return true, nil
	}

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
func SetAuthzHandler(fn func(ctx context.Context) (AuthzPrincipal, AuthzUser, error)) func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		principal, user, err := fn(c.Context())
		if err != nil {
			return err
		}

		return ContextWithAuthz(c, principal, user).Next()
	}
}

// NewProtectedHandler ...
func NewProtectedHandler(handler fiber.Handler, permission AuthzPermission, config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c *fiber.Ctx) error {
		principal, user, err := AuthzFromContext(c)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		allowed, err := cfg.Checker.Allowed(c.Context(), principal, user, permission)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		if !allowed {
			return c.SendStatus(403)
		}

		return handler(c)
	}
}

// ContextWithAuthz ...
func ContextWithAuthz(ctx *fiber.Ctx, principal AuthzPrincipal, user AuthzUser) *fiber.Ctx {
	ctx.Locals(authzPrincipial, principal)
	ctx.Locals(authzUser, user)

	return ctx
}

// AuthzFromContext ...
func AuthzFromContext(ctx *fiber.Ctx) (AuthzPrincipal, AuthzUser, error) {
	principal := ctx.Locals(authzPrincipial)
	user := ctx.Locals(authzUser)

	return principal.(AuthzPrincipal), user.(AuthzUser), nil
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	return cfg
}
