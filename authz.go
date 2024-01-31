// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package authz

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// AuthzPrincipal ...
type AuthzPrincipal string

// AuthzUser ...
type AuthzUser string

// AuthzPermission ...
type AuthzPermission string

// String ...
func (a AuthzPermission) String() string {
	return string(a)
}

// AuthzPermissionDefaults ...
const (
	Read       AuthzPermission = "read"
	Write      AuthzPermission = "write"
	Admin      AuthzPermission = "admin"
	SuperAdmin AuthzPermission = "superadmin"
)

// AuthzChecker...
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

// Allowed ...
func (u *Unimplemented) Allowed(_ context.Context, _ AuthzPrincipal, _ AuthzUser, _ AuthzPermission) (bool, error) {
	return false, nil
}

var _ AuthzChecker = (*defaultChecker)(nil)

type defaultChecker struct {
	db *gorm.DB
}

// DefaultChecker ...
func DefaultChecker(db *gorm.DB) *defaultChecker {
	return &defaultChecker{db}
}

// Allowed ...
func (d *defaultChecker) Allowed(ctx context.Context, principal AuthzPrincipal, user AuthzUser, permission AuthzPermission) (bool, error) {
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

// NewProtectedHandler ...
func NewProtectedHandler(handler fiber.Handler, config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c *fiber.Ctx) error {
		principal, user, permission, err := AuthzFromContext(c)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		allowed, err := cfg.Checker.Allowed(c.Context(), principal, user, permission)
		if err != nil {
			return defaultErrorHandler(c, err)
		}

		if !allowed {
			return c.SendStatus(404)
		}

		return handler(c)
	}
}

// ContextWithAuthz ...
func ContextWithAuthz(ctx *fiber.Ctx, principal AuthzPrincipal, user AuthzUser, permission AuthzPermission) *fiber.Ctx {
	ctx.Set(fmt.Sprint(authzPrincipial), string(principal))
	ctx.Set(fmt.Sprint(authzUser), string(user))
	ctx.Set(fmt.Sprint(authzPermission), string(permission))

	return ctx
}

// AuthzFromContext ...
func AuthzFromContext(ctx *fiber.Ctx) (AuthzPrincipal, AuthzUser, AuthzPermission, error) {
	principal := ctx.Get(fmt.Sprint(authzPrincipial))
	user := ctx.Get(fmt.Sprint(authzUser))
	permission := ctx.Get(fmt.Sprint(authzPermission))

	return AuthzPrincipal(principal), AuthzUser(user), AuthzPermission(permission), nil
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
