// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package authz

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

// AuthzPrincipal is the subject.
type AuthzPrincipal string

// String is the stringer implementation.
func (a AuthzPrincipal) String() string {
	return string(a)
}

// AuthzObject is the object.
type AuthzObject string

// String is the stringer implementation.
func (a AuthzObject) String() string {
	return string(a)
}

// AuthzAction is the action.
type AuthzAction string

// String is the stringer implementation.
func (a AuthzAction) String() string {
	return string(a)
}

const (
	AuthzNoPrincipial AuthzPrincipal = ""
	AuthzNoObject     AuthzObject    = ""
	AuthzNoAction     AuthzAction    = ""
)

// AuthzParams is the struct that holds the principal, object and action from the context.
// There needs to be a :principal, :object and :action in the context.
type AuthzParams struct {
	// Principal is the subject.
	Principal AuthzPrincipal `json:"principal" params:"principal" query:"principal" form:"principal"`
	// Object is the object.
	Object AuthzObject `json:"object" params:"object" query:"object" form:"object"`
	// Action is the action.
	Action AuthzAction `json:"action" params:"action" query:"action" form:"action"`
}

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
	authzContext
)

// Unimplemented is the default implementation.
type Unimplemented struct{}

// Allowed is the default implementation.
func (u *Unimplemented) Allowed(_ context.Context, _ AuthzPrincipal, _ AuthzObject, _ AuthzAction) (bool, error) {
	return false, nil
}

var _ AuthzChecker = (*Fake)(nil)

// Fake is a fake authz checker.
type Fake struct {
	allowd bool
}

// NewFake returns a new Fake authz checker.
func NewFake(allowed bool) *Fake {
	return &Fake{allowd: allowed}
}

// Allowed returns true if the principal is allowed to perform the action on the object.
func (f *Fake) Allowed(_ context.Context, _ AuthzPrincipal, _ AuthzObject, _ AuthzAction) (bool, error) {
	return f.allowd, nil
}

// Config ...
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// Checker is implementing the AuthzChecker interface.
	Checker AuthzChecker

	// ObjectResolver is the object resolver.
	ObjectResolver AuthzObjectResolver

	// ActionResolver is the action resolver.
	ActionResolver AuthzActionResolver

	// PrincipalResolver is the principal resolver.
	PrincipalResolver AuthzPrincipalResolver

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler:      defaultErrorHandler,
	ObjectResolver:    NewNoopObjectResolver(),
	PrincipalResolver: NewNoopPrincipalResolver(),
	ActionResolver:    NewNoopActionResolver(),
	Checker:           NewNoop(),
}

// default ErrorHandler that process return error from fiber.Handler
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrBadRequest
}

// AuthzObjectResolver is the interface that wraps the Resolve method.
type AuthzObjectResolver interface {
	// Resolve ...
	Resolve(c *fiber.Ctx) (AuthzObject, error)
}

// AuthzPrincipalResolver is the interface that wraps the Resolve method.
type AuthzPrincipalResolver interface {
	// Resolve ...
	Resolve(c *fiber.Ctx) (AuthzPrincipal, error)
}

// AuthzActionResolver is the interface that wraps the Resolve method.
type AuthzActionResolver interface {
	// Resolve ...
	Resolve(c *fiber.Ctx) (AuthzAction, error)
}

// Authenticate is a middleware that sets the principal and user in the context.
func Authenticate(handler fiber.Handler, config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		object, err := cfg.ObjectResolver.Resolve(c)
		if err != nil {
			return err
		}

		principal, err := cfg.PrincipalResolver.Resolve(c)
		if err != nil {
			return err
		}

		action, err := cfg.ActionResolver.Resolve(c)
		if err != nil {
			return err
		}

		allowed, err := cfg.Checker.Allowed(c.Context(), principal, object, action)
		if err != nil {
			return cfg.ErrorHandler(c, err)
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
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		payload := struct {
			Principal  AuthzPrincipal `json:"principal"`
			Object     AuthzObject    `json:"object"`
			Permission AuthzAction    `json:"action"`
		}{}

		if err := c.BodyParser(&payload); err != nil {
			return cfg.ErrorHandler(c, err)
		}

		allowed, err := cfg.Checker.Allowed(c.Context(), payload.Principal, payload.Object, payload.Permission)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		if allowed {
			return c.SendStatus(200)
		}

		return c.SendStatus(403)
	}
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	if cfg.Checker == nil {
		cfg.Checker = ConfigDefault.Checker
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = ConfigDefault.ErrorHandler
	}

	if cfg.ObjectResolver == nil {
		cfg.ObjectResolver = ConfigDefault.ObjectResolver
	}

	if cfg.PrincipalResolver == nil {
		cfg.PrincipalResolver = ConfigDefault.PrincipalResolver
	}

	if cfg.ActionResolver == nil {
		cfg.ActionResolver = ConfigDefault.ActionResolver
	}

	return cfg
}

type noopObjectResolver struct{}

// Resolve ...
func (n *noopObjectResolver) Resolve(c *fiber.Ctx) (AuthzObject, error) {
	return AuthzNoObject, nil
}

// NewNoopObjectResolver ...
func NewNoopObjectResolver() AuthzObjectResolver {
	return &noopObjectResolver{}
}

type noopPrincipalResolver struct{}

// Resolve ...
func (n *noopPrincipalResolver) Resolve(c *fiber.Ctx) (AuthzPrincipal, error) {
	return AuthzNoPrincipial, nil
}

// NewNoopPrincipalResolver ...
func NewNoopPrincipalResolver() AuthzPrincipalResolver {
	return &noopPrincipalResolver{}
}

type noopActionResolver struct{}

// Resolve ...
func (n *noopActionResolver) Resolve(c *fiber.Ctx) (AuthzAction, error) {
	return AuthzNoAction, nil
}

// NewNoopActionResolver ...
func NewNoopActionResolver() AuthzActionResolver {
	return &noopActionResolver{}
}
