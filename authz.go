// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package authz

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

// Principal is the subject.
type Principal string

// String is the stringer implementation.
func (a Principal) String() string {
	return string(a)
}

// Object is the object.
type Object string

// String is the stringer implementation.
func (a Object) String() string {
	return string(a)
}

// Action is the action.
type Action string

// String is the stringer implementation.
func (a Action) String() string {
	return string(a)
}

const (
	NoPrincipial Principal = ""
	NoObject     Object    = ""
	NoAction     Action    = ""
)

// Params is the struct that holds the principal, object and action from the context.
// There needs to be a :principal, :object and :action in the context.
type Params struct {
	// Principal is the subject.
	Principal Principal `json:"principal" params:"principal" query:"principal" form:"principal"`
	// Object is the object.
	Object Object `json:"object" params:"object" query:"object" form:"object"`
	// Action is the action.
	Action Action `json:"action" params:"action" query:"action" form:"action"`
}

// Checker is the interface that wraps the Allowed method.
type Checker interface {
	// Allowed ...
	Allowed(context.Context, Principal, Object, Action) (bool, error)
}

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context.
const (
	authzPrincipial contextKey = iota
	authzObject
	authzAction
	authzContext
)

// Unimplemented is the default implementation.
type Unimplemented struct{}

// Allowed is the default implementation.
func (u *Unimplemented) Allowed(_ context.Context, _ Principal, _ Object, _ Action) (bool, error) {
	return false, nil
}

var _ Checker = (*Fake)(nil)

// Fake is a fake authz checker.
type Fake struct {
	allowd bool
}

// NewFake returns a new Fake authz checker.
func NewFake(allowed bool) *Fake {
	return &Fake{allowd: allowed}
}

// Allowed returns true if the principal is allowed to perform the action on the object.
func (f *Fake) Allowed(_ context.Context, _ Principal, _ Object, _ Action) (bool, error) {
	return f.allowd, nil
}

// Config ...
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// Checker is implementing the AuthzChecker interface.
	Checker Checker

	// ObjectResolver is the object resolver.
	ObjectResolver ObjectResolver

	// ActionResolver is the action resolver.
	ActionResolver ActionResolver

	// PrincipalResolver is the principal resolver.
	PrincipalResolver PrincipalResolver

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

// default ErrorHandler that process return error from fiber.Handler.
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrBadRequest
}

// ObjectResolver is the interface that wraps the Resolve method.
type ObjectResolver interface {
	// Resolve ...
	Resolve(c *fiber.Ctx) (Object, error)
}

// PrincipalResolver is the interface that wraps the Resolve method.
type PrincipalResolver interface {
	// Resolve ...
	Resolve(c *fiber.Ctx) (Principal, error)
}

// ActionResolver is the interface that wraps the Resolve method.
type ActionResolver interface {
	// Resolve ...
	Resolve(c *fiber.Ctx) (Action, error)
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
			Principal  Principal `json:"principal"`
			Object     Object    `json:"object"`
			Permission Action    `json:"action"`
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

// Helper function to set default values.
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
func (n *noopObjectResolver) Resolve(_ *fiber.Ctx) (Object, error) {
	return NoObject, nil
}

// NewNoopObjectResolver ...
func NewNoopObjectResolver() ObjectResolver {
	return &noopObjectResolver{}
}

type noopPrincipalResolver struct{}

// Resolve ...
func (n *noopPrincipalResolver) Resolve(_ *fiber.Ctx) (Principal, error) {
	return NoPrincipial, nil
}

// NewNoopPrincipalResolver ...
func NewNoopPrincipalResolver() PrincipalResolver {
	return &noopPrincipalResolver{}
}

type noopActionResolver struct{}

// Resolve ...
func (n *noopActionResolver) Resolve(_ *fiber.Ctx) (Action, error) {
	return NoAction, nil
}

// NewNoopActionResolver ...
func NewNoopActionResolver() ActionResolver {
	return &noopActionResolver{}
}
