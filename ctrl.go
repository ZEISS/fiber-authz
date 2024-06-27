package authz

import "github.com/gofiber/fiber/v2"

// AuthzController is the controller that holds the authz checker.
type AuthzController interface {
	// Resolve is the resolver.
	Resolve(ctx *fiber.Ctx) (AuthzPrincipal, AuthzObject, AuthzAction, error)
}

var _ AuthzController = (*DefaultAuthzController)(nil)

// DefaultAuthzController is the default implementation of the AuthzController.
type DefaultAuthzController struct{}

// NewDefaultAuthzController returns a new DefaultAuthzController.
func NewDefaultAuthzController() *DefaultAuthzController {
	return &DefaultAuthzController{}
}

// ResolvePrincipal is the principal resolver.
func (d *DefaultAuthzController) Resolve(ctx *fiber.Ctx) (AuthzPrincipal, AuthzObject, AuthzAction, error) {
	return AuthzNoPrincipial, AuthzNoObject, AuthzNoAction, nil
}
