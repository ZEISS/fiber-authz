package authz

import "github.com/gofiber/fiber/v2"

// AuthzController is the controller that holds the 3-factors to authenticate.
type AuthzController interface {
	// GetPrincipial returns the principal.
	GetPrincipial(ctx *fiber.Ctx) (AuthzPrincipal, error)
	// GetObject returns the object.
	GetObject(ctx *fiber.Ctx) (AuthzObject, error)
	// GetAction returns the action.
	GetAction(ctx *fiber.Ctx) (AuthzAction, error)
}

var _ AuthzController = (*DefaultAuthzController)(nil)

// DefaultAuthzController is the default implementation of the AuthzController.
type DefaultAuthzController struct {
	PrincipalResolver AuthzPrincipalResolver
	ObjectResolver    AuthzObjectResolver
	ActionResolver    AuthzActionResolver
}

// NewDefaultAuthzController returns a new DefaultAuthzController.
func NewDefaultAuthzController(pr AuthzPrincipalResolver, or AuthzObjectResolver, ar AuthzActionResolver) *DefaultAuthzController {
	return &DefaultAuthzController{}
}

// GetPrincipial returns the principal.
func (d *DefaultAuthzController) GetPrincipial(ctx *fiber.Ctx) (AuthzPrincipal, error) {
	return d.PrincipalResolver.Resolve(ctx)
}

// GetObject returns the object.
func (d *DefaultAuthzController) GetObject(ctx *fiber.Ctx) (AuthzObject, error) {
	return d.ObjectResolver.Resolve(ctx)
}

// GetAction returns the action.
func (d *DefaultAuthzController) GetAction(ctx *fiber.Ctx) (AuthzAction, error) {
	return d.ActionResolver.Resolve(ctx)
}
