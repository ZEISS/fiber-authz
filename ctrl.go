package authz

import "github.com/gofiber/fiber/v2"

// Controller is the controller that holds the 3-factors to authenticate.
type Controller interface {
	// GetPrincipial returns the principal.
	GetPrincipial(ctx *fiber.Ctx) (Principal, error)
	// GetObject returns the object.
	GetObject(ctx *fiber.Ctx) (Object, error)
	// GetAction returns the action.
	GetAction(ctx *fiber.Ctx) (Action, error)
}

var _ Controller = (*DefaultController)(nil)

// DefaultController is the default implementation of the Controller.
type DefaultController struct {
	PrincipalResolver PrincipalResolver
	ObjectResolver    ObjectResolver
	ActionResolver    ActionResolver
}

// NewDefaultController returns a new DefaultController.
func NewDefaultController(pr PrincipalResolver, or ObjectResolver, ar ActionResolver) *DefaultController {
	return &DefaultController{
		PrincipalResolver: pr,
		ObjectResolver:    or,
		ActionResolver:    ar,
	}
}

// GetPrincipial returns the principal.
func (d *DefaultController) GetPrincipial(ctx *fiber.Ctx) (Principal, error) {
	return d.PrincipalResolver.Resolve(ctx)
}

// GetObject returns the object.
func (d *DefaultController) GetObject(ctx *fiber.Ctx) (Object, error) {
	return d.ObjectResolver.Resolve(ctx)
}

// GetAction returns the action.
func (d *DefaultController) GetAction(ctx *fiber.Ctx) (Action, error) {
	return d.ActionResolver.Resolve(ctx)
}
