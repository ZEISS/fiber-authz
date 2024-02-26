package authz

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	goth "github.com/zeiss/fiber-goth"
)

var _ AuthzPrincipalResolver = (*gothAuthzPrincipalResolver)(nil)

type gothAuthzPrincipalResolver struct{}

// Resolve ...
func (g *gothAuthzPrincipalResolver) Resolve(c *fiber.Ctx) (AuthzPrincipal, error) {
	session, err := goth.SessionFromContext(c)
	if err != nil && !errors.Is(err, goth.ErrMissingSession) {
		return AuthzNoPrincipial, err
	}

	return AuthzPrincipal(session.UserID.String()), nil
}

// NewGothAuthzPrincipalResolver ...
func NewGothAuthzPrincipalResolver() AuthzPrincipalResolver {
	return &gothAuthzPrincipalResolver{}
}
