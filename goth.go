package authz

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	goth "github.com/zeiss/fiber-goth"
)

const authzPrincipalFormat = "user:%s"

var _ AuthzPrincipalResolver = (*GothAuthzPrincipalResolver)(nil)

// GothAuthzPrincipalResolver is the resolver that resolves the principal from the goth session.
type GothAuthzPrincipalResolver struct{}

// Resolve returns the principal from the goth session.
func (g *GothAuthzPrincipalResolver) Resolve(c *fiber.Ctx) (AuthzPrincipal, error) {
	session, err := goth.SessionFromContext(c)
	if err != nil && !errors.Is(err, goth.ErrMissingSession) {
		return AuthzNoPrincipial, err
	}

	return AuthzPrincipal(fmt.Sprintf(authzPrincipalFormat, session.UserID.String())), nil
}

// NewGothAuthzPrincipalResolver returns a new GothAuthzPrincipalResolver.
func NewGothAuthzPrincipalResolver() AuthzPrincipalResolver {
	return &GothAuthzPrincipalResolver{}
}
