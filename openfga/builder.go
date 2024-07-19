package openfga

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/openfga/go-sdk/client"
	"github.com/zeiss/fiber-authz/oas"
)

// DefaultSeparator is the default separator for entities.
const DefaultSeparator = "/"

// DefaultNamespaceSeparator is the default separator for namespaces.
const DefaultNamespaceSeparator = ":"

// EntitiesString is a type that represents a list of entities.
func EntityString[E Entities](e E) string {
	return string(e)
}

// User is a type that represents a user.
type User string

// Relation is a type that represents a relation.
type Relation string

// Object is a type that represents an object.
type Object string

// NoopUser is a user that represents no user.
const NoopUser User = ""

// NoopRelation is a relation that represents no relation.
const NoopRelation Relation = ""

// NoopObject is an object that represents no object.
const NoopObject Object = ""

// Stringer create a string an adds it to the representation.
type Stringer func() string

// Entities is a type that represents a list of entities.
type Entities interface {
	User | Relation | Object
}

// NewEntity returns a new User.
func NewEntity[E Entities](s ...Stringer) E {
	u := ""

	for _, v := range s {
		u += v()
	}

	return E(u)
}

// NewUser returns a new User.
func NewUser(s ...Stringer) User {
	return NewEntity[User](s...)
}

// NewRelation returns a new Relation.
func NewRelation(s ...Stringer) Relation {
	return NewEntity[Relation](s...)
}

// NewObject returns a new Object.
func NewObject(s ...Stringer) Object {
	return NewEntity[Object](s...)
}

// Namespace adds a namespace to the entity.
func Namespace(namespace string, sep ...string) Stringer {
	return func() string {
		s := DefaultNamespaceSeparator

		if len(sep) > 0 {
			s = sep[0]
		}

		return namespace + s
	}
}

// Join joins the entities with the separator.
func Join(sep string, entities ...string) Stringer {
	return func() string {
		return strings.Join(entities, sep)
	}
}

// OidcSubject returns the OIDC subject.
func OidcSubject(claims *oas.AuthClaims) Stringer {
	return func() string {
		return claims.Subject
	}
}

// String returns the string representation of the entities.
func String(s string) Stringer {
	return func() string {
		return s
	}
}

// RequestParams is a type that represents the parameters for a request.
func RequestParams(c *fiber.Ctx, sep string, params ...string) Stringer {
	return func() string {
		for i, param := range params {
			params[i] = c.Params(param)
		}

		return strings.Join(params, sep)
	}
}

// Checker is an interface for checking permissions.
type Checker interface {
	// Allowed returns true if the principal is allowed to perform the action on the user.
	Allowed(ctx context.Context, user User, relation Relation, object Object) (bool, error)
}

var _ Checker = (*ClientImpl)(nil)

// ClientImpl is an implementation of the Client interface.
type ClientImpl struct {
	client *client.OpenFgaClient
}

// Allowed returns true if the user is allowed if the user has the relation on the object.
func (c *ClientImpl) Allowed(ctx context.Context, user User, relation Relation, object Object) (bool, error) {
	body := client.ClientCheckRequest{
		User:     EntityString(user),
		Relation: EntityString(relation),
		Object:   EntityString(object),
	}

	allowed, err := c.client.Check(ctx).Body(body).Execute()
	if err != nil {
		return false, err
	}

	return allowed.GetAllowed(), nil
}

// NewClient returns a new FGA client.
func NewClient(c *client.OpenFgaClient) *ClientImpl {
	return &ClientImpl{client: c}
}
