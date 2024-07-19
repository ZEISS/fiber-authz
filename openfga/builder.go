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

// User is a type that represents a user.
type User string

// String returns the string representation of the user.
func (u User) String() string {
	return string(u)
}

// Relation is a type that represents a relation.
type Relation string

// String returns the string representation of the relation.
func (r Relation) String() string {
	return string(r)
}

// Object is a type that represents an object.
type Object string

// String returns the string representation of the object.
func (o Object) String() string {
	return string(o)
}

// NoopUser is a user that represents no user.
const NoopUser User = ""

// NoopRelation is a relation that represents no relation.
const NoopRelation Relation = ""

// NoopObject is an object that represents no object.
const NoopObject Object = ""

// Stringers create a string an adds it to the representation.
type Stringers func() string

// Entities is a type that represents a list of entities.
type Entities interface {
	User | Relation | Object
}

// NewEntity returns a new User.
func NewEntity[E Entities](s ...Stringers) E {
	u := ""

	for _, v := range s {
		u += v()
	}

	return E(u)
}

// NewUser returns a new User.
func NewUser(s ...Stringers) User {
	return NewEntity[User](s...)
}

// NewRelation returns a new Relation.
func NewRelation(s ...Stringers) Relation {
	return NewEntity[Relation](s...)
}

// NewObject returns a new Object.
func NewObject(s ...Stringers) Object {
	return NewEntity[Object](s...)
}

// Namespace adds a namespace to the entity.
func Namespace(namespace string, sep ...string) Stringers {
	return func() string {
		s := DefaultNamespaceSeparator

		if len(sep) > 0 {
			s = sep[0]
		}

		return namespace + s
	}
}

// Join joins the entities with the separator.
func Join(sep string, entities ...string) Stringers {
	return func() string {
		return strings.Join(entities, sep)
	}
}

// OidcSubject returns the OIDC subject.
func OidcSubject(claims *oas.AuthClaims) Stringers {
	return func() string {
		return claims.Subject
	}
}

// String returns the string representation of the entities.
func String(s string) Stringers {
	return func() string {
		return s
	}
}

// RequestParams is a type that represents the parameters for a request.
func RequestParams(c *fiber.Ctx, sep string, params ...string) Stringers {
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
		User:     user.String(),
		Relation: relation.String(),
		Object:   object.String(),
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
