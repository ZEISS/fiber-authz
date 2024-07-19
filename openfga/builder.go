package openfga

import (
	"context"
	"fmt"
	"strings"

	"github.com/openfga/go-sdk/client"
)

// DefaultSeparator is the default separator for entities.
const DefaultSeparator = "/"

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

// Entities is a type that represents a set of entities.
type Entities interface {
	User | Relation | Object
}

// Builder is an interface for building FGA queries.
type Builder[T Entities] interface {
	// Set sets the user.
	Set(sep string, s ...string) Builder[T]
	// Get returns the user.
	Get() T
	// SetNamespace sets the namespace on a user.
	SetNamespace(namespace string) Builder[T]
}

// Transformer is a function that transforms a Builder.
type Transformer[T comparable] func(e T) T

// NewBuilder returns a new Builder.
func NewBuilder[T Entities]() Builder[T] {
	return &BuilderImpl[T]{}
}

// BuilderImpl is an implementation of the Builder interface.
type BuilderImpl[T Entities] struct {
	user T
}

// Set sets the entity on the builder.
func (b *BuilderImpl[T]) Set(sep string, entities ...string) Builder[T] {
	b.user = set[T](sep, entities...)(b.user)
	return b
}

func set[T Entities](sep string, entities ...string) Transformer[T] {
	return func(e T) T {
		return T(fmt.Sprintf("%s%s", e, strings.Join(entities, sep)))
	}
}

// Get returns the entity that the query is for.
func (b *BuilderImpl[T]) Get() T {
	return b.user
}

// SetNamespace sets the namespace on the entity.
func (b *BuilderImpl[T]) SetNamespace(namespace string) Builder[T] {
	b.user = setNamespace[T](namespace)(b.user)
	return b
}

func setNamespace[T Entities](namespace string) Transformer[T] {
	return func(e T) T {
		return T(fmt.Sprintf("%s:%s", namespace, e))
	}
}

// Checker is an interface for checking permissions.
type Checker[U, R, O Entities] interface {
	// Allowed returns true if the principal is allowed to perform the action on the user.
	Allowed(ctx context.Context, user U, relation R, object O) (bool, error)
}

var _ Checker[User, Relation, Object] = (*ClientImpl)(nil)

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
