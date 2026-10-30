package authz

import (
	"context"

	"github.com/openfga/go-sdk/client"
)

var _ Checker = (*FGA)(nil)

type FGA struct {
	client *client.OpenFgaClient
}

// NewFGA returns a new FGA authz checker.
func NewFGA(c *client.OpenFgaClient) *FGA {
	return &FGA{client: c}
}

// FGAUser is the subject.
type FGAUser = Principal

// FGARelation is the object.
type FGARelation = Object

// FGAAction is the action.
type FGAAction = Action

// Allowed returns true if the principal is allowed to perform the action on the user.
// Returns an error if the request fails.
// The principal is the object, the user is the subject, and the permission is the relation.
func (f *FGA) Allowed(ctx context.Context, user FGAUser, relation FGARelation, object FGAAction) (bool, error) {
	body := client.ClientCheckRequest{
		User:     user.String(),
		Relation: relation.String(),
		Object:   object.String(),
	}

	allowed, err := f.client.Check(ctx).Body(body).Execute()
	if err != nil {
		return false, err
	}

	return allowed.GetAllowed(), nil
}
