package authz

import (
	"context"

	"github.com/openfga/go-sdk/client"
)

var _ AuthzChecker = (*fga)(nil)

type fga struct {
	client *client.OpenFgaClient
}

// NewFGA returns a new FGA authz checker
func NewFGA(c *client.OpenFgaClient) *fga {
	return &fga{client: c}
}

// AuthzFGAUser is the subject.
type AuthzFGAUser = AuthzPrincipal

// AuthzFGARelation is the object.
type AuthzFGARelation = AuthzObject

// AuthzFGAAction is the action.
type AuthzFGAAction = AuthzAction

// Allowed returns true if the principal is allowed to perform the action on the user.
// Returns an error if the request fails.
// The principal is the object, the user is the subject, and the permission is the relation.
func (f *fga) Allowed(ctx context.Context, user AuthzFGAUser, relation AuthzFGARelation, object AuthzFGAAction) (bool, error) {
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
