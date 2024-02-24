package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTeam(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		team  *Team
		error bool
	}{
		{
			name: "valid team",
			team: &Team{
				Name: "team",
				Slug: "team",
			},
		},
		{
			name: "required slug",
			team: &Team{
				Name: "team",
			},
			error: true,
		},
		{
			name: "slug too short",
			team: &Team{
				Name: "team",
				Slug: "te",
			},
			error: true,
		},
		{
			name: "slug too long",
			team: &Team{
				Name: "team",
				Slug: "t" + string(make([]byte, 255)),
			},
			error: true,
		},
		{
			name: "slug not lowercase",
			team: &Team{
				Name: "team",
				Slug: "Team",
			},
			error: true,
		},
		{
			name: "slug not alphanumeric",
			team: &Team{
				Name: "team",
				Slug: "team!",
			},
			error: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.team.Validate()
			if tt.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
