package openfga_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeiss/fiber-authz/openfga"
)

func TestUserBuilder(t *testing.T) {
	tests := []struct {
		name string
		in   openfga.User
		out  openfga.User
	}{
		{
			name: "set user namespace",
			in:   openfga.NewUser(openfga.Namespace("user"), openfga.String("foo")),
			out:  openfga.User("user:foo"),
		},
		{
			name: "append wit path like",
			in:   openfga.NewUser(openfga.Namespace("user"), openfga.Join(openfga.DefaultSeparator, "bar", "baz")),
			out:  openfga.User("user:bar/baz"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.out, tt.in)
		})
	}
}
