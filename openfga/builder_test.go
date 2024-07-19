package openfga_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeiss/fiber-authz/openfga"
)

func TestUserBuilder(t *testing.T) {
	tests := []struct {
		name string
		in   openfga.Builder[openfga.User]
		out  openfga.User
	}{
		{
			name: "set user namespace",
			in:   openfga.NewBuilder[openfga.User]().Set(openfga.DefaultSeparator, "foo").SetNamespace("user"),
			out:  openfga.User("user:foo"),
		},
		{
			name: "append wit path like",
			in:   openfga.NewBuilder[openfga.User]().Set(openfga.DefaultSeparator, "bar", "baz").SetNamespace("user"),
			out:  openfga.User("user:bar/baz"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.out, tt.in.Get())
		})
	}
}
