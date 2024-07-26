package openfga_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeiss/fiber-authz/openfga"
)

func TestNewUser(t *testing.T) {
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
		{
			name: "empty namespace",
			in:   openfga.NewUser(openfga.Namespace(""), openfga.String("foo")),
			out:  openfga.User("foo"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.out, tt.in)
		})
	}
}

func BenchmarkNewUser(b *testing.B) {
	for i := 0; i < b.N; i++ {
		openfga.NewUser(openfga.Namespace("user"), openfga.String("foo"), openfga.String("bar"), openfga.String("baz"))
	}
}
