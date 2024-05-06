package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnimplemented(t *testing.T) {
	t.Parallel()

	checker := &Unimplemented{}
	require.NotNil(t, checker)

	allowed, err := checker.Allowed(context.TODO(), "principal", "object", "action")
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestFakeChecker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		allowed  bool
		expected bool
	}{
		{
			name:     "allowed",
			allowed:  true,
			expected: true,
		},
		{
			name:     "not allowed",
			allowed:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewFake(tt.allowed)
			require.NotNil(t, checker)

			allowed, err := checker.Allowed(context.TODO(), "principal", "object", "action")
			require.NoError(t, err)
			require.Equal(t, tt.expected, allowed)
		})
	}
}
