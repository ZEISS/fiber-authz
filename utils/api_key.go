package utils

import "github.com/google/uuid"

// NewAPIKey creates a new API key.
func NewAPIKey() (string, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	return uuid.String(), nil
}
