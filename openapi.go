package authz

import (
	"context"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	middleware "github.com/oapi-codegen/fiber-middleware"
)

// NewOpenAPIErrorHandler creates a new OpenAPI error handler.
func NewOpenAPIErrorHandler() middleware.ErrorHandler {
	return func(c *fiber.Ctx, message string, statusCode int) {
		c.Status(statusCode).JSON(map[string]interface{}{
			"message": message,
			"code":    statusCode,
		})
	}
}

// NewOpenAPIAuthenticator creates a new OpenAPI authenticator.
func NewOpenAPIAuthenticator() openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		c := middleware.GetFiberContext(ctx)

		key, err := GetAPIKeyFromRequest(input.RequestValidationInput.Request)
		if err != nil {
			return err
		}

		err = validate.Var(key, "required,uuid")
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid API key")
		}

		// Create a new context with the API key.
		usrCtx := c.UserContext()
		authCtx := context.WithValue(usrCtx, authzAPIKey, key)

		// nolint: contextcheck
		c.SetUserContext(authCtx)

		return nil
	}
}

// GetAPIKeyFromContext extracts the API key from the context.
func GetAPIKeyFromContext(ctx context.Context) (string, error) {
	key := ctx.Value(authzAPIKey)

	if key == nil {
		return "", errors.New("API key not found")
	}

	return key.(string), nil
}

// GetAPIKeyFromRequest is a fake implementation of the API key extractor.
func GetAPIKeyFromRequest(req *http.Request) (string, error) {
	return req.Header.Get("x-api-key"), nil
}
