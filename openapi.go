package authz

import (
	"context"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gofiber/fiber/v2"
	middleware "github.com/oapi-codegen/fiber-middleware"
	"gorm.io/gorm"
)

// OpenAPIAuthenticatorOpts are the OpenAPI authenticator options.
type OpenAPIAuthenticatorOpts struct {
	PathParam string
	Checker   AuthzChecker
}

// Conigure the OpenAPI authenticator.
func (o *OpenAPIAuthenticatorOpts) Conigure(opts ...OpenAPIAuthenticatorOpt) {
	for _, opt := range opts {
		opt(o)
	}
}

// OpenAPIAuthenticatorOpt is a function that sets an option on the OpenAPI authenticator.
type OpenAPIAuthenticatorOpt func(*OpenAPIAuthenticatorOpts)

// OpenAPIAuthenticatorDefaultOpts are the default OpenAPI authenticator options.
func OpenAPIAuthenticatorDefaultOpts() OpenAPIAuthenticatorOpts {
	return OpenAPIAuthenticatorOpts{
		PathParam: "teamId",
		Checker:   NewNoop(),
	}
}

// WithPathParam sets the path parameter.
func WithPathParam(param string) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.PathParam = param
	}
}

// WithChecker sets the authz checker.
func WithChecker(checker AuthzChecker) OpenAPIAuthenticatorOpt {
	return func(opts *OpenAPIAuthenticatorOpts) {
		opts.Checker = checker
	}
}

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
func NewOpenAPIAuthenticator(opts ...OpenAPIAuthenticatorOpt) openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		opt := OpenAPIAuthenticatorDefaultOpts()
		opt.Conigure(opts...)

		c := middleware.GetFiberContext(ctx)
		obj := AuthzObject(c.Params(opt.PathParam, ""))

		key, err := GetAPIKeyFromRequest(input.RequestValidationInput.Request)
		if err != nil {
			return err
		}

		err = validate.Var(key, "required,uuid")
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid API key")
		}

		allowed := len(input.Scopes) == 0
		if len(input.Scopes) > 0 {
			allowed, err = opt.Checker.Allowed(ctx, AuthzPrincipal(key), obj, AuthzAction(input.Scopes[0]))
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, "Internal Server Error")
			}
		}

		if !allowed {
			return fiber.NewError(fiber.StatusForbidden, "Forbidden")
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

var _ AuthzChecker = (*apiKey)(nil)

type apiKey struct {
	db *gorm.DB
}

// NewAPIKey returns a new API key authenticator.
func NewAPIKey(db *gorm.DB) *apiKey {
	return &apiKey{
		db: db,
	}
}

// Allowed is a method that returns true if the principal is allowed to perform the action on the user.
func (t *apiKey) Allowed(ctx context.Context, principal AuthzPrincipal, object AuthzObject, action AuthzAction) (bool, error) {
	var allowed int64

	team := t.db.WithContext(ctx).Model(&apiKey{}).Select("id").Where("slug = ?", object)

	err := t.db.Raw("SELECT COUNT(1) FROM vw_user_team_permissions WHERE user_id = ? AND team_id = (?) AND permission = ?", principal, team, action).Count(&allowed).Error
	if err != nil {
		return false, err
	}

	if allowed > 0 {
		return true, nil
	}

	return false, nil
}
