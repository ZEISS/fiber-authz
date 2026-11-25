package sbac

import (
	"context"
	"net/http"
	"time"

	authz "github.com/zeiss/fiber-authz/v3"
	humax "github.com/zeiss/fiber-authz/v3/oas/huma"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	seed "github.com/zeiss/gorm-seed"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// Admin is the admin action.
	PermissionAdmin = "admin"
	// Read is the read action.
	PermissionRead = "read"
	// Write is the write action.
	PermissionWrite = "write"
)

var (
	// RoleOwner is the owner role.
	RoleOwner = "owner"
	// RoleCollaborator is the collaborator role.
	RoleCollaborator = "collaborator"
	// RoleUser is the user role.
	RoleUser = "user"
)

// SitePermissionSeed is the seed for the site permissions.
// With a simple seed that creates the admin, write, and read permissions.
var SitePermissionSeed = seed.Seeds{
	{
		Name: "CreatePermissions",
		Run: func(db *gorm.DB) error {
			permissions := []Permission{
				{Scope: PermissionAdmin},
				{Scope: PermissionWrite},
				{Scope: PermissionRead},
			}
			return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&permissions).Error
		},
	},
	{
		Name: "CreateRoles",
		Run: func(db *gorm.DB) error {
			roles := []Role{
				{Name: RoleOwner},
				{Name: RoleCollaborator},
				{Name: RoleUser},
			}
			return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&roles).Error
		},
	},
	{
		Name: "AddAdminPermissionToOwner",
		Run: func(db *gorm.DB) error {
			var owner Role
			if err := db.First(&owner, "name = ?", RoleOwner).Error; err != nil {
				return err
			}
			var adminPermission Permission
			if err := db.First(&adminPermission, "scope = ?", PermissionAdmin).Error; err != nil {
				return err
			}

			owner.Permissions = []*Permission{&adminPermission}
			return db.Save(&owner).Error
		},
	},
}

// RunSeeds runs the seeders for the authz package.
func RunSeeds(ctx context.Context, db *gorm.DB, seeds ...seed.Seed) error {
	seeder := seed.NewSeeder(db)
	return seeder.Seed(ctx, seeds...)
}

// use a single instance of Validate, it caches struct info.
var validate = validator.New()

// RunMigrations is a function that runs the migrations for the authz package.
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&Role{},
		&Site{},
		&User{},
		&Permission{},
		&UserRole{},
	)
	if err != nil {
		return err
	}

	userRolesTableName := db.NamingStrategy.TableName("user_roles")
	rolePermissionsTableName := db.NamingStrategy.TableName("role_permissions")
	permissionsTableName := db.NamingStrategy.TableName("permissions")

	query := db.Raw("SELECT A.user_id, A.site_id, C.scope as permission FROM " + userRolesTableName + " AS A LEFT JOIN " + rolePermissionsTableName + " AS B ON A.role_id = B.role_id LEFT JOIN " + permissionsTableName + " AS C on B.permission_id = C.id;")
	err = db.Migrator().CreateView("vw_user_site_permissions", gorm.ViewOption{Query: query, Replace: true})
	if err != nil {
		return err
	}

	return nil
}

// Role is a role that a user can have.
type Role struct {
	// ID is the primary key of the role.
	ID uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	// Name is the name of the role.
	Name string `gorm:"uniqueIndex"`
	// Description is the description of the role.
	Description string `validate:"omitempty,max=255"`
	// Permissions are the permissions that the role has.
	Permissions []*Permission `gorm:"many2many:role_permissions;"`
}

// Validate validates the role.
func (r *Role) Validate() error {
	validate = validator.New()

	return validate.Struct(r)
}

// Site is a site that a user can belong to.
type Site struct {
	// ID is the primary key of the site.
	ID uuid.UUID `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
	// Name is the name of the site.
	Name string `json:"name" validate:"required,alphanum,gt=3,lt=255"`
	// Slug is the unique identifier of the site.
	Slug string `json:"slug" gorm:"uniqueIndex" validate:"required,alphanum,gt=3,lt=255,lowercase"`
	// Description is the description of the site.
	Description *string `json:"description" validate:"omitempty,max=255"`
	// Users are the users in the site.
	Users []*User `gorm:"many2many:user_sites;"`
	// CreatedAt is the time the site was created.
	CreatedAt time.Time
	// UpdatedAt is the time the site was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the site was deleted.
	DeletedAt gorm.DeletedAt
}

// Validate validates the site.
func (s *Site) Validate() error {
	validate = validator.New()
	return validate.Struct(s)
}

// User is a user.
type User struct {
	// ID is the unique identifier of the user.
	ID uuid.UUID `json:"ID" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	// Email is the email of the user.
	Email string `json:"email" gorm:"unique" validate:"required,email"`
	// Sites are the sites the user is a member of.
	Sites []Site `gorm:"many2many:user_sites;"`
	// Roles are the roles the user has.
	Roles []Role `gorm:"many2many:user_roles;"`
	// CreatedAt is the time the user role was created.
	CreatedAt time.Time
	// UpdatedAt is the time the user role was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the user role was deleted.
	DeletedAt gorm.DeletedAt
}

// UserRole is a user role.
type UserRole struct {
	// UserID is the primary key of the user.
	UserID uuid.UUID `gorm:"primaryKey"`
	User   User

	// SiteID is the primary key of the site.
	SiteID uuid.UUID `gorm:"primaryKey"`
	Site   Site

	// RoleID is the primary key of the role.
	RoleID uuid.UUID `gorm:"primaryKey"`
	Role   Role
}

// Validate validates the user.
func (u *User) Validate() error {
	validate = validator.New()
	return validate.Struct(u)
}

// Permission is a permission that a user can have.
type Permission struct {
	// ID is the primary key of the permission.
	ID uint `json:"id" gorm:"primaryKey"`
	// Scope is the unique identifier of the permission.
	Scope string `json:"scope" gorm:"uniqueIndex" validate:"required,alphanum,gt=3,lt=255,lowercase"`
	// Description is the description of the permission.
	Description *string `json:"description" validate:"omitempty,max=255"`
	// Roles are the roles that have the permission.
	Roles []Role `gorm:"many2many:role_permissions;"`
}

// Validate validates the permission.
func (p *Permission) Validate() error {
	validate = validator.New()
	return validate.Struct(p)
}

var (
	_ authz.Checker = (*SBAC)(nil)
)

// SBAC is a struct that implements the authz.Checker interface.
type SBAC struct {
	db     *gorm.DB
	checks []CheckFunc
}

// DefaultChecks is the default validation functions for the SBAC authz checker.
var DefaultChecks = []CheckFunc{}

// Opt is a function that returns an option for the SBAC authz checker.
type Opt func(*SBAC)

// CheckFunc is a function that checks the given context of the request.
type CheckFunc func(ctx context.Context, principal authz.Principal, object authz.Object, action authz.Action) (bool, error)

// WithChecks returns an option that sets the post-check functions for the SBAC authz checker.
func WithChecks(checks ...CheckFunc) Opt {
	return func(s *SBAC) {
		s.checks = checks
	}
}

// NewSBAC returns a new SBAC authz checker.
func NewSBAC(db *gorm.DB, opts ...Opt) *SBAC {
	s := &SBAC{
		db:     db,
		checks: DefaultChecks,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Allowed is a method that returns true if the principal is allowed to perform the action on the user.
func (s *SBAC) Allowed(ctx context.Context, principal authz.Principal, object authz.Object, action authz.Action) (bool, error) {
	var allowed int64

	for _, check := range s.checks {
		allowed, err := check(ctx, principal, object, action)
		if err != nil {
			return false, err
		}

		if !allowed {
			return false, nil
		}
	}

	err := s.db.Raw("SELECT COUNT(1) FROM vw_user_site_permissions WHERE user_id = (SELECT id FROM users WHERE email = ?) AND site_id = (SELECT id FROM sites WHERE slug = ?) AND permission = ?", principal, object, action).Count(&allowed).Error
	if err != nil {
		return false, err
	}

	if allowed > 0 {
		return true, nil
	}

	return false, nil
}

// Check returns a middleware that checks the principal's permissions for the given action on the user.
func Check(api huma.API, checker authz.Checker, action, site string) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		token, ok := ctx.Context().Value(humax.OidcTokenKey).(*jwt.Token)
		if !ok {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		principal := authz.Principal(email)
		object := authz.Object(site)
		action := authz.Action(action)

		allowed, err := checker.Allowed(ctx.Context(), principal, object, action)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		if !allowed {
			huma.WriteErr(api, ctx, http.StatusForbidden, "Forbidden")
			return
		}

		next(ctx)
	}
}
