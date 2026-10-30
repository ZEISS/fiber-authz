package tbrac

import (
	"context"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	authz "github.com/zeiss/fiber-authz"
	"github.com/zeiss/fiber-goth/adapters"
	"gorm.io/gorm"
)

// use a single instance of Validate, it caches struct info.
var validate = validator.New()

// RunMigrations is a function that runs the migrations for the authz package.
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&Role{},
		&Team{},
		&User{},
		&Permission{},
		&UserRole{},
		&APIKey{},
		&APIKeyRole{},
	)
	if err != nil {
		return err
	}

	userRolesTableName := db.NamingStrategy.TableName("user_roles")
	apiKeyRolesTableName := db.NamingStrategy.TableName("api_key_roles")
	rolePermissionsTableName := db.NamingStrategy.TableName("role_permissions")
	permissionsTableName := db.NamingStrategy.TableName("permissions")

	// View for user team permissions
	query := db.Raw("SELECT A.user_id, A.team_id, C.scope as permission FROM " + userRolesTableName + " AS A LEFT JOIN " + rolePermissionsTableName + " AS B ON A.role_id = B.role_id LEFT JOIN " + permissionsTableName + " AS C on B.permission_id = C.id;")
	err = db.Migrator().CreateView("vw_user_team_permissions", gorm.ViewOption{Query: query, Replace: true})
	if err != nil {
		return err
	}

	// View for the api key permissions
	query = db.Raw("SELECT A.key_id, A.team_id, C.scope as permission FROM " + apiKeyRolesTableName + " AS A LEFT JOIN " + rolePermissionsTableName + " AS B ON A.role_id = B.role_id LEFT JOIN " + permissionsTableName + " AS C on B.permission_id = C.id;")
	err = db.Migrator().CreateView("vw_api_key_team_permissions", gorm.ViewOption{Query: query, Replace: true})
	if err != nil {
		return err
	}

	return nil
}

// Role is a role that a user can have.
type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name        string    `gorm:"uniqueIndex"`
	Description string    `validate:"omitempty,max=255"`

	Permissions *[]Permission `gorm:"many2many:role_permissions;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

// Validate validates the role.
func (r *Role) Validate() error {
	validate = validator.New()

	return validate.Struct(r)
}

// Team is a group of users.
type Team struct {
	// ID is the primary key of the team.
	ID uuid.UUID `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
	// Name is the name of the team.
	Name string `json:"name" validate:"required,alphanum,gt=3,lt=255"`
	// Slug is the unique identifier of the team.
	Slug string `json:"slug" gorm:"uniqueIndex" validate:"required,alphanum,gt=3,lt=255,lowercase"`
	// Description is the description of the team.
	Description *string `json:"description" validate:"omitempty,max=255"`

	// Users are the users in the team.
	Users *[]User `gorm:"many2many:user_teams;"`

	// CreatedAt is the time the team was created.
	CreatedAt time.Time
	// UpdatedAt is the time the team was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the team was deleted.
	DeletedAt gorm.DeletedAt
}

// Validate validates the team.
func (t *Team) Validate() error {
	validate = validator.New()

	return validate.Struct(t)
}

// User is a user.
type User struct {
	Teams *[]Team `gorm:"many2many:user_teams;"`
	Roles *[]Role `gorm:"many2many:user_roles;"`

	*adapters.GothUser
}

// UserRole is a user role.
type UserRole struct {
	// UserID is the primary key of the user.
	UserID uuid.UUID `gorm:"primaryKey"`
	User   User

	// TeamID is the primary key of the team.
	TeamID uuid.UUID `gorm:"primaryKey"`
	Team   Team

	// RoleID is the primary key of the role.
	RoleID uuid.UUID `gorm:"primaryKey"`
	Role   Role

	// CreatedAt is the time the user role was created.
	CreatedAt time.Time
	// UpdatedAt is the time the user role was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the user role was deleted.
	DeletedAt gorm.DeletedAt
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
	Roles *[]Role `gorm:"many2many:role_permissions;"`

	// CreatedAt is the time the permission was created.
	CreatedAt time.Time
	// UpdatedAt is the time the permission was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the permission was deleted.
	DeletedAt gorm.DeletedAt
}

// Validate validates the permission.
func (p *Permission) Validate() error {
	validate = validator.New()

	return validate.Struct(p)
}

// APIKey is an API key.
type APIKey struct {
	// ID is the primary key of the API key.
	ID uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	// Key is the API key.
	Key string `gorm:"uniqueIndex" validate:"required,alphanum,gt=3,lt=255,lowercase"`
	// Description is the description of the API key.
	Description *string `validate:"omitempty,max=255"`
	// CreatedAt is the time the API key was created.
	CreatedAt time.Time
	// UpdatedAt is the time the API key was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the API key was deleted.
	DeletedAt gorm.DeletedAt
}

// APIKeyRole is a user role.
type APIKeyRole struct {
	// APIKeyID is the primary key of the API key.
	KeyID uuid.UUID `gorm:"primaryKey"`
	Key   APIKey

	// RoleID is the primary key of the role.
	RoleID uuid.UUID `gorm:"primaryKey"`
	Role   Role

	// TeamID is the primary key of the team.
	TeamID uuid.UUID `gorm:"primaryKey"`
	Team   Team

	// CreatedAt is the time the API key role was created.
	CreatedAt time.Time
	// UpdatedAt is the time the API key role was last updated.
	UpdatedAt time.Time
	// DeletedAt is the time the API key role was deleted.
	DeletedAt gorm.DeletedAt
}

var (
	_ authz.Checker    = (*TBAC)(nil)
	_ adapters.Adapter = (*TBAC)(nil)
)

type TBAC struct {
	db *gorm.DB

	adapters.UnimplementedAdapter
}

// NewTBAC returns a new TBAC authz checker.
func NewTBAC(db *gorm.DB) *TBAC {
	return &TBAC{
		db: db,
	}
}

// Allowed is a method that returns true if the principal is allowed to perform the action on the user.
func (t *TBAC) Allowed(ctx context.Context, principal authz.Principal, object authz.Object, action authz.Action) (bool, error) {
	var allowed int64

	team := t.db.WithContext(ctx).Model(&Team{}).Select("id").Where("slug = ?", object)

	err := t.db.Raw("SELECT COUNT(1) FROM vw_user_team_permissions WHERE user_id = ? AND team_id = (?) AND permission = ?", principal, team, action).Count(&allowed).Error
	if err != nil {
		return false, err
	}

	if allowed > 0 {
		return true, nil
	}

	return false, nil
}

// Resolve ...
func (t *TBAC) Resolve(c *fiber.Ctx) (authz.Object, error) {
	return authz.Object(c.Params("team")), nil
}

// CreateUser ...
func (t *TBAC) CreateUser(ctx context.Context, user adapters.GothUser) (adapters.GothUser, error) {
	err := t.db.WithContext(ctx).FirstOrCreate(&user).Error
	if err != nil {
		return adapters.GothUser{}, err
	}

	return user, nil
}

// GetSession is a helper function to retrieve a session by session token.
func (t *TBAC) GetSession(ctx context.Context, sessionToken string) (adapters.GothSession, error) {
	var session adapters.GothSession
	err := t.db.WithContext(ctx).Preload("User").Where("session_token = ?", sessionToken).First(&session).Error
	if err != nil {
		return adapters.GothSession{}, err
	}

	return session, nil
}

// GetUser is a helper function to retrieve a user by ID.
func (t *TBAC) GetUser(ctx context.Context, id uuid.UUID) (adapters.GothUser, error) {
	var user adapters.GothUser
	err := t.db.WithContext(ctx).Preload("Accounts").Where("id = ?", id).First(&user).Error
	if err != nil {
		return adapters.GothUser{}, err
	}

	return user, nil
}

// CreateSession is a helper function to create a new session.
func (t *TBAC) CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (adapters.GothSession, error) {
	session := adapters.GothSession{UserID: userID, SessionToken: uuid.NewString(), ExpiresAt: expires}
	err := t.db.WithContext(ctx).Create(&session).Error
	if err != nil {
		return adapters.GothSession{}, err
	}

	return session, nil
}

// DeleteSession is a helper function to delete a session by session token.
func (t *TBAC) DeleteSession(ctx context.Context, sessionToken string) error {
	return t.db.WithContext(ctx).Where("session_token = ?", sessionToken).Delete(&adapters.GothSession{}).Error
}

// RefreshSession is a helper function to refresh a session.
func (t *TBAC) RefreshSession(ctx context.Context, session adapters.GothSession) (adapters.GothSession, error) {
	err := t.db.WithContext(ctx).Model(&adapters.GothSession{}).Where("session_token = ?", session.SessionToken).Updates(&session).Error
	if err != nil {
		return adapters.GothSession{}, err
	}

	return session, nil
}

// DeleteUser ...
func (t *TBAC) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return t.db.WithContext(ctx).Where("id = ?", id).Delete(&adapters.GothUser{}).Error
}

// LinkAccount ...
func (t *TBAC) LinkAccount(ctx context.Context, accountID, userID uuid.UUID) error {
	return t.db.WithContext(ctx).Model(&adapters.GothAccount{}).Where("id = ?", accountID).Update("user_id", userID).Error
}
