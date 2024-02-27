package authz

import (
	"context"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	)
	if err != nil {
		return err
	}

	query := db.Raw("SELECT A.user_id, A.team_id, C.slug as permission FROM user_roles AS A LEFT JOIN role_permissions AS B ON A.role_id = B.role_id LEFT JOIN permissions AS C on B.permission_id = C.id;")

	return db.Migrator().CreateView("vw_user_team_permissions", gorm.ViewOption{Query: query, Replace: true})
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
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name        string
	Slug        string  `gorm:"uniqueIndex" validate:"required,alphanum,gt=3,lt=255,lowercase"`
	Description *string `validate:"omitempty,max=255"`

	Users *[]User `gorm:"many2many:user_teams;"`

	CreatedAt time.Time
	UpdatedAt time.Time
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

	*adapters.User
}

// UserRole is a user role.
type UserRole struct {
	UserID uuid.UUID `gorm:"primaryKey"`
	User   User

	TeamID uuid.UUID `gorm:"primaryKey"`
	Team   Team

	RoleID uuid.UUID `gorm:"primaryKey"`
	Role   Role

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

// Validate validates the user.
func (u *User) Validate() error {
	validate = validator.New()

	return validate.Struct(u)
}

// Permission is a permission that a user can have.
type Permission struct {
	ID          uint    `gorm:"primaryKey"`
	Slug        string  `gorm:"uniqueIndex" validate:"required,alphanum,gt=3,lt=255,lowercase"`
	Description *string `validate:"omitempty,max=255"`

	Roles *[]Role `gorm:"many2many:role_permissions;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

// Validate validates the permission.
func (p *Permission) Validate() error {
	validate = validator.New()

	return validate.Struct(p)
}

var (
	_ AuthzChecker     = (*tbac)(nil)
	_ adapters.Adapter = (*tbac)(nil)
)

type tbac struct {
	db *gorm.DB

	adapters.UnimplementedAdapter
}

// NewTBAC returns a new TBAC authz checker
func NewTBAC(db *gorm.DB) *tbac {
	return &tbac{
		db: db,
	}
}

// Allowed is a method that returns true if the principal is allowed to perform the action on the user.
func (t *tbac) Allowed(ctx context.Context, principal AuthzPrincipal, object AuthzObject, action AuthzAction) (bool, error) {
	var allowed int64

	teamSlug := t.db.WithContext(ctx).Model(&Team{}).Select("id").Where("slug = ?", object)

	err := t.db.Raw("SELECT COUNT(1) FROM vw_user_team_permissions WHERE user_id = ? AND team_id = (?) AND permission = ?", principal, teamSlug, action).Count(&allowed).Error
	if err != nil {
		return false, err
	}

	if allowed > 0 {
		return true, nil
	}

	return false, nil
}

// Resolve ...
func (t *tbac) Resolve(c *fiber.Ctx) (AuthzObject, error) {
	return AuthzObject(c.Params("team")), nil
}

// CreateUser ...
func (a *tbac) CreateUser(ctx context.Context, user adapters.User) (adapters.User, error) {
	err := a.db.WithContext(ctx).FirstOrCreate(&user).Error
	if err != nil {
		return adapters.User{}, err
	}

	return user, nil
}

// GetSession is a helper function to retrieve a session by session token.
func (a *tbac) GetSession(ctx context.Context, sessionToken string) (adapters.Session, error) {
	var session adapters.Session
	err := a.db.WithContext(ctx).Preload("User").Where("session_token = ?", sessionToken).First(&session).Error
	if err != nil {
		return adapters.Session{}, err
	}

	return session, nil
}

// GetUser is a helper function to retrieve a user by ID.
func (a *tbac) GetUser(ctx context.Context, id uuid.UUID) (adapters.User, error) {
	var user adapters.User
	err := a.db.WithContext(ctx).Preload("Accounts").Where("id = ?", id).First(&user).Error
	if err != nil {
		return adapters.User{}, err
	}

	return user, nil
}

// CreateSession is a helper function to create a new session.
func (a *tbac) CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (adapters.Session, error) {
	session := adapters.Session{UserID: userID, SessionToken: uuid.NewString(), ExpiresAt: expires}
	err := a.db.WithContext(ctx).Create(&session).Error
	if err != nil {
		return adapters.Session{}, err
	}

	return session, nil
}

// DeleteSession is a helper function to delete a session by session token.
func (a *tbac) DeleteSession(ctx context.Context, sessionToken string) error {
	return a.db.WithContext(ctx).Where("session_token = ?", sessionToken).Delete(&adapters.Session{}).Error
}

// RefreshSession is a helper function to refresh a session.
func (a *tbac) RefreshSession(ctx context.Context, session adapters.Session) (adapters.Session, error) {
	err := a.db.WithContext(ctx).Model(&adapters.Session{}).Where("session_token = ?", session.SessionToken).Updates(&session).Error
	if err != nil {
		return adapters.Session{}, err
	}

	return session, nil
}

// DeleteUser ...
func (a *tbac) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return a.db.WithContext(ctx).Where("id = ?", id).Delete(&adapters.User{}).Error
}

// LinkAccount ...
func (a *tbac) LinkAccount(ctx context.Context, accountID, userID uuid.UUID) error {
	return a.db.WithContext(ctx).Model(&adapters.Account{}).Where("id = ?", accountID).Update("user_id", userID).Error
}
