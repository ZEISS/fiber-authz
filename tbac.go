package authz

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunMigrations is a function that runs the migrations for the authz package.
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&Role{},
		&Team{},
		&User{},
		&Permission{},
		&RolePermission{},
		&UserTeam{},
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
	Name        string
	Description string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// Team is a group of users.
type Team struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name        string
	Slug        string
	Description *string

	Users *[]User `gorm:"many2many:user_teams;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// User is a user.
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name          string
	Email         string
	EmailVerified *string
	Image         *string

	Teams *[]Team `gorm:"many2many:user_teams;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// Permission is a permission that a user can have.
type Permission struct {
	ID          uint `gorm:"primaryKey"`
	Slug        string
	Description *string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// RolePermission is a relation between a role and a permission.
type RolePermission struct {
	ID uint `gorm:"primaryKey"`

	RoleID uuid.UUID
	Role   Role

	PermissionID uint
	Permission   Permission

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}

// UserTeam is a relation between a user and a team.
type UserTeam struct {
	ID uint `gorm:"primaryKey"`

	UserID uuid.UUID
	User   User

	TeamID uuid.UUID
	Team   Team

	gorm.Model
}

// UserRole is a relation between a user and a role.
type UserRole struct {
	ID uint `gorm:"primaryKey"`

	UserID uuid.UUID
	User   User

	TeamID uuid.UUID
	Team   Team

	RoleID uuid.UUID
	Role   Role
}

var _ AuthzChecker = (*tbac)(nil)

type tbac struct {
	db *gorm.DB
}

// NewTBAC returns a new TBAC authz checker
func NewTBAC(db *gorm.DB) *tbac {
	return &tbac{db}
}

// Allowed is a method that returns true if the principal is allowed to perform the action on the user.
func (d *tbac) Allowed(ctx context.Context, principal AuthzPrincipal, object AuthzObject, action AuthzAction) (bool, error) {
	var allowed int64

	err := d.db.Raw("SELECT COUNT(1) FROM vw_user_team_permissions WHERE user_id = ? AND team_id = ? AND permission = ?", principal, object, action).Count(&allowed).Error
	if err != nil {
		return false, err
	}

	if allowed > 0 {
		return true, nil
	}

	return false, nil
}
