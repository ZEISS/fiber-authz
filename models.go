package authz

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunMigrations ...
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&Role{},
		&Principal{},
		&User{},
		&Permission{},
		&RolePermission{},
		&UserPrincipal{},
		&UserRole{},
	)
	if err != nil {
		return err
	}

	query := db.Raw("SELECT A.user_id, A.principal_id, C.slug as permission FROM user_roles AS A LEFT JOIN role_permissions AS B ON A.role_id = B.role_id LEFT JOIN permissions AS C on B.permission_id = C.id;")

	return db.Migrator().CreateView("vw_user_principal_permissions", gorm.ViewOption{Query: query, Replace: true})
}

// Role ...
type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name        string
	Description string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// Principal ...
type Principal struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name        string
	Slug        string
	Description *string

	Users *[]Principal `gorm:"many2many:user_principals;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// User ...
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Name          string
	Email         string
	EmailVerified *string
	Image         *string

	Principals *[]Principal `gorm:"many2many:user_principals;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// Permission ...
type Permission struct {
	ID          uint `gorm:"primaryKey"`
	Slug        string
	Description *string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// RolePermission ...
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

// UserPrincipal ...
type UserPrincipal struct {
	ID uint `gorm:"primaryKey"`

	UserID uuid.UUID
	User   User

	PrincipalID uuid.UUID
	Principal   Principal

	gorm.Model
}

// UserRole ...
type UserRole struct {
	ID uint `gorm:"primaryKey"`

	UserID uuid.UUID
	User   User

	PrincipalID uuid.UUID
	Principal   Principal

	RoleID uuid.UUID
	Role   Role
}
