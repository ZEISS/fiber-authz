package authz

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunMigrations ...
func RunMigrations(db *gorm.DB) error {
	return db.AutoMigrate(
		&Role{},
		&Team{},
		&User{},
		&Permission{},
		&RolePermission{},
		&UserTeam{},
		&UserPermission{},
		&UserRole{},
	)
}

// Role ...
type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Name        string
	Description string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// Team ...
type Team struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Name        string
	Slug        string
	Description *string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	gorm.Model
}

// User ...
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Name          string
	Email         string
	EmailVerified *string
	Image         *string
	Teams         *[]Team

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

	UserID uuid.UUID
	User   User

	RoleID uuid.UUID
	Role   Role

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}

// UserTeams ...
type UserTeam struct {
	ID uint `gorm:"primaryKey"`

	UserID uuid.UUID
	User   User

	TeamID uuid.UUID
	Team   Team

	gorm.Model
}

// UserPermission ...
type UserPermission struct {
	UserID uuid.UUID
	User   User

	TeamID uuid.UUID
	Team   Team

	Permission string
}

// UserRole ...
type UserRole struct {
	ID uint `gorm:"primaryKey"`

	UserID uuid.UUID
	User   User

	TeamID uuid.UUID
	Team   Team

	RoleID uuid.UUID
	Role   Role
}
