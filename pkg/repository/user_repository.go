package repository

import (
	"errors"

	"github.com/CzarSimon/user-service/pkg/models"
)

// Common user errors
var (
	ErrNoSuchUser = errors.New("no such user")
	ErrUserExists = errors.New("user already exists")
)

// UserRepository does stuff.
type UserRepository interface {
	Find(id string) (models.User, error)
	FindByEmail(email string) (models.User, error)
	Save(user models.User) error
	UpdatePassword(user models.User) error
}
