package models

import (
	"time"

	"github.com/CzarSimon/user-service/pkg/id"
)

// Role constants.
const (
	AnonymousRole = "ANONYMOUS"
	UserRole      = "USER"
	AdminRole     = "ADMIN"
)

// User holds data about an application user.
type User struct {
	ID                string      `json:"id,omitempty"`
	Email             string      `json:"email,omitempty"`
	Surname           string      `json:"surname,omitempty"`
	MiddleAndLastName string      `json:"middleAndLastName,omitempty"`
	Role              string      `json:"role,omitempty"`
	CreatedAt         time.Time   `json:"createdAt,omitempty"`
	Credentials       Credentials `json:"-"`
}

// NewUser creates a new User.
func NewUser(email, surname, lastName, role string, credentials Credentials) User {
	return User{
		ID:                id.New(),
		Email:             email,
		Surname:           surname,
		MiddleAndLastName: lastName,
		Role:              role,
		CreatedAt:         now(),
		Credentials:       credentials,
	}
}

// SignupRequest request body for a user signup.
type SignupRequest struct {
	Email             string `json:"email,omitempty"`
	Password          string `json:"password,omitempty"`
	RepeatPassword    string `json:"repeatPassword,omitempty"`
	Surname           string `json:"surname,omitempty"`
	MiddleAndLastName string `json:"middleAndLastName,omitempty"`
}

// User creates a new user from a signup request.
func (s *SignupRequest) User(credentials Credentials) User {
	return NewUser(s.Email, s.Surname, s.MiddleAndLastName, UserRole, credentials)
}

// LoginRequest request body for a user login.
type LoginRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// LoginResponse response for login and signup requests.
type LoginResponse struct {
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	User         User   `json:"user,omitempty"`
}

// ChangePasswordRequest request body for changing a user password.
type ChangePasswordRequest struct {
	Email       string `json:"email,omitempty"`
	OldPassword string `json:"oldPassword,omitempty"`
	NewPassword string `json:"newPassword,omitempty"`
}

// Credentials authentication information.
type Credentials struct {
	UserID       string
	PasswordHash string
	Salt         string
}

func now() time.Time {
	return time.Now().UTC()
}
