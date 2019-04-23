package models

import (
	"testing"

	"github.com/CzarSimon/user-service/pkg/id"
	"github.com/stretchr/testify/assert"
)

func TestNewUser(t *testing.T) {
	assert := assert.New(t)

	email := "mail@mail.com"
	fname := "fname"
	lname := "lname"
	role := UserRole

	preUserID := id.New()
	c1 := Credentials{
		UserID:       preUserID,
		PasswordHash: "some-hash",
		Salt:         "some-salt",
	}

	// User with ID from credentials.
	user := NewUser(email, fname, lname, role, c1)
	assert.Equal(email, user.Email)
	assert.Equal(c1.UserID, user.ID)
	assert.Equal(preUserID, user.ID)
	assert.Equal(user.ID, user.Credentials.UserID)
	assert.NotEqual("", user.ID)

	c2 := Credentials{
		PasswordHash: "some-hash",
		Salt:         "some-salt",
	}
	// User with new ID.
	user = NewUser(email, fname, lname, role, c2)
	assert.Equal(email, user.Email)
	assert.Equal(user.ID, user.Credentials.UserID)
	assert.Equal("", c2.UserID)
	assert.NotEqual(preUserID, user.ID)
	assert.NotEqual("", user.ID)
}
