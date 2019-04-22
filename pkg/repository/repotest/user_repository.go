package repotest

import (
	"github.com/CzarSimon/user-service/pkg/models"
)

// MockUserRepo mock implementation of repository.UserRepository.
type MockUserRepo struct {
	FindUser        models.User
	FindErr         error
	FindArg         string
	FindInvocations int

	FindByEmailUser        models.User
	FindByEmailErr         error
	FindByEmailArg         string
	FindByEmailInvocations int

	SaveErr         error
	SaveArg         models.User
	SaveInvocations int

	UpdatePasswordErr         error
	UpdatePasswordArg         models.User
	UpdatePasswordInvocations int
}

// Find mock implementation of finding a user by id.
func (ur *MockUserRepo) Find(id string) (models.User, error) {
	ur.FindArg = id
	ur.FindInvocations++
	return ur.FindUser, ur.FindErr
}

// FindByEmail mock implementation of finding a user by email.
func (ur *MockUserRepo) FindByEmail(email string) (models.User, error) {
	ur.FindByEmailArg = email
	ur.FindByEmailInvocations++
	return ur.FindByEmailUser, ur.FindByEmailErr
}

// Save mock implementation of saving a user.
func (ur *MockUserRepo) Save(user models.User) error {
	ur.SaveArg = user
	ur.SaveInvocations++
	return ur.SaveErr
}

// UpdatePassword mock implementation of updating a users password.
func (ur *MockUserRepo) UpdatePassword(user models.User) error {
	ur.UpdatePasswordArg = user
	ur.UpdatePasswordInvocations++
	return ur.UpdatePasswordErr
}

// UnsetArgs unsets all recoreded arguments and invocations.
func (ur *MockUserRepo) UnsetArgs() {
	ur.FindInvocations = 0
	ur.FindByEmailInvocations = 0
	ur.SaveInvocations = 0
	ur.UpdatePasswordInvocations = 0

	ur.FindArg = ""
	ur.FindByEmailArg = ""
	ur.SaveArg = models.User{}
}
