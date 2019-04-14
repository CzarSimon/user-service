package service

import (
	"net/http"

	"github.com/CzarSimon/user-service/pkg/auth"
	"github.com/CzarSimon/user-service/pkg/httputil"
	"github.com/CzarSimon/user-service/pkg/models"
	"github.com/CzarSimon/user-service/pkg/repository"
)

// UserService service responsible for business logic related to users.
type UserService interface {
	SignUp(req models.SignupRequest) (models.LoginResponse, error)
}

type userSvc struct {
	hasher   auth.Hasher
	issuer   auth.Issuer
	userRepo repository.UserRepository
}

func (svc *userSvc) SignUp(req models.SignupRequest) (models.LoginResponse, error) {
	_, err := svc.userRepo.FindByEmail(req.Email)
	if err != repository.ErrNoSuchUser {
		return models.LoginResponse{}, errUserAlreadyExists()
	}

	user := models.NewUser(req.Email, req.Surname, req.MiddleAndLastName, models.UserRole)
	err = svc.userRepo.Save(user)
	if err != nil {
		return models.LoginResponse{}, httputil.NewInternalServerError("Failed to save user")
	}

	return svc.createLoginResponse(user)
}

func (svc *userSvc) createLoginResponse(user models.User) (models.LoginResponse, error) {
	token, err := svc.issuer.Issue(user.ID, user.Role)
	if err != nil {
		return models.LoginResponse{}, httputil.NewInternalServerError("Failed to generate token")
	}

	return models.LoginResponse{
		Token: token,
		User:  user,
	}, nil
}

func errUserAlreadyExists() error {
	return httputil.NewError("User already exists", http.StatusConflict)
}
