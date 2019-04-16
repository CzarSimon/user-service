package service

import (
	"log"
	"net/http"

	"github.com/CzarSimon/user-service/pkg/auth"
	"github.com/CzarSimon/user-service/pkg/httputil"
	"github.com/CzarSimon/user-service/pkg/models"
	"github.com/CzarSimon/user-service/pkg/repository"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func init() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalln("Failed to get zap.Logger", err)
	}

	logger = l.Sugar().With("application", "user-service", "package", "pkg/service")
}

// UserService service responsible for business logic related to users.
type UserService interface {
	SignUp(req models.SignupRequest) (models.LoginResponse, error)
	Login(req models.LoginRequest) (models.LoginResponse, error)
	Find(id string) (models.User, error)
}

type userSvc struct {
	hasher          auth.Hasher
	issuer          auth.Issuer
	userRepo        repository.UserRepository
	passwordChecker passwordChecker
	saltLength      int
}

func (svc *userSvc) SignUp(req models.SignupRequest) (models.LoginResponse, error) {
	_, err := svc.userRepo.FindByEmail(req.Email)
	if err != repository.ErrNoSuchUser {
		return models.LoginResponse{}, errUserAlreadyExists()
	}

	credentials, err := svc.createCredentials(req)
	if err != nil {
		return models.LoginResponse{}, err
	}

	user := req.User(credentials)
	err = svc.userRepo.Save(user)
	if err != nil {
		logger.Errorw("Failed to save user", "err", err)
		return models.LoginResponse{}, httputil.NewInternalServerError("Failed to save user")
	}

	return svc.createLoginResponse(user)
}

func (svc *userSvc) createCredentials(req models.SignupRequest) (models.Credentials, error) {
	err := svc.passwordChecker.check(req.Password, req.RepeatPassword)
	if err != nil {
		return models.Credentials{}, err
	}

	salt, err := auth.GenSalt(svc.saltLength)
	if err != nil {
		logger.Errorw("Failed generate salt", "err", err)
		return models.Credentials{}, httputil.NewInternalServerError("Failed to generate salt")
	}

	hash, err := svc.hasher.Hash(req.Password, salt)
	if err != nil {
		logger.Errorw("Failed generate hash", "err", err)
		return models.Credentials{}, httputil.NewInternalServerError("Failed to hash password")
	}

	return models.Credentials{
		PasswordHash: hash,
		Salt:         salt,
	}, nil
}

func (svc *userSvc) Login(req models.LoginRequest) (models.LoginResponse, error) {
	user, err := svc.userRepo.FindByEmail(req.Email)
	if err == repository.ErrNoSuchUser {
		return models.LoginResponse{}, errNoSuchUser()
	} else if err != nil {
		return models.LoginResponse{}, httputil.NewInternalServerError("Failed to get user")
	}

	err = svc.hasher.Verify(req.Password, user.Credentials.Salt, user.Credentials.PasswordHash)
	if err != nil {
		logger.Errorw("Failed generate salt", "err", err)
		return models.LoginResponse{}, errInvalidCredentials()
	}

	return svc.createLoginResponse(user)
}

func (svc *userSvc) Find(id string) (models.User, error) {
	user, err := svc.userRepo.Find(id)
	if err != nil {
		return models.User{}, httputil.NewError("No such user", http.StatusNotFound)
	}

	return user, nil
}

func (svc *userSvc) createLoginResponse(user models.User) (models.LoginResponse, error) {
	token, err := svc.issuer.Issue(user.ID, user.Role)
	if err != nil {
		logger.Errorw("Failed issue token", "err", err)
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

func errNoSuchUser() error {
	return httputil.NewError("No such user", http.StatusUnauthorized)
}

func errInvalidCredentials() error {
	return httputil.NewError("Email and password does not match", http.StatusUnauthorized)
}
