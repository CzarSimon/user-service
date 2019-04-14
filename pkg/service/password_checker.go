package service

import (
	"net/http"

	"github.com/CzarSimon/user-service/pkg/httputil"
)

type passwordChecker interface {
	check(password, repeatPassword string) error
}

type defaultChecker struct {
	minLength int
}

func (c *defaultChecker) check(password, repeatPassword string) error {
	if len(password) < c.minLength {
		return httputil.NewError("password is to short", http.StatusBadRequest)
	}

	if password != repeatPassword {
		return httputil.NewError("passwords do not match", http.StatusBadRequest)
	}

	return nil
}
