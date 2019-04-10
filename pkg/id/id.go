package id

import (
	uuid "github.com/satori/go.uuid"
)

// New creates a new unique id.
func New() string {
	return uuid.NewV4().String()
}
