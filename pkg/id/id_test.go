package id_test

import (
	"testing"

	"github.com/CzarSimon/user-service/pkg/id"
)

func TestNewId(t *testing.T) {
	lastId := ""
	testCases := 1
	for i := 0; i < testCases; i++ {
		newId := id.New()
		if lastId == newId {
			t.Errorf("Should not equal:\nLastId: %s\nNewId: %s", lastId, newId)
		}
	}
}
