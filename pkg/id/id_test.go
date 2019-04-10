package id

import (
	"testing"
)

func TestNewId(t *testing.T) {
	lastID := ""
	testCases := 100
	for i := 0; i < testCases; i++ {
		newID := New()
		if lastID == newID {
			t.Errorf("Should not equal:\nLastId: %s\nNewId: %s", lastID, newID)
		}
		lastID = newID
	}
}
