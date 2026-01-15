package custom_error

import (
	"errors"
	"testing"
)

func TestRustDeskErrors(t *testing.T) {
	if !errors.Is(ErrRustDeskHBBSNotFound, ErrRustDeskHBBSNotFound) {
		t.Error("ErrRustDeskHBBSNotFound should match itself")
	}
	if !errors.Is(ErrRustDeskHBBRNotFound, ErrRustDeskHBBRNotFound) {
		t.Error("ErrRustDeskHBBRNotFound should match itself")
	}
}
