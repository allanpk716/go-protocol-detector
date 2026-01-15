package rustdesk

import (
	"testing"
)

func TestNewHBBRHelper(t *testing.T) {
	helper := NewHBBRHelper()
	if helper == nil {
		t.Fatal("NewHBBRHelper returned nil")
	}
	if helper.GetVersion() == "" {
		t.Error("Version should not be empty")
	}
}

func TestHBBRHelperStructure(t *testing.T) {
	helper := NewHBBRHelper()
	// HBBR uses connection-based detection, no packet needed
	// Helper should exist and have version
	if helper.GetVersion() == "" {
		t.Error("Version should not be empty")
	}
}
