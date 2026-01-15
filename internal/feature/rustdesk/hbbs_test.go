package rustdesk

import (
	"testing"
)

func TestNewHBBSHelper(t *testing.T) {
	helper := NewHBBSHelper()
	if helper == nil {
		t.Fatal("NewHBBSHelper returned nil")
	}
	if helper.GetVersion() == "" {
		t.Error("Version should not be empty")
	}
}

func TestHBBSHelperSenderPackage(t *testing.T) {
	helper := NewHBBSHelper()
	pkg := helper.SenderPackage
	if len(pkg) == 0 {
		t.Error("SenderPackage should not be empty")
	}
	expectedPrefix := []byte{0x00, 0x00, 0x00, 0x04}
	if len(pkg) < 4 {
		t.Fatalf("Package too short: %d bytes", len(pkg))
	}
	if pkg[0] != expectedPrefix[0] || pkg[1] != expectedPrefix[1] ||
	   pkg[2] != expectedPrefix[2] || pkg[3] != expectedPrefix[3] {
		t.Errorf("Length prefix mismatch: got %x, want %x", pkg[0:4], expectedPrefix)
	}
}

func TestHBBSHelperReceiverFeatures(t *testing.T) {
	helper := NewHBBSHelper()
	features := helper.ReceiverFeatures
	if len(features) == 0 {
		t.Error("ReceiverFeatures should not be empty")
	}
}
