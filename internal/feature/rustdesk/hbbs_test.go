package rustdesk

import (
	"bytes"
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

	// Verify complete package structure.
	// hbb_common's BytesCodec frames the payload with a variable-length header:
	// for a 4-byte payload the 1-byte header is (4 << 2) = 0x10.
	expectedPackage := []byte{
		0x10,                   // BytesCodec length header (4 << 2)
		0xA2, 0x02,             // field 20 tag + length
		0x08, 0x00,             // field 1 (serial) + value
	}
	if !bytes.Equal(pkg, expectedPackage) {
		t.Errorf("Package mismatch:\ngot  %x\nwant %x", pkg, expectedPackage)
	}

	// Also verify the BytesCodec length header decodes back to the payload length
	if len(pkg) < 1 {
		t.Fatalf("Package too short: %d bytes", len(pkg))
	}
	headerLen := pkg[0] >> 2
	if headerLen != byte(len(pkg)-1) {
		t.Errorf("Length header mismatch: header says %d, payload is %d", headerLen, len(pkg)-1)
	}
}

func TestHBBSHelperReceiverFeatures(t *testing.T) {
	helper := NewHBBSHelper()
	features := helper.ReceiverFeatures
	if len(features) == 0 {
		t.Error("ReceiverFeatures should not be empty")
	}
}
