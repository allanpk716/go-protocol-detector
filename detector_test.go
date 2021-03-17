package detector

import (
	"testing"
)

func TestNewDetector(t *testing.T) {
	NewDetector()
}

func TestDetector_RDPCheck(t *testing.T) {
	det := NewDetector()
	// change to your PC IP and port
	err := det.RDPCheck("192.168.200.24", "3389")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDetector_SSHCheck(t *testing.T) {

	det := NewDetector()
	// change to your PC IP and port
	err := det.SSHCheck("192.168.200.23", "22")
	if err != nil {
		t.Fatal(err)
	}
}