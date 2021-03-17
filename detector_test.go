package detector

import (
	"testing"
)

func TestNewDetector(t *testing.T) {
	NewDetector()
}

func TestDetector_RDPCheck(t *testing.T) {
	det := NewDetector()
	if det.rdp.GetVersion() == ""{
		t.Fatal("rdp version is empty")
	}
	if len(det.rdp.GetSupportOSVersion()) == 0{
		t.Fatal("rdp Support OS Version is empty")
	}
	// change to your PC IP and port
	err := det.RDPCheck("192.168.200.24", "3389")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDetector_SSHCheck(t *testing.T) {

	det := NewDetector()
	if det.ssh.GetVersion() == ""{
		t.Fatal("ssh version is empty")
	}
	// change to your PC IP and port
	err := det.SSHCheck("192.168.200.23", "22")
	if err != nil {
		t.Fatal(err)
	}
}