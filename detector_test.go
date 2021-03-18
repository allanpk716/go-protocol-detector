package Detector

import (
	"testing"
	"time"
)
var (
	timeOut = 3 * time.Second
)

func TestNewDetector(t *testing.T) {
	NewDetector(timeOut)
}

func TestDetector_RDPCheck(t *testing.T) {
	det := NewDetector(timeOut)
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
	//
	err = det.RDPCheck("192.168.200.1", "1")
	if err != ErrRDPNotFound {
		t.Fatal(err)
	}
}

func TestDetector_SSHCheck(t *testing.T) {

	det := NewDetector(timeOut)
	if det.ssh.GetVersion() == ""{
		t.Fatal("ssh version is empty")
	}
	// change to your PC IP and port
	err := det.SSHCheck("192.168.200.23", "22")
	if err != nil {
		t.Fatal(err)
	}
	//
	err = det.SSHCheck("192.168.200.1", "1")
	if err != ErrSSHNotFound {
		t.Fatal(err)
	}
}

func TestDetector_FTPCheck(t *testing.T) {
	det := NewDetector(timeOut)
	if det.ftp.GetVersion() == ""{
		t.Fatal("ftp version is empty")
	}
	// change to your FTP IP and port
	err := det.FTPCheck("cdimage.debian.org", "21")
	if err != nil {
		t.Fatal(err)
	}
	//
	err = det.FTPCheck("192.168.200.1", "1")
	if err != ErrFTPNotFound {
		t.Fatal(err)
	}
}

func TestDetector_TelnetCheck(t *testing.T) {
	det := NewDetector(timeOut)
	// change to your FTP IP and port
	err := det.TelnetCheck("172.20.65.150", "23")
	if err != nil {
		t.Fatal(err)
	}
	//
	err = det.TelnetCheck("192.168.200.1", "1")
	if err != ErrTelnetNotFound {
		t.Fatal(err)
	}
}