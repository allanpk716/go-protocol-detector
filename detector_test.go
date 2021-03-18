package Detector

import (
	"github.com/allanpk716/go-protocol-detector/CustomError"
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
	if err != CustomError.ErrRDPNotFound {
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
	if err != CustomError.ErrSSHNotFound {
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
	if err != CustomError.ErrFTPNotFound {
		t.Fatal(err)
	}
}

func TestDetector_SFTPCheck(t *testing.T) {
	det := NewDetector(timeOut)
	// change to your SFTP IP and port
	// use password login
	err := det.SFTPCheck("172.20.65.150", "22", "user", "123", "")
	if err != nil {
		t.Fatal(err)
	}
	// use private key login, private key with password '123'
	err = det.SFTPCheck("172.20.65.150", "22", "user", "123", "privatekey.ppk")
	//err := det.SFTPCheck("192.168.200.23", "22")
	if err != nil {
		t.Fatal(err)
	}
}


func TestDetector_TelnetCheck(t *testing.T) {
	det := NewDetector(timeOut)
	// change to your Telnet IP and port
	err := det.TelnetCheck("172.20.65.150", "23")
	if err != nil {
		t.Fatal(err)
	}

	err = det.TelnetCheck("192.168.200.1", "1")
	if err != CustomError.ErrTelnetNotFound {
		t.Fatal(err)
	}
}

func TestDetector_VNCCheck(t *testing.T) {
	det := NewDetector(timeOut)
	// change to your VNC IP and port
	err := det.VNCCheck("172.20.65.233", "5902")
	if err != nil {
		t.Fatal(err)
	}
	err = det.VNCCheck("192.168.200.1", "1")
	if err != CustomError.ErrVNCNotFound {
		t.Fatal(err)
	}
}