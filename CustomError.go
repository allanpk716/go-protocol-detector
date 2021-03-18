package Detector

import "errors"

var (
	ErrRDPNotFound = errors.New("rdp not found")
	ErrSSHNotFound = errors.New("ssh not found")
	ErrFTPNotFound = errors.New("ftp not found")
	ErrTelnetNotFound = errors.New("telnet not found")
)
