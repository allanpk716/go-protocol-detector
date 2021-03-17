package detector

import "errors"

var (
	ErrRDPNotFound = errors.New("rdp not found")
	ErrSSHNotFound = errors.New("ssh not found")
)
