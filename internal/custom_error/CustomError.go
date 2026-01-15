package custom_error

import "errors"

var (
	ErrRDPNotFound    = errors.New("rdp not found")
	ErrSSHNotFound    = errors.New("ssh not found")
	ErrFTPNotFound    = errors.New("ftp not found")
	ErrTelnetNotFound = errors.New("telnet not found")
	ErrVNCNotFound    = errors.New("vnc not found")
	ErrSFTPNotFound        = errors.New("sftp not found")
	ErrRustDeskHBBSNotFound = errors.New("rustdesk hbbs not found")
	ErrRustDeskHBBRNotFound = errors.New("rustdesk hbbr not found")
	ErrRustDeskHBBS21116NotFound = errors.New("rustdesk hbbs 21116 not found")

	ErrCommontPortCheckError = errors.New("commont port check error")

	ErrInScanRangeCannotFound = errors.New("in scan range cannot found")
)

const ErrSSHOrgErrorInfo = "ssh: handshake failed"
