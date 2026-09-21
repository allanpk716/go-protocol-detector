//go:build windows

package utils

import "syscall"

// WSA socket error codes from the Windows Sockets specification (winsock2.h).
// Real runtime errors on Windows carry these values; the POSIX-named
// syscall.ECONNREFUSED is a synthetic value on this platform and never matches.
// The stdlib syscall package does not export the WSA* constants, hence the
// literals.
const (
	wsaEConnRefused syscall.Errno = 10061 // WSAECONNREFUSED
	wsaEHostUnreach syscall.Errno = 10065 // WSAEHOSTUNREACH
	wsaENetUnreach  syscall.Errno = 10051 // WSAENETUNREACH
)

// windowsRefusedErrno reports errno values that mean "connection refused" on
// Windows.
func windowsRefusedErrno(errno syscall.Errno) bool {
	return errno == wsaEConnRefused
}

// windowsUnreachableErrno reports errno values that mean "network unreachable"
// (host or network level).
func windowsUnreachableErrno(errno syscall.Errno) bool {
	return errno == wsaEHostUnreach || errno == wsaENetUnreach
}
