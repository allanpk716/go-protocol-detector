//go:build !windows

package utils

import "syscall"

// windowsRefusedErrno is a no-op on non-Windows platforms: real runtime errors
// already carry POSIX errno values matched directly in ClassifyNetError.
func windowsRefusedErrno(errno syscall.Errno) bool { return false }

// windowsUnreachableErrno is a no-op on non-Windows platforms.
func windowsUnreachableErrno(errno syscall.Errno) bool { return false }
