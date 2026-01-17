// +build darwin

package pkg

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// isTerminal checks if the writer is a terminal on macOS
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		var termios syscall.Termios
		_, _, err := syscall.Syscall6(
			syscall.SYS_IOCTL,
			uintptr(f.Fd()),
			uintptr(syscall.TIOCGETA),
			uintptr(unsafe.Pointer(&termios)),
			0, 0, 0,
		)
		return err == 0
	}
	return false
}

// enableVirtualTerminalProcessing is a no-op on macOS
// ANSI escape sequences are natively supported
func enableVirtualTerminalProcessing(w io.Writer) {
	// Not needed on macOS - terminals natively support ANSI codes
}
