// +build windows

package pkg

import (
	"io"
	"os"
	"syscall"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	ENABLE_VIRTUAL_TERMINAL_PROCESSING uint32 = 0x0004
)

// isTerminal checks if the writer is a terminal on Windows
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		var st uint32
		err := syscall.GetConsoleMode(syscall.Handle(f.Fd()), &st)
		return err == nil
	}
	return false
}

// enableVirtualTerminalProcessing enables ANSI escape sequences on Windows 10+
func enableVirtualTerminalProcessing(w io.Writer) {
	if f, ok := w.(*os.File); ok {
		var mode uint32
		handle := syscall.Handle(f.Fd())
		if syscall.GetConsoleMode(handle, &mode) == nil {
			// Enable virtual terminal processing
			mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING
			procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
		}
	}
}
