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
// This works with native Windows console and Git Bash/MSYS2 terminals
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		// Try native Windows console check first
		var st uint32
		err := syscall.GetConsoleMode(syscall.Handle(f.Fd()), &st)
		if err == nil {
			return true // Native Windows console
		}

		// For Git Bash/MSYS2, check if output is to a terminal (not a file/pipe)
		// In Git Bash, file descriptor 1 (stdout) is a terminal when running interactively
		// We can check this by seeing if the file is a character device
		fileInfo, _ := f.Stat()
		if fileInfo != nil && (fileInfo.Mode()&os.ModeCharDevice) != 0 {
			return true // Character device (likely a terminal)
		}
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
