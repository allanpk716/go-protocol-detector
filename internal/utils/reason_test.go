package utils

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func dialErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

func TestClassifyNetError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ReasonUnknown},
		{"refused", dialErr(syscall.ECONNREFUSED), ReasonClosed},
		{"host unreachable", dialErr(syscall.EHOSTUNREACH), ReasonUnreachable},
		{"net unreachable", dialErr(syscall.ENETUNREACH), ReasonUnreachable},
		{"eof", io.EOF, ReasonProtocolMismatch},
		{"unexpected eof", io.ErrUnexpectedEOF, ReasonProtocolMismatch},
		{"plain error", errors.New("boom"), ReasonUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyNetError(c.err); got != c.want {
				t.Fatalf("ClassifyNetError(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

func TestClassifyNetErrorTimeout(t *testing.T) {
	// net.DialTimeout timeout errors satisfy net.Error with Timeout()==true,
	// including when wrapped by outer layers.
	timeoutErr := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	if got := ClassifyNetError(errors.Join(errors.New("ctx: "), timeoutErr)); got != ReasonTimeout {
		t.Fatalf("wrapped deadline error classified as %q, want %q", got, ReasonTimeout)
	}
}

// TestClassifyNetErrorWrappedChain guards the double-%w wrapping style used by
// the SFTP check: the sentinel must stay Is()-able AND the raw network error
// must stay As()-able through the chain.
func TestClassifyNetErrorWrappedChain(t *testing.T) {
	sentinel := errors.New("sftp not found")
	wrapped := fmt.Errorf("%w: %w", sentinel, dialErr(syscall.ECONNREFUSED))
	if !errors.Is(wrapped, sentinel) {
		t.Fatal("sentinel must survive the double-%w wrap")
	}
	if got := ClassifyNetError(wrapped); got != ReasonClosed {
		t.Fatalf("wrapped chain classified as %q, want %q", got, ReasonClosed)
	}

	wrappedTimeout := fmt.Errorf("%w: %w", sentinel, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded})
	if got := ClassifyNetError(wrappedTimeout); got != ReasonTimeout {
		t.Fatalf("wrapped timeout classified as %q, want %q", got, ReasonTimeout)
	}
}

func TestSanitizeBanner(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"ssh banner line", []byte("SSH-2.0-OpenSSH_8.9\r\nSSH-2.0..."), "SSH-2.0-OpenSSH_8.9"},
		{"ftp banner", []byte("220 ProFTPD Server (ftp)\r\n"), "220 ProFTPD Server (ftp)"},
		{"binary stops at first non-printable", []byte{0x03, 0x00, 'S', 'S', 'H'}, ""},
		{"too short", []byte("22"), ""},
		{"exactly four chars", []byte("220 "), "220 "},
		{"nul after four printables", append([]byte("220 "), make([]byte, 200)...), "220 "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SanitizeBanner(c.in); got != c.want {
				t.Fatalf("SanitizeBanner(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func bytesOf(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

func TestSanitizeBannerLengthCap(t *testing.T) {
	long := bytesOf('x', 300)
	got := SanitizeBanner(long)
	if len(got) != 128 {
		t.Fatalf("banner length = %d, want 128", len(got))
	}
}
