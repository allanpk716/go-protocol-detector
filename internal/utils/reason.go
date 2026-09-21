package utils

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// Negative-result reasons. Fixed enum; see CONTEXT.md (负结果原因).
const (
	ReasonClosed           = "closed"
	ReasonTimeout          = "timeout"
	ReasonProtocolMismatch = "protocol_mismatch"
	ReasonUnreachable      = "unreachable"
	ReasonUnknown          = "unknown"
)

const (
	maxBannerLen = 128
	minBannerLen = 4
)

// ClassifyNetError maps a network-layer error to a negative-reason enum value.
// It is stage-agnostic: dial errors and read errors both flow through here.
// Wrapped chains must keep the raw error reachable via errors.As — callers
// that wrap must use double %w (fmt.Errorf("%w: %w", ...)), not %v.
func ClassifyNetError(err error) string {
	if err == nil {
		return ReasonUnknown
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			return ReasonClosed
		case syscall.EHOSTUNREACH, syscall.ENETUNREACH:
			return ReasonUnreachable
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonTimeout
	}
	// EOF at read stage: the TCP connection was established but the peer
	// closed it without speaking the expected protocol.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ReasonProtocolMismatch
	}
	return ReasonUnknown
}

// SanitizeBanner returns the printable-ASCII prefix of a raw response,
// stopping at the first CR/LF or non-printable byte, capped at 128 bytes.
// Fewer than 4 printable leading bytes yields "" (binary protocols).
func SanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == '\r' || c == '\n' {
			break
		}
		if c < 0x20 || c > 0x7E {
			break
		}
		sb.WriteByte(c)
		if sb.Len() >= maxBannerLen {
			break
		}
	}
	if sb.Len() < minBannerLen {
		return ""
	}
	return sb.String()
}
