package pkg

import (
	"errors"
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
	"strconv"
	"testing"
	"time"
)

func TestScanWithOutputRetainsAllResults(t *testing.T) {
	port, stop := startFakeServer(t, "")
	defer stop()
	closed := closedPort(t)

	st := NewScanTools(4, 2*time.Second)
	out, ctx, err := st.ScanWithOutput(Common, InputInfo{
		Host: "127.0.0.1",
		Port: strconv.Itoa(port) + "," + strconv.Itoa(closed),
	}, false, "", false)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(out.AllResults) != 2 {
		t.Fatalf("AllResults len = %d, want 2", len(out.AllResults))
	}
	hits, closedCount := 0, 0
	for _, r := range out.AllResults {
		if r.Success {
			hits++
			if r.Reason != "" {
				t.Fatalf("hit has reason %q", r.Reason)
			}
		} else {
			if r.Reason != "closed" {
				t.Fatalf("closed-port result reason = %q, want closed", r.Reason)
			}
			closedCount++
		}
	}
	if hits != 1 || closedCount != 1 {
		t.Fatalf("hits=%d closed=%d, want 1/1", hits, closedCount)
	}
	if ctx.HostsCount != 1 || ctx.PortsCount != 2 {
		t.Fatalf("ctx counts = %d/%d, want 1/2", ctx.HostsCount, ctx.PortsCount)
	}
}

func TestIsKnownProtocol(t *testing.T) {
	for _, ok := range []string{"common", "rdp", "ssh", "ftp", "sftp", "telnet", "vnc", "rustdesk-hbbs", "rustdesk-hbbr", "rustdesk-hbbs-21116"} {
		if !IsKnownProtocol(ok) {
			t.Fatalf("%q should be known", ok)
		}
	}
	for _, bad := range []string{"", "http", "RDP"} {
		if IsKnownProtocol(bad) {
			t.Fatalf("%q should be unknown", bad)
		}
	}
}

func TestParseHostInvalidIsValidationError(t *testing.T) {
	st := NewScanTools(2, time.Second)
	_, err := st.parseHost("not-an-ip")
	if err == nil {
		t.Fatal("expected error")
	}
	var se *scanErrors.ScannerError
	if !errors.As(err, &se) || se.Type != scanErrors.ErrorTypeValidation {
		t.Fatalf("error should be VALIDATION-typed, got %#v", err)
	}
}
