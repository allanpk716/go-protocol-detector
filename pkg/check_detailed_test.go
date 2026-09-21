package pkg

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// startFakeServer accepts connections in a loop and writes greeting on accept.
func startFakeServer(t *testing.T, greeting string) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if greeting != "" {
				_, _ = conn.Write([]byte(greeting))
			}
			// hold connection open until test ends
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return p, func() { _ = ln.Close(); <-done }
}

// startPartialVNCServer sends ONLY the 4-byte "RFB " prefix, then stalls —
// exactly the peer shape that must still be detected as a VNC hit, because
// the old Check() matched on those 4 bytes alone.
func startPartialVNCServer(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("RFB "))
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Read(buf) // stall: never send the remaining 8 bytes
			_ = conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return p, func() { _ = ln.Close(); <-done }
}

// closedPort grabs an ephemeral port and releases it, so dialing it is refused.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p, _ := strconv.Atoi(ln.Addr().String()[len("127.0.0.1:"):])
	_ = ln.Close()
	return p
}

func TestCheckDetailedCommonHit(t *testing.T) {
	port, stop := startFakeServer(t, "")
	defer stop()
	d := NewDetector(2 * time.Second)
	detail, err := d.CheckDetailed(Common, "127.0.0.1", strconv.Itoa(port), "", "", "")
	if err != nil {
		t.Fatalf("common check failed: %v", err)
	}
	if detail.Reason != "" {
		t.Fatalf("hit should have empty reason, got %q", detail.Reason)
	}
	if detail.Banner != "" {
		t.Fatalf("common protocol has no banner, got %q", detail.Banner)
	}
}

func TestCheckDetailedClosedPort(t *testing.T) {
	port := closedPort(t)
	d := NewDetector(2 * time.Second)
	detail, err := d.CheckDetailed(SSH, "127.0.0.1", strconv.Itoa(port), "", "", "")
	if err == nil {
		t.Fatal("expected error on closed port")
	}
	if detail.Reason != "closed" {
		t.Fatalf("reason = %q, want closed", detail.Reason)
	}
}

func TestCheckDetailedSSHHitWithBanner(t *testing.T) {
	port, stop := startFakeServer(t, "SSH-2.0-TestServer\r\n")
	defer stop()
	d := NewDetector(2 * time.Second)
	detail, err := d.CheckDetailed(SSH, "127.0.0.1", strconv.Itoa(port), "", "", "")
	if err != nil {
		t.Fatalf("ssh check failed: %v", err)
	}
	if detail.Banner != "SSH-2.0-TestServer" {
		t.Fatalf("banner = %q, want SSH-2.0-TestServer", detail.Banner)
	}
}

func TestCheckDetailedProtocolMismatch(t *testing.T) {
	// 12+ junk bytes: not an RFB version string
	port, stop := startFakeServer(t, "HELLO-WORLD-JUNK")
	defer stop()
	d := NewDetector(2 * time.Second)
	detail, err := d.CheckDetailed(VNC, "127.0.0.1", strconv.Itoa(port), "", "", "")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if detail.Reason != "protocol_mismatch" {
		t.Fatalf("reason = %q, want protocol_mismatch", detail.Reason)
	}
}

func TestCheckDetailedVNCHitWithBanner(t *testing.T) {
	port, stop := startFakeServer(t, "RFB 003.008\n")
	defer stop()
	d := NewDetector(2 * time.Second)
	detail, err := d.CheckDetailed(VNC, "127.0.0.1", strconv.Itoa(port), "", "", "")
	if err != nil {
		t.Fatalf("vnc check failed: %v", err)
	}
	if detail.Banner != "RFB 003.008" {
		t.Fatalf("banner = %q, want RFB 003.008", detail.Banner)
	}
}

// TestCheckDetailedVNCPartialDataStillHits pins the human-mode equivalence
// guarantee: a peer that sends only the 4-byte "RFB " prefix is a HIT with an
// empty banner — identical outcome to the old Check(), banner aside.
func TestCheckDetailedVNCPartialDataStillHits(t *testing.T) {
	port, stop := startPartialVNCServer(t)
	defer stop()
	d := NewDetector(2 * time.Second)
	detail, err := d.CheckDetailed(VNC, "127.0.0.1", strconv.Itoa(port), "", "", "")
	if err != nil {
		t.Fatalf("partial-data VNC peer must still hit (old 4-byte semantics): %v", err)
	}
	if detail.Banner != "" {
		t.Fatalf("banner should be empty on partial data, got %q", detail.Banner)
	}
}
