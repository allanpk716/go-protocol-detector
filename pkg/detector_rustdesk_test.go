package pkg

import (
	"testing"
	"time"
)

func TestDetector_HBBSCheck(t *testing.T) {
	d := NewDetector(3 * time.Second)
	// Test against known RustDesk server (port 21116)
	// Note: Port 21115 is NOT detected - see internal/feature/rustdesk/README.md for details
	err := d.HBBSCheck("116.62.8.4", "21116")
	if err != nil {
		t.Logf("HBBS check failed (server may be unavailable): %v", err)
	}
}

func TestDetector_HBBRCheck(t *testing.T) {
	d := NewDetector(3 * time.Second)
	// Test against known RustDesk server
	err := d.HBBRCheck("116.62.8.4", "21117")
	if err != nil {
		t.Logf("HBBR check failed (server may be unavailable): %v", err)
	}
}

func TestDetector_HBBS21116Check(t *testing.T) {
	d := NewDetector(3 * time.Second)
	// Test against known RustDesk server
	err := d.HBBS21116Check("116.62.8.4", "21116")
	if err != nil {
		t.Logf("HBBS21116 check failed (server may be unavailable): %v", err)
	}
}
