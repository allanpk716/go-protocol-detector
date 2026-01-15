package pkg

import (
	"testing"
	"time"
)

func TestDetector_HBBSCheck(t *testing.T) {
	d := NewDetector(3 * time.Second)
	// Test against known RustDesk server
	err := d.HBBSCheck("116.62.8.4", "21115")
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
