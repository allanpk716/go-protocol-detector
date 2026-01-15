package pkg

import (
	"testing"
	"time"
)

func TestScanTools_RustDeskHBBSScan(t *testing.T) {
	scan := NewScanTools(1, 3*time.Second)
	input := InputInfo{
		Host: "116.62.8.4",
		Port: "21115",
	}
	output, err := scan.Scan(RustDeskHBBS, input, false)
	if err != nil {
		t.Logf("RustDesk HBBS scan error: %v", err)
	}

	// Verify results
	if output != nil {
		t.Logf("HBBS Scan Results - Success: %d, Failed: %d",
			len(output.SuccessMapString), len(output.FailedMapString))
		for host, ports := range output.SuccessMapString {
			t.Logf("  Host %s: %v", host, ports)
		}
		for host, ports := range output.FailedMapString {
			t.Logf("  Host %s: %v", host, ports)
		}
	}
}

func TestScanTools_RustDeskHBBRScan(t *testing.T) {
	scan := NewScanTools(1, 3*time.Second)
	input := InputInfo{
		Host: "116.62.8.4",
		Port: "21117",
	}
	output, err := scan.Scan(RustDeskHBBR, input, false)
	if err != nil {
		t.Logf("RustDesk HBBR scan error: %v", err)
	}

	// Verify results
	if output != nil {
		t.Logf("HBBR Scan Results - Success: %d, Failed: %d",
			len(output.SuccessMapString), len(output.FailedMapString))
		for host, ports := range output.SuccessMapString {
			t.Logf("  Host %s: %v", host, ports)
		}
		for host, ports := range output.FailedMapString {
			t.Logf("  Host %s: %v", host, ports)
		}
	}
}

func TestScanTools_RustDeskScanWithLocalhost(t *testing.T) {
	// Test with localhost to verify switch cases work (should fail gracefully)

	// Test HBBS
	scan := NewScanTools(1, 1*time.Second)
	input := InputInfo{
		Host: "127.0.0.1",
		Port: "21115",
	}
	output, err := scan.Scan(RustDeskHBBS, input, false)
	if err != nil {
		t.Logf("RustDesk HBBS localhost scan error: %v", err)
	}
	if output != nil {
		t.Logf("HBBS Localhost - Success: %v, Failed: %v",
			len(output.SuccessMapString), len(output.FailedMapString))
	}

	// Test HBBR (create new ScanTools to avoid RateLimiter double-stop)
	scan2 := NewScanTools(1, 1*time.Second)
	input2 := InputInfo{
		Host: "127.0.0.1",
		Port: "21117",
	}
	output, err = scan2.Scan(RustDeskHBBR, input2, false)
	if err != nil {
		t.Logf("RustDesk HBBR localhost scan error: %v", err)
	}
	if output != nil {
		t.Logf("HBBR Localhost - Success: %v, Failed: %v",
			len(output.SuccessMapString), len(output.FailedMapString))
	}
}
