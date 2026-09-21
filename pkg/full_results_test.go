package pkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteFullResultsJSON(t *testing.T) {
	results := []CheckResult{
		{Success: true, Host: "10.0.0.1", Port: "22", ResponseTime: 5 * time.Millisecond, Banner: "SSH-2.0-X"},
		{Success: false, Host: "10.0.0.2", Port: "22", Reason: "closed"},
	}
	path := filepath.Join(t.TempDir(), "full.json")
	if err := WriteFullResultsJSON(path, "ssh", "scan-9", results); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	var got FullScanResults
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got.Protocol != "ssh" || got.ScanID != "scan-9" {
		t.Fatalf("header = %+v", got)
	}
	if len(got.Hits) != 1 || got.Hits[0].Banner != "SSH-2.0-X" {
		t.Fatalf("hits = %+v", got.Hits)
	}
	if len(got.Negatives) != 1 || got.Negatives[0].Reason != "closed" {
		t.Fatalf("negatives = %+v", got.Negatives)
	}
	if len(got.Errors) != 0 {
		t.Fatalf("errors = %+v", got.Errors)
	}
	if got.Timestamp == "" {
		t.Fatal("timestamp must be set")
	}
}

func TestWriteFullResultsJSONOver100NegativesNotTruncated(t *testing.T) {
	var results []CheckResult
	for i := 0; i < 120; i++ {
		results = append(results, CheckResult{Success: false, Host: "10.0.0.1", Port: "22", Reason: "timeout"})
	}
	path := filepath.Join(t.TempDir(), "big.json")
	if err := WriteFullResultsJSON(path, "common", "s", results); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var got FullScanResults
	_ = json.Unmarshal(raw, &got)
	if len(got.Negatives) != 120 {
		t.Fatalf("negatives = %d, want 120 (no truncation in file)", len(got.Negatives))
	}
}
