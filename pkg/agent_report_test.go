package pkg

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func mkResult(host string, port string, success bool, reason string, errMsg string) CheckResult {
	return CheckResult{
		Success:      success,
		ProtocolType: Common,
		Host:         host,
		Port:         port,
		Timestamp:    time.Now(),
		ResponseTime: 10 * time.Millisecond,
		ErrorMessage: errMsg,
		Banner:       "",
		Reason:       reason,
	}
}

func TestBuildAgentReportClassification(t *testing.T) {
	results := []CheckResult{
		mkResult("10.0.0.2", "22", true, "", ""),
		mkResult("10.0.0.1", "22", true, "", ""),
		mkResult("10.0.0.3", "22", false, "closed", "common check error"),
		mkResult("10.0.0.3", "80", false, "timeout", "common check error"),
		mkResult("10.0.0.4", "22", false, "", "Connection denied: pool exhausted"),
	}
	r := BuildAgentReport("common", "scan-1", results, 4, 2, 1234, DefaultSampleLimit, "")

	if r.Protocol != "common" || r.ScanID != "scan-1" {
		t.Fatalf("protocol/scanID = %q/%q", r.Protocol, r.ScanID)
	}
	if r.Targets.Hosts != 4 || r.Targets.Ports != 2 || r.Targets.TotalChecks != 5 {
		t.Fatalf("targets = %+v", r.Targets)
	}
	if r.Stats.Hits != 2 || r.Stats.Negatives != 2 || r.Stats.Errors != 1 || r.Stats.DurationMs != 1234 {
		t.Fatalf("stats = %+v", r.Stats)
	}
	if r.Hits[0].Host != "10.0.0.1" || r.Hits[1].Host != "10.0.0.2" {
		t.Fatalf("hits not sorted: %+v", r.Hits)
	}
	if r.Hits[0].Port != 22 || r.Hits[0].ResponseTimeMs != 10 {
		t.Fatalf("hit fields: %+v", r.Hits[0])
	}
	if r.Negatives.ByReason["closed"] != 1 || r.Negatives.ByReason["timeout"] != 1 {
		t.Fatalf("by_reason = %+v", r.Negatives.ByReason)
	}
	if len(r.Negatives.Sample) != 2 || r.Negatives.SampleTruncated {
		t.Fatalf("negatives sample: %+v", r.Negatives)
	}
	if len(r.Errors.Sample) != 1 || r.Errors.Sample[0].Message != "Connection denied: pool exhausted" {
		t.Fatalf("errors sample: %+v", r.Errors)
	}
	if r.OutputFile != "" {
		t.Fatalf("output_file should be omitted, got %q", r.OutputFile)
	}
}

// TestBuildAgentReportEmptySamplesSerializeAsArrays pins the schema contract:
// zero-entry samples must marshal as [], never null.
func TestBuildAgentReportEmptySamplesSerializeAsArrays(t *testing.T) {
	r := BuildAgentReport("common", "s", []CheckResult{mkResult("10.0.0.1", "22", true, "", "")}, 1, 1, 9, 50, "")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"sample":[]`) {
		t.Fatalf("samples must serialize as [], got %s", s)
	}
	if strings.Contains(s, `"sample":null`) {
		t.Fatalf("samples must never serialize as null, got %s", s)
	}
}

func TestBuildAgentReportTruncation(t *testing.T) {
	var results []CheckResult
	for i := 0; i < 80; i++ {
		results = append(results, mkResult(fmt.Sprintf("10.0.0.%d", i%250+1), "22", false, "closed", "x"))
	}
	r := BuildAgentReport("common", "scan-2", results, 80, 1, 5, 50, "/tmp/out.json")
	if len(r.Negatives.Sample) != 50 || !r.Negatives.SampleTruncated {
		t.Fatalf("sample len=%d truncated=%v, want 50/true", len(r.Negatives.Sample), r.Negatives.SampleTruncated)
	}
	if r.Negatives.Total != 80 {
		t.Fatalf("total = %d, want 80", r.Negatives.Total)
	}
	if r.OutputFile != "/tmp/out.json" {
		t.Fatalf("output_file = %q", r.OutputFile)
	}
}

func TestBuildAgentReportSampleLimitClamp(t *testing.T) {
	results := []CheckResult{mkResult("10.0.0.1", "22", false, "closed", "x")}
	r := BuildAgentReport("common", "s", results, 1, 1, 1, 0, "")
	if len(r.Negatives.Sample) != 1 {
		t.Fatalf("sampleLimit<=0 should fall back to default, got %d", len(r.Negatives.Sample))
	}
}

func TestBuildAgentReportBannerAndPortSorting(t *testing.T) {
	results := []CheckResult{
		{Success: true, Host: "10.0.0.1", Port: "8080", ResponseTime: time.Millisecond, Banner: "SSH-2.0-X"},
		{Success: true, Host: "10.0.0.1", Port: "22", ResponseTime: time.Millisecond},
	}
	r := BuildAgentReport("ssh", "s", results, 1, 2, 1, 50, "")
	if r.Hits[0].Port != 22 || r.Hits[1].Port != 8080 {
		t.Fatalf("ports not numerically sorted: %+v", r.Hits)
	}
	if r.Hits[0].Banner != "" || r.Hits[1].Banner != "SSH-2.0-X" {
		t.Fatalf("banner passthrough: %+v", r.Hits)
	}
}

func TestIsAllUnreachable(t *testing.T) {
	n := func(reason string, count int) []CheckResult {
		var out []CheckResult
		for i := 0; i < count; i++ {
			out = append(out, mkResult("10.0.0.1", "22", false, reason, "e"))
		}
		return out
	}
	if !IsAllUnreachable(BuildAgentReport("common", "s", n("unreachable", 3), 1, 1, 1, 50, "")) {
		t.Fatal("all-unreachable scan should be flagged")
	}
	if IsAllUnreachable(BuildAgentReport("common", "s", append(n("unreachable", 2), mkResult("h", "1", false, "closed", "e")), 1, 1, 1, 50, "")) {
		t.Fatal("mixed reasons must not be flagged")
	}
	if IsAllUnreachable(BuildAgentReport("common", "s", append(n("unreachable", 2), mkResult("h", "1", true, "", "")), 1, 1, 1, 50, "")) {
		t.Fatal("any hit must not be flagged")
	}
	if IsAllUnreachable(BuildAgentReport("common", "s", append(n("unreachable", 2), mkResult("h", "1", false, "", "Connection denied")), 1, 1, 1, 50, "")) {
		t.Fatal("any error must not be flagged")
	}
	if IsAllUnreachable(BuildAgentReport("common", "s", nil, 0, 0, 1, 50, "")) {
		t.Fatal("empty result is not all-unreachable")
	}
}
