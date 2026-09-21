package pkg

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
)

type envHead struct {
	Version   string          `json:"version"`
	Tool      string          `json:"tool"`
	Type      string          `json:"type"`
	Kind      string          `json:"kind"`
	ErrorCode string          `json:"error_code,omitempty"`
	Data      json.RawMessage `json:"data"`
}

func newTestWriter(buf *bytes.Buffer) *agentsdk.Writer {
	return agentsdk.NewWriter(buf, "go-protocol-detector")
}

func TestEmitScanResultEnvelope(t *testing.T) {
	var buf bytes.Buffer
	w := newTestWriter(&buf)
	report := BuildAgentReport("common", "s1", []CheckResult{{Success: true, Host: "10.0.0.1", Port: "80"}}, 1, 1, 9, 50, "")
	if err := EmitScanResultEnvelope(w, report); err != nil {
		t.Fatalf("emit: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if !strings.HasSuffix(line, "}") || strings.Count(line, "\n") != 0 {
		t.Fatalf("emission must be a single JSONL line, got %q", line)
	}
	var head envHead
	if err := json.Unmarshal([]byte(line), &head); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if head.Version != "1.0" || head.Tool != "go-protocol-detector" || head.Type != "result" || head.Kind != "scan-result" {
		t.Fatalf("envelope head = %+v", head)
	}
	var data AgentReportData
	if err := json.Unmarshal(head.Data, &data); err != nil {
		t.Fatalf("data unmarshal: %v", err)
	}
	if data.Stats.Hits != 1 {
		t.Fatalf("data = %+v", data)
	}
}

func TestBuildSelfDescribeData(t *testing.T) {
	sd := BuildSelfDescribeData("vtest")
	if sd.Version != "vtest" {
		t.Fatalf("version = %q", sd.Version)
	}
	if len(sd.Protocols) != 10 {
		t.Fatalf("protocols = %d, want 10", len(sd.Protocols))
	}
	sftpAuth := ""
	for _, p := range sd.Protocols {
		if p.Name == "sftp" {
			sftpAuth = p.AuthSupport
		}
	}
	if sftpAuth != "optional" {
		t.Fatalf("sftp auth_support = %q, want optional", sftpAuth)
	}
	for _, code := range []string{"0", "1", "2", "3", "4", "5"} {
		if _, ok := sd.ExitCodes[code]; !ok {
			t.Fatalf("exit code %s missing from self-describe", code)
		}
	}
	if sd.DataSchema == "" || !strings.Contains(sd.DataSchema, "scan-result") {
		t.Fatal("data_schema must be populated")
	}
	var buf bytes.Buffer
	w := newTestWriter(&buf)
	if err := EmitSelfDescribeEnvelope(w, sd); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var head envHead
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &head); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if head.Kind != "self-describe" {
		t.Fatalf("kind = %q", head.Kind)
	}
}
