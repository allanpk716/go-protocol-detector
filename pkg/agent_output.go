package pkg

import (
	agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
)

// EmitScanResultEnvelope writes the final kind="scan-result" envelope.
func EmitScanResultEnvelope(w *agentsdk.Writer, data AgentReportData) error {
	return w.Success(data, "scan-result")
}

// EmitSelfDescribeEnvelope writes the kind="self-describe" capability envelope.
func EmitSelfDescribeEnvelope(w *agentsdk.Writer, data SelfDescribeData) error {
	return w.Success(data, "self-describe")
}

type SelfDescribeProtocol struct {
	Name        string `json:"name"`
	AuthSupport string `json:"auth_support"` // "none" | "optional"
}

type SelfDescribeFlag struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default string `json:"default"`
	Usage   string `json:"usage"`
}

type SelfDescribeData struct {
	Version    string                 `json:"version"`
	Protocols  []SelfDescribeProtocol `json:"protocols"`
	Flags      []SelfDescribeFlag     `json:"flags"`
	ExitCodes  map[string]string      `json:"exit_codes"`
	Limits     map[string]int         `json:"limits"`
	DataSchema string                 `json:"data_schema"`
}

// BuildSelfDescribeData assembles the machine-readable capability description.
func BuildSelfDescribeData(appVersion string) SelfDescribeData {
	return SelfDescribeData{
		Version: appVersion,
		Protocols: []SelfDescribeProtocol{
			{Name: "common", AuthSupport: "none"},
			{Name: "rdp", AuthSupport: "none"},
			{Name: "ssh", AuthSupport: "none"},
			{Name: "ftp", AuthSupport: "none"},
			{Name: "sftp", AuthSupport: "optional"},
			{Name: "telnet", AuthSupport: "none"},
			{Name: "vnc", AuthSupport: "none"},
			{Name: "rustdesk-hbbs", AuthSupport: "none"},
			{Name: "rustdesk-hbbr", AuthSupport: "none"},
			{Name: "rustdesk-hbbs-21116", AuthSupport: "none"},
		},
		Flags: []SelfDescribeFlag{
			{Name: "protocol", Type: "string", Default: "common", Usage: "protocol to scan: common|rdp|ssh|ftp|sftp|telnet|vnc|rustdesk-hbbs|rustdesk-hbbr|rustdesk-hbbs-21116"},
			{Name: "host", Type: "string", Default: "", Usage: "targets: 192.168.1.1,192.168.1.100-254,192.168.1.0/24"},
			{Name: "port", Type: "string", Default: "", Usage: "ports: 22,80,443,3380-3390"},
			{Name: "thread", Type: "int", Default: "10", Usage: "concurrency (max 1000)"},
			{Name: "timeout", Type: "int", Default: "1000", Usage: "connect timeout in ms"},
			{Name: "user", Type: "string", Default: "root", Usage: "sftp auth username (optional)"},
			{Name: "password", Type: "string", Default: "root", Usage: "sftp auth password (optional)"},
			{Name: "prikey", Type: "string", Default: "~/.ssh/id_rsa", Usage: "sftp auth private key path (optional)"},
			{Name: "format", Type: "string", Default: "auto", Usage: "output format: auto|human|jsonl; explicit value always wins; unrecognized values fall back to auto"},
			{Name: "agent", Type: "bool", Default: "false", Usage: "prefer JSONL output (applies only when --format is auto/unrecognized)"},
			{Name: "output-file", Type: "string", Default: "", Usage: "write full non-truncated results as JSON to this file"},
			{Name: "self-describe", Type: "bool", Default: "false", Usage: "print this capability description and exit"},
			{Name: "csv-output", Type: "string", Default: "", Usage: "human-mode CSV output path"},
			{Name: "no-progress", Type: "bool", Default: "false", Usage: "disable progress bars (human mode)"},
		},
		ExitCodes: map[string]string{
			"0": "scan completed (empty result is still success)",
			"1": "fatal crash / internal error",
			"2": "input invalid (unknown flag, invalid value, or host/port/protocol parse failure)",
			"3": "reserved, unused by this tool",
			"4": "network error: all targets unreachable (hits=0, errors=0, every negative unreachable)",
			"5": "reserved, unused by this tool",
		},
		Limits: map[string]int{
			"max_ips_per_range":          1000,
			"max_ports_total":            65536,
			"max_threads":                1000,
			"max_concurrent_connections": 500,
			"read_timeout_ms":            5000,
			"default_connect_timeout_ms": 1000,
		},
		DataSchema: `Final output is ONE JSONL envelope, kind="scan-result".
data fields:
  protocol        string   protocol that was scanned
  scan_id         string   unique scan identifier
  targets         {hosts:int, ports:int, total_checks:int}
  stats           {duration_ms:int, hits:int, negatives:int, errors:int}
  hits            [{host:string, port:int, response_time_ms:int, banner?:string}]
  negatives       {total:int, by_reason:{closed|timeout|protocol_mismatch|unreachable|unknown:int},
                   sample:[{host,port,reason}], sample_truncated:bool}
  errors          {total:int, sample:[{host,port,message}], sample_truncated:bool}
  output_file?    string   present only with --output-file; file holds ALL results
samples are JSON arrays ([] even when empty, never null), capped at 50 entries;
use --output-file for full data.
banner captured for ssh/ftp/vnc/sftp only; empty otherwise.`,
	}
}
