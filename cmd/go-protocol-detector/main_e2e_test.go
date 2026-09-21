package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var e2eBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "gpd-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}
	e2eBin = filepath.Join(tmp, "go-protocol-detector.exe")
	out, err := exec.Command("go", "build", "-o", e2eBin, ".").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s\n", out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

type e2eEnvelope struct {
	Version   string          `json:"version"`
	Tool      string          `json:"tool"`
	Type      string          `json:"type"`
	Kind      string          `json:"kind"`
	ErrorCode string          `json:"error_code,omitempty"`
	Data      json.RawMessage `json:"data"`
}

func runBinary(args ...string) (stdout string, exitCode int, err error) {
	cmd := exec.Command(e2eBin, args...)
	var sb strings.Builder
	cmd.Stdout = &sb
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return sb.String(), -1, runErr
		}
	}
	return sb.String(), code, nil
}

func firstJSONLEnvelope(t *testing.T, stdout string) e2eEnvelope {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 {
		t.Fatalf("no stdout output")
	}
	var env e2eEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatalf("first stdout line is not JSONL: %q (err %v)", lines[0], err)
	}
	return env
}

func startE2EListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func TestE2EAutoFormatIsJSONLWhenPiped(t *testing.T) {
	port := startE2EListener(t)
	stdout, code, err := runBinary("--protocol=common", "--host=127.0.0.1", "--port="+strconv.Itoa(port), "--timeout=3000")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	env := firstJSONLEnvelope(t, stdout)
	if env.Type != "result" || env.Kind != "scan-result" || env.Tool != "go-protocol-detector" {
		t.Fatalf("envelope = %+v", env)
	}
	var data struct {
		Stats struct {
			Hits int `json:"hits"`
		} `json:"stats"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if data.Stats.Hits != 1 || data.Protocol != "common" {
		t.Fatalf("data = %+v", data)
	}
}

func TestE2EForcedHumanFormat(t *testing.T) {
	port := startE2EListener(t)
	stdout, code, err := runBinary("--format=human", "--protocol=common", "--host=127.0.0.1", "--port="+strconv.Itoa(port), "--timeout=3000")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Scan Result") {
		t.Fatalf("human output missing result banner: %q", stdout)
	}
}

func TestE2EClosedPortIsNegativeNotError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port, _ := strconv.Atoi(strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:"))
	_ = ln.Close()
	time.Sleep(100 * time.Millisecond)

	stdout, code, err := runBinary("--format=jsonl", "--protocol=common", "--host=127.0.0.1", "--port="+strconv.Itoa(port), "--timeout=3000")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("empty-result scan must exit 0, got %d", code)
	}
	env := firstJSONLEnvelope(t, stdout)
	var data struct {
		Stats struct {
			Hits      int `json:"hits"`
			Negatives int `json:"negatives"`
			Errors    int `json:"errors"`
		} `json:"stats"`
		Negatives struct {
			ByReason map[string]int `json:"by_reason"`
		} `json:"negatives"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if data.Stats.Hits != 0 || data.Stats.Errors != 0 || data.Stats.Negatives < 1 {
		t.Fatalf("stats = %+v", data.Stats)
	}
	if data.Negatives.ByReason["closed"] < 1 {
		t.Fatalf("by_reason = %+v, want closed>=1", data.Negatives.ByReason)
	}
}

func TestE2EInvalidHostExits2(t *testing.T) {
	stdout, code, err := runBinary("--format=jsonl", "--protocol=common", "--host=not-an-ip", "--port=22", "--timeout=1000")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	env := firstJSONLEnvelope(t, stdout)
	if env.Type != "error" || env.ErrorCode != "INPUT_INVALID" {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestE2EInvalidProtocolExits2(t *testing.T) {
	_, code, err := runBinary("--format=jsonl", "--protocol=http", "--host=127.0.0.1", "--port=80", "--timeout=1000")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

// TestE2EUnknownFlagExits2 pins the OnUsageError contract: CLI parse failures
// in machine context produce one error envelope and exit 2, not stderr noise.
func TestE2EUnknownFlagExits2(t *testing.T) {
	stdout, code, err := runBinary("--format=jsonl", "--no-such-flag=1", "--host=127.0.0.1", "--port=22")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	env := firstJSONLEnvelope(t, stdout)
	if env.Type != "error" || env.ErrorCode != "INPUT_INVALID" {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestE2ESelfDescribe(t *testing.T) {
	stdout, code, err := runBinary("--self-describe", "--format=jsonl")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	env := firstJSONLEnvelope(t, stdout)
	if env.Kind != "self-describe" {
		t.Fatalf("kind = %q", env.Kind)
	}
	var data struct {
		Version   string `json:"version"`
		Protocols []struct {
			Name string `json:"name"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if data.Version == "" || len(data.Protocols) == 0 {
		t.Fatalf("data = %+v", data)
	}
}

func TestE2EOutputFile(t *testing.T) {
	port := startE2EListener(t)
	outPath := filepath.Join(t.TempDir(), "full.json")
	stdout, code, err := runBinary("--format=jsonl", "--output-file="+outPath,
		"--protocol=common", "--host=127.0.0.1", "--port="+strconv.Itoa(port), "--timeout=3000")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	env := firstJSONLEnvelope(t, stdout)
	var data struct {
		OutputFile string `json:"output_file"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if data.OutputFile != outPath {
		t.Fatalf("output_file = %q, want %q", data.OutputFile, outPath)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	var full struct {
		Hits []struct {
			Port int `json:"port"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("file json: %v", err)
	}
	if len(full.Hits) != 1 || full.Hits[0].Port != port {
		t.Fatalf("file hits = %+v", full.Hits)
	}
}
