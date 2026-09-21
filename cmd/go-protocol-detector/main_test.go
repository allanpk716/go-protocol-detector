package main

import (
	"errors"
	"net"
	"os"
	"testing"

	agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
)

// resolveFormat rule (single source of truth):
// 1. an explicit --format=human|jsonl ALWAYS wins;
// 2. otherwise --agent forces jsonl;
// 3. otherwise TTY detection (unrecognized --format values fall back here too).
func TestResolveFormat(t *testing.T) {
	cases := []struct {
		format, want string
		agent, tty   bool
	}{
		{"auto", "human", false, true},
		{"auto", "jsonl", false, false},
		{"human", "human", false, false},
		{"jsonl", "jsonl", false, true},
		{"garbage", "human", false, true}, // unrecognized falls back to auto behavior
		{"garbage", "jsonl", false, false},
		{"auto", "jsonl", true, true},  // --agent applies when format is auto
		{"human", "human", true, true}, // explicit --format beats --agent
		{"jsonl", "jsonl", true, true}, // both agree on jsonl
	}
	for _, c := range cases {
		if got := resolveFormat(c.format, c.agent, c.tty); got != c.want {
			t.Fatalf("resolveFormat(%q,%v,%v) = %q, want %q", c.format, c.agent, c.tty, got, c.want)
		}
	}
}

func TestStdoutIsTerminalUnderPipe(t *testing.T) {
	fi, err := os.Stdout.Stat()
	if err != nil {
		t.Skip("cannot stat stdout")
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		t.Skip("stdout is a terminal in this environment")
	}
	if stdoutIsTerminal() {
		t.Fatal("piped stdout must not be detected as terminal")
	}
}

func TestClassifyExitError(t *testing.T) {
	validation := scanErrors.NewValidationError("bad port", nil)
	code, errCode := classifyExitError(validation)
	if code != agentsdk.ExitInvalidParams || errCode != "INPUT_INVALID" {
		t.Fatalf("validation → %d/%q", code, errCode)
	}
	resource := scanErrors.NewResourceLimitError("too many ports", nil)
	code, errCode = classifyExitError(resource)
	if code != agentsdk.ExitInvalidParams || errCode != "INPUT_INVALID" {
		t.Fatalf("resource → %d/%q", code, errCode)
	}
	code, errCode = classifyExitError(&net.OpError{Op: "listen"})
	if code != agentsdk.ExitFatalError || errCode != "INTERNAL_ERROR" {
		t.Fatalf("unknown → %d/%q", code, errCode)
	}
	code, errCode = classifyExitError(errors.New("x"))
	if code != agentsdk.ExitFatalError || errCode != "INTERNAL_ERROR" {
		t.Fatalf("plain → %d/%q", code, errCode)
	}
}
