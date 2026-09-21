# go-protocol-detector Agent Mode (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give go-protocol-detector a machine-native output contract (single JSONL result envelope, semantic exit codes, `--format` switch with TTY autodetect, `--self-describe`, `--output-file`, banner capture) while keeping human-mode behavior unchanged.

**Architecture:** Stay on `urfave/cli/v2`; use the `ai-agent-cli-rules` Go SDK's `Writer` directly for JSONL envelopes (its `App.Execute` is cobra-bound and NOT used). Detector layer gains a `CheckDetailed` path returning `CheckDetail{Banner, Reason}`; scan pipeline retains full `[]CheckResult`; a pure `BuildAgentReport` function assembles the envelope data with sample truncation. CLI-first per ADR-0001; TTY autodetect per ADR-0002.

**Tech Stack:** Go 1.24, `urfave/cli/v2`, `github.com/allanpk716/ai-agent-cli-rules/sdks/go` v0.2.0 (already in go.mod), stdlib only for new code.

**Spec:** `CONTEXT.md` (glossary: 命中/负结果/错误 trichotomy, negative-reason enum, 空结果成功), `docs/adr/0001-cli-jsonl-as-contract-mcp-later.md`, `docs/adr/0002-tty-autodetect-output-mode.md`. The data schema, exit-code table, and truncation rules are embedded verbatim in Global Constraints below.

## Global Constraints

- **Platform**: Windows is the primary dev OS; the Bash tool is Git Bash. Built binary is `./go-protocol-detector.exe` (`.exe` suffix required on Windows).
- **Human mode must not change behavior**: the default terminal experience (progress bars, final `====` result block, CSV output) stays byte-for-byte the same logic. Only agent-mode code paths are new. One documented exception: input-validation errors from `parseHost`/`parsePort` get typed as `ScannerError` (VALIDATION) for exit-code classification — their stderr text gains a `[VALIDATION]` prefix, nothing else.
- **No new Go dependencies.** SDK stays at v0.2.0.
- **Code comments in English**; docs: `AGENT_INSTRUCTION.md` in English, `README.md`/`CLAUDE.md` updates in English (matching existing file language).
- **Envelope protocol**: SDK `Envelope` v1.0. Final scan result → one `type=result, kind="scan-result"` envelope. Capability description → one `type=result, kind="self-describe"` envelope. Failures → `type=error` envelopes with `error_code` strings.
- **Exit codes**: `0` scan completed (empty result is still success); `2` INPUT_INVALID (host/port/protocol parse failure); `4` NETWORK_ERROR (all targets unreachable — conservative, only when hits==0 && errors==0 && every negative is `unreachable`); `1` FATAL_CRASH/INTERNAL_ERROR. `3` and `5` are reserved and unused. Use `agentsdk.ExitSuccess`/`ExitInvalidParams`/`ExitNetworkError`/`ExitFatalError` constants.
- **Negative reason enum** (exact strings): `closed`, `timeout`, `protocol_mismatch`, `unreachable`, `unknown`.
- **Sample truncation**: negatives and errors samples capped at `DefaultSampleLimit = 50` entries (constant, no flag). Full data goes to `--output-file`.
- **Classification rule** (from CONTEXT.md): `Success==true` → hit; `Success==false && Reason != ""` → negative (data); `Success==false && Reason == ""` → error (scan-cancellation, resource-denial, panic — actionable).
- **Banner**: sanitized printable-ASCII prefix of the raw response, max 128 bytes, min 4 chars or empty. Captured for ssh/ftp (via `commonCheckDetailed`), vnc (full 12-byte RFB version string), sftp (SSH banner from diagnostics). Not captured for rdp/rustdesk/common (binary or no read); telnet effectively never reaches 4 printable bytes — document as "no banner".
- **Every commit message ends with:**
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Run tests with `go test ./internal/... ./pkg/... ./cmd/...` from repo root. Tests must not require live services or `.env` (use `127.0.0.1` listeners on ephemeral ports).

---

### Task 1: Negative-reason classifier and banner sanitizer

**Files:**
- Create: `internal/utils/reason.go`
- Test: `internal/utils/reason_test.go`

**Interfaces:**
- Consumes: nothing new (stdlib only).
- Produces: `utils.ReasonClosed/ReasonTimeout/ReasonProtocolMismatch/ReasonUnreachable/ReasonUnknown` (string consts), `utils.ClassifyNetError(err error) string`, `utils.SanitizeBanner(b []byte) string`. Task 2, 6, and `internal/feature/vnc` depend on these exact names.

- [ ] **Step 1: Write the failing test**

Create `internal/utils/reason_test.go`:

```go
package utils

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func dialErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

func TestClassifyNetError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ReasonUnknown},
		{"refused", dialErr(syscall.ECONNREFUSED), ReasonClosed},
		{"host unreachable", dialErr(syscall.EHOSTUNREACH), ReasonUnreachable},
		{"net unreachable", dialErr(syscall.ENETUNREACH), ReasonUnreachable},
		{"eof", io.EOF, ReasonProtocolMismatch},
		{"unexpected eof", io.ErrUnexpectedEOF, ReasonProtocolMismatch},
		{"plain error", errors.New("boom"), ReasonUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyNetError(c.err); got != c.want {
				t.Fatalf("ClassifyNetError(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

func TestClassifyNetErrorTimeout(t *testing.T) {
	// net.DialTimeout timeout errors satisfy net.Error with Timeout()==true.
	// Fabricate one that is also wrapped, like real code paths produce.
	timeoutErr := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	if got := ClassifyNetError(errors.Join(errors.New("ctx: "), timeoutErr)); got != ReasonTimeout {
		t.Fatalf("wrapped deadline error classified as %q, want %q", got, ReasonTimeout)
	}
}

func TestSanitizeBanner(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"ssh banner line", []byte("SSH-2.0-OpenSSH_8.9\r\nSSH-2.0..."), "SSH-2.0-OpenSSH_8.9"},
		{"ftp banner", []byte("220 ProFTPD Server (ftp)\r\n"), "220 ProFTPD Server (ftp)"},
		{"binary stops at first non-printable", []byte{0x03, 0x00, 'S', 'S', 'H'}, ""},
		{"too short", []byte("22"), ""},
		{"exactly four chars", []byte("220 "), "220 "},
		{"cap at 128", append([]byte("220 "), make([]byte, 200)...), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// fix "cap at 128": 200 printable 'a's, not zero bytes
			in := c.in
			if c.name == "cap at 128" {
				in = append([]byte("220 "), bytesOf('a', 200)...)
			}
			if got := SanitizeBanner(in); got != c.want {
				t.Fatalf("SanitizeBanner(%q) = %q, want %q", in, got, c.want)
			}
		})
	}
}

func bytesOf(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

func TestSanitizeBannerLengthCap(t *testing.T) {
	long := bytesOf('x', 300)
	got := SanitizeBanner(long)
	if len(got) != 128 {
		t.Fatalf("banner length = %d, want 128", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/utils/ -run 'TestClassify|TestSanitize' -v`
Expected: FAIL — `undefined: ReasonClosed` (compile error).

- [ ] **Step 3: Write minimal implementation**

Create `internal/utils/reason.go`:

```go
package utils

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// Negative-result reasons. Fixed enum; see CONTEXT.md (负结果原因).
const (
	ReasonClosed           = "closed"
	ReasonTimeout          = "timeout"
	ReasonProtocolMismatch = "protocol_mismatch"
	ReasonUnreachable      = "unreachable"
	ReasonUnknown          = "unknown"
)

const (
	maxBannerLen = 128
	minBannerLen = 4
)

// ClassifyNetError maps a network-layer error to a negative-reason enum value.
// It is stage-agnostic: dial errors and read errors both flow through here.
func ClassifyNetError(err error) string {
	if err == nil {
		return ReasonUnknown
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			return ReasonClosed
		case syscall.EHOSTUNREACH, syscall.ENETUNREACH:
			return ReasonUnreachable
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonTimeout
	}
	// EOF at read stage: the TCP connection was established but the peer
	// closed it without speaking the expected protocol.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ReasonProtocolMismatch
	}
	return ReasonUnknown
}

// SanitizeBanner returns the printable-ASCII prefix of a raw response,
// stopping at the first CR/LF or non-printable byte, capped at 128 bytes.
// Few than 4 printable leading bytes yields "" (binary protocols).
func SanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == '\r' || c == '\n' {
			break
		}
		if c < 0x20 || c > 0x7E {
			break
		}
		sb.WriteByte(c)
		if sb.Len() >= maxBannerLen {
			break
		}
	}
	if sb.Len() < minBannerLen {
		return ""
	}
	return sb.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/utils/ -run 'TestClassify|TestSanitize' -v`
Expected: PASS (all subtests).

Note: `syscall.ECONNREFUSED`/`EHOSTUNREACH`/`ENETUNREACH` exist on both Windows (WSA values) and Unix, so the test compiles cross-platform.

- [ ] **Step 5: Commit**

```bash
git add internal/utils/reason.go internal/utils/reason_test.go
git commit -m "feat(reason): add negative-reason classifier and banner sanitizer

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Detector detailed checks (banner + reason) and pipeline wiring

**Files:**
- Modify: `pkg/detector.go` (add `CheckDetail`, `CheckDetailed`, per-protocol `*Detailed` methods; make `commonCheck` delegate)
- Modify: `pkg/scan_tools.go:554-562` (`CheckResult` gains `Banner`, `Reason` fields)
- Modify: `pkg/scan_core.go:41-72` (`performProtocolCheck` switches to `CheckDetailed`) and `pkg/scan_core.go:173` (worker fills new fields)
- Modify: `internal/feature/vnc/vnc.go` (read full 12-byte RFB version; add `CheckDetailed`)
- Modify: `internal/feature/sftp/sftp.go:96-150` (wrap raw net errors so classification can unwrap them)
- Test: `pkg/check_detailed_test.go` (new)

**Interfaces:**
- Consumes: `utils.ClassifyNetError`, `utils.SanitizeBanner`, `utils.Reason*` consts (Task 1).
- Produces:
  - `type CheckDetail struct { Banner string; Reason string }` (in `pkg`)
  - `func (d Detector) CheckDetailed(pt ProtocolType, host, port, user, password, privateKeyFullPath string) (CheckDetail, error)`
  - `CheckResult.Banner string`, `CheckResult.Reason string` (Task 3/4 consume)
  - `func (v VNCHelper) CheckDetailed() (banner string, reason string, err error)` (in `internal/feature/vnc`)

- [ ] **Step 1: Write the failing test**

Create `pkg/check_detailed_test.go`:

```go
package pkg

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// startFakeServer accepts one connection at a time and writes greeting on accept.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/ -run TestCheckDetailed -v`
Expected: FAIL — compile error `d.CheckDetailed undefined`.

- [ ] **Step 3: Implement the detailed detector layer**

**3a.** In `pkg/scan_tools.go`, extend `CheckResult` (currently at line 554):

```go
type CheckResult struct {
	Success      bool
	ProtocolType ProtocolType
	Host         string
	Port         string
	Timestamp    time.Time
	ResponseTime time.Duration
	ErrorMessage string
	Banner       string // sanitized raw-response prefix on success ("" when none)
	Reason       string // negative reason on failure ("" on success or scan-level error)
}
```

**3b.** In `pkg/detector.go`, add after the `Detector` constructor:

```go
// CheckDetail carries per-target extra info for agent mode.
// Banner: sanitized raw-response prefix of a hit (may be empty).
// Reason: negative reason of a failure ("closed|timeout|protocol_mismatch|unreachable|unknown").
type CheckDetail struct {
	Banner string
	Reason string
}

// CheckDetailed runs the protocol check for pt and returns extra detail.
// It is the agent-mode entry point; the plain XxxCheck methods stay for tests
// and backward compatibility.
func (d Detector) CheckDetailed(pt ProtocolType, host, port, user, password, privateKeyFullPath string) (CheckDetail, error) {
	switch pt {
	case RDP:
		return d.commonCheckDetailed(host, port, d.rdp.SenderPackage, d.rdp.ReceiverFeatures, custom_error.ErrRDPNotFound)
	case SSH:
		return d.commonCheckDetailed(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, custom_error.ErrSSHNotFound)
	case FTP:
		return d.commonCheckDetailed(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, custom_error.ErrFTPNotFound)
	case SFTP:
		return d.sftpCheckDetailed(host, port)
	case Telnet:
		return d.telnetCheckDetailed(host, port)
	case VNC:
		return d.vncCheckDetailed(host, port)
	case RustDeskHBBS:
		// HBBS uses the RegisterPk probe (see HBBSCheck comment)
		return d.commonCheckDetailed(host, port, d.rustdeskHBBS21116.SenderPackage, d.rustdeskHBBS21116.ReceiverFeatures, custom_error.ErrRustDeskHBBSNotFound)
	case RustDeskHBBR:
		return d.hbbrCheckDetailed(host, port)
	case RustDeskHBBS21116:
		return d.commonCheckDetailed(host, port, d.rustdeskHBBS21116.SenderPackage, d.rustdeskHBBS21116.ReceiverFeatures, custom_error.ErrRustDeskHBBS21116NotFound)
	default:
		return d.commonPortCheckDetailed(host, port)
	}
}
```

Replace the body of `commonCheck` (detector.go:159-202) with a delegation and add the detailed variant:

```go
func (d Detector) commonCheck(host string, port string,
	senderPackage []byte, recFeatures []common.ReceiverFeature, outErr error) error {
	_, err := d.commonCheckDetailed(host, port, senderPackage, recFeatures, outErr)
	return err
}

func (d Detector) commonCheckDetailed(host string, port string,
	senderPackage []byte, recFeatures []common.ReceiverFeature, outErr error) (CheckDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, outErr
	}
	defer conn.Close()

	if _, err = conn.Write(senderPackage); err != nil {
		return CheckDetail{Reason: utils.ReasonClosed}, outErr
	}
	lastFeature := recFeatures[len(recFeatures)-1]
	readBytesLen := lastFeature.StartIndex + len(lastFeature.FeatureBytes)

	// 添加网络读取安全限制
	if readBytesLen > MaxReadSize {
		return CheckDetail{Reason: utils.ReasonUnknown}, outErr
	}
	if readBytesLen <= 0 {
		return CheckDetail{Reason: utils.ReasonUnknown}, outErr
	}

	var readBuf = make([]byte, readBytesLen)

	// 设置读取超时，防止阻塞
	if err = conn.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		return CheckDetail{Reason: utils.ReasonUnknown}, outErr
	}

	// 使用io.ReadFull确保读取指定大小的数据或返回错误
	if _, err = io.ReadFull(conn, readBuf); err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, outErr
	}
	// according to the features
	for _, feature := range recFeatures {
		if bytes.Equal(readBuf[feature.StartIndex:feature.StartIndex+len(feature.FeatureBytes)], feature.FeatureBytes) == false {
			return CheckDetail{Reason: utils.ReasonProtocolMismatch}, outErr
		}
	}
	return CheckDetail{Banner: utils.SanitizeBanner(readBuf)}, nil
}

func (d Detector) telnetCheckDetailed(host, port string) (CheckDetail, error) {
	tel, err := telnet.NewTelnetHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrTelnetNotFound
	}
	n, err := tel.Check()
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrTelnetNotFound
	}
	if n <= 0 {
		return CheckDetail{Reason: utils.ReasonProtocolMismatch}, custom_error.ErrTelnetNotFound
	}
	return CheckDetail{}, nil
}

func (d Detector) vncCheckDetailed(host, port string) (CheckDetail, error) {
	v, err := vnc.NewVNCHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrVNCNotFound
	}
	banner, reason, err := v.CheckDetailed()
	if err != nil {
		return CheckDetail{Reason: reason}, custom_error.ErrVNCNotFound
	}
	return CheckDetail{Banner: banner}, nil
}

func (d Detector) sftpCheckDetailed(host, port string) (CheckDetail, error) {
	diag, err := sftp.NewSFTPHelper(host, port, d.timeOut).CheckWithDiagnostics()
	if err == nil {
		return CheckDetail{Banner: diag.SSHBanner}, nil
	}
	// TCP ok and a banner came back, but not a usable SSH/SFTP service
	if diag != nil && diag.TCPConnected && diag.SSHBanner != "" {
		return CheckDetail{Reason: utils.ReasonProtocolMismatch}, err
	}
	return CheckDetail{Reason: utils.ClassifyNetError(err)}, err
}

func (d Detector) hbbrCheckDetailed(host, port string) (CheckDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrRustDeskHBBRNotFound
	}
	defer conn.Close()
	if _, err = conn.Write(d.rustdeskHBBR.SenderPackage); err != nil {
		return CheckDetail{Reason: utils.ReasonClosed}, custom_error.ErrRustDeskHBBRNotFound
	}
	return CheckDetail{}, nil
}

func (d Detector) commonPortCheckDetailed(host, port string) (CheckDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrCommontPortCheckError
	}
	_ = conn.Close()
	return CheckDetail{}, nil
}
```

Add `"github.com/allanpk716/go-protocol-detector/internal/utils"` to detector.go imports.

**3c.** Rework `internal/feature/vnc/vnc.go` — replace `Check` with a delegating wrapper plus a detailed method that reads the full 12-byte RFB version string:

```go
func (v VNCHelper) Check() error {
	_, _, err := v.CheckDetailed()
	return err
}

// CheckDetailed reads the full 12-byte RFB version string (e.g. "RFB 003.008\n")
// and returns (banner, negativeReason, err).
func (v VNCHelper) CheckDetailed() (string, string, error) {
	if err := v.Conn.SetReadDeadline(time.Now().Add(v.timeout)); err != nil {
		return "", utils.ReasonUnknown, custom_error.ErrVNCNotFound
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(v.Conn, buf); err != nil {
		return "", utils.ClassifyNetError(err), custom_error.ErrVNCNotFound
	}
	if !bytes.HasPrefix(buf, []byte("RFB ")) {
		return "", utils.ReasonProtocolMismatch, custom_error.ErrVNCNotFound
	}
	return strings.TrimSpace(string(buf)), "", nil
}
```

Update vnc.go imports: add `"io"`, `"strings"`, `"github.com/allanpk716/go-protocol-detector/internal/utils"`; drop nothing. `bytes`, `net`, `time`, `custom_error`, `common` stay.

**3d.** In `internal/feature/sftp/sftp.go`, wrap the raw network errors at the two TCP/banner-read failure returns inside `checkSFTPProtocolWithDiagnostics` (lines ~103-120) so `ClassifyNetError` can unwrap them. Replace:

```go
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("TCP连接失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}
```

with:

```go
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("TCP连接失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, fmt.Errorf("%w: %v", custom_error.ErrSFTPNotFound, err)
	}
```

and the banner-read failure return:

```go
	banner, err := reader.ReadString('\n')
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("读取SSH Banner失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, fmt.Errorf("%w: %v", custom_error.ErrSFTPNotFound, err)
	}
```

(`errors.Is(err, ErrSFTPNotFound)` still holds for existing callers; the appended raw error enables classification.)

**3e.** Wire the pipeline in `pkg/scan_core.go`. Change `performProtocolCheck` (line 41) to:

```go
// performProtocolCheck 执行特定协议的检测
func (sc *scanCore) performProtocolCheck(deliveryInfo DeliveryInfo) (bool, string, CheckDetail) {
	detail, err := deliveryInfo.Detector.CheckDetailed(
		sc.protocol, deliveryInfo.Host, deliveryInfo.Port,
		deliveryInfo.User, deliveryInfo.Password, deliveryInfo.PrivateKeyFullPath)

	if err != nil {
		return false, err.Error(), detail
	}
	return true, "", detail
}
```

and the call site in `createGoroutinePoolWithCallback` (line 173):

```go
	checkResult.Success, checkResult.ErrorMessage, detail := sc.performProtocolCheck(deliveryInfo)
	checkResult.Banner = detail.Banner
	checkResult.Reason = detail.Reason
```

(`detail` needs no declaration — it is a new variable from the multi-return; make sure the line replaces `checkResult.Success, checkResult.ErrorMessage = sc.performProtocolCheck(deliveryInfo)`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/ -run TestCheckDetailed -v && go test ./internal/...`
Expected: all PASS. Also run `go build ./...` — must compile.

- [ ] **Step 5: Commit**

```bash
git add pkg/detector.go pkg/scan_tools.go pkg/scan_core.go pkg/check_detailed_test.go internal/feature/vnc/vnc.go internal/feature/sftp/sftp.go
git commit -m "feat(detector): detailed protocol checks exposing banner and negative reason

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Full-result retention, host/port counts, input-error typing

**Files:**
- Modify: `pkg/scan_tools.go` — `OutputInfo` gains `AllResults`; `startResultCollector` call sites init the slice; `parseHost`/`parsePort` plain errors become `errors.NewValidationError`; add `IsKnownProtocol`
- Modify: `pkg/scan_core.go:75-113` — collector appends every `CheckResult`
- Modify: `pkg/scan_context.go` — struct gains `HostsCount`, `PortsCount int`
- Test: `pkg/scan_retention_test.go` (new)

**Interfaces:**
- Consumes: `CheckResult.Banner/Reason` (Task 2).
- Produces: `OutputInfo.AllResults []CheckResult`; `ScanContext.HostsCount int`, `ScanContext.PortsCount int`; `func IsKnownProtocol(name string) bool`. Task 4/5/7 consume these.

- [ ] **Step 1: Write the failing test**

Create `pkg/scan_retention_test.go`:

```go
package pkg

import (
	"strconv"
	"testing"
	"time"
)

func TestScanWithOutputRetainsAllResults(t *testing.T) {
	port, stop := startFakeServer(t, "")
	defer stop()
	closed := closedPort(t)

	st := NewScanTools(4, 2*time.Second)
	out, ctx, err := st.ScanWithOutput(Common, InputInfo{
		Host: "127.0.0.1",
		Port: strconv.Itoa(port) + "," + strconv.Itoa(closed),
	}, false, "", false)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(out.AllResults) != 2 {
		t.Fatalf("AllResults len = %d, want 2", len(out.AllResults))
	}
	hits, closedCount := 0, 0
	for _, r := range out.AllResults {
		if r.Success {
			hits++
			if r.Reason != "" {
				t.Fatalf("hit has reason %q", r.Reason)
			}
		} else {
			if r.Reason != "closed" {
				t.Fatalf("closed-port result reason = %q, want closed", r.Reason)
			}
			closedCount++
		}
	}
	if hits != 1 || closedCount != 1 {
		t.Fatalf("hits=%d closed=%d, want 1/1", hits, closedCount)
	}
	if ctx.HostsCount != 1 || ctx.PortsCount != 2 {
		t.Fatalf("ctx counts = %d/%d, want 1/2", ctx.HostsCount, ctx.PortsCount)
	}
}

func TestIsKnownProtocol(t *testing.T) {
	for _, ok := range []string{"common", "rdp", "ssh", "ftp", "sftp", "telnet", "vnc", "rustdesk-hbbs", "rustdesk-hbbr", "rustdesk-hbbs-21116"} {
		if !IsKnownProtocol(ok) {
			t.Fatalf("%q should be known", ok)
		}
	}
	for _, bad := range []string{"", "http", "RDP"} {
		if IsKnownProtocol(bad) {
			t.Fatalf("%q should be unknown", bad)
		}
	}
}

func TestParseHostInvalidIsValidationError(t *testing.T) {
	st := NewScanTools(2, time.Second)
	_, err := st.parseHost("not-an-ip")
	if err == nil {
		t.Fatal("expected error")
	}
	var se *scanErrors.ScannerError
	if !errorsAs(err, &se) || se.Type != scanErrors.ErrorTypeValidation {
		t.Fatalf("error should be VALIDATION-typed, got %#v", err)
	}
}
```

Add these two tiny helpers at the bottom of the same test file (keeps the import list small):

```go
import (
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
)

func errorsAs(err error, target interface{}) bool {
	return errorsAsStd(err, target) // see below — use std errors.As via alias
}
```

Simpler: drop the helper indirection and import `"errors"` (stdlib) plus `scanErrors` directly, calling `errors.As(err, &se)` in the test. Final imports of the test file:

```go
import (
	"errors"
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
	"strconv"
	"testing"
	"time"
)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/ -run 'TestScanWithOutputRetainsAllResults|TestIsKnownProtocol|TestParseHostInvalid' -v`
Expected: FAIL — `out.AllResults undefined`, `IsKnownProtocol undefined`, and the validation-type assertion fails.

- [ ] **Step 3: Implement**

**3a.** `pkg/scan_tools.go` — extend `OutputInfo` (line 572):

```go
type OutputInfo struct {
	ProtocolType     ProtocolType
	SuccessMapString map[string][]string
	FailedMapString  map[string][]string
	AllResults       []CheckResult // full per-target results for agent mode
}
```

**3b.** `pkg/scan_core.go` — in `startResultCollector`, append every result under the existing mutex. Inside the `for revCheckResult := range checkResultChan` loop, as the first statement after `resultMapMutex.Lock()`:

```go
			outputInfo.AllResults = append(outputInfo.AllResults, revCheckResult)
```

**3c.** `pkg/scan_context.go` — add fields to the `ScanContext` struct (after `TotalTargets` at line ~25):

```go
	HostsCount int // number of unique hosts targeted
	PortsCount int // number of ports targeted
```

In `pkg/scan_tools.go` `ScanWithOutput`, right after `scanContext.SetTargets(allTargets)` (line 220), add:

```go
	scanContext.HostsCount = totalIPs
	scanContext.PortsCount = len(ports)
```

(`totalIPs` is computed at lines 177-185; `ports` is parsed at line 171 — both are in scope.)

**3d.** Type input errors as validation. In `pkg/scan_tools.go` `parseHost` (lines 338-432), replace every `fmt.Errorf(...)` return with `errors.NewValidationError(<same format/args>, nil)`. The affected returns: empty input, ParseCIDR error, host Split error, ParseIP error, 4-part split error, both Atoi errors, start/end range bounds checks, range size cap, octet overflow. In `parsePort`, likewise replace the remaining `fmt.Errorf` returns (the two `Port Split Error` and `Port Atoi Error` cases). The `errors.NewValidationError` / `errors.NewResourceLimitError` returns already present stay unchanged.

**3e.** Add `IsKnownProtocol` next to `String2ProtocolType` (line 620):

```go
// IsKnownProtocol reports whether name is a recognized protocol identifier.
func IsKnownProtocol(name string) bool {
	switch name {
	case "rdp", "ssh", "ftp", "sftp", "telnet", "vnc", "common",
		"rustdesk-hbbs", "rustdesk-hbbr", "rustdesk-hbbs-21116":
		return true
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/ -run 'TestScanWithOutputRetainsAllResults|TestIsKnownProtocol|TestParseHostInvalid' -v && go test ./pkg/`
Expected: new tests PASS; existing suite still PASS (port/host validation tests may assert error text — if any existing test asserts the old `fmt.Errorf` text exactly, update that assertion to accept the `[VALIDATION]` prefix and note it in the commit).

- [ ] **Step 5: Commit**

```bash
git add pkg/scan_tools.go pkg/scan_core.go pkg/scan_context.go pkg/scan_retention_test.go
git commit -m "feat(scan): retain full CheckResult list, host/port counts, typed input errors

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Agent report builder

**Files:**
- Create: `pkg/agent_report.go`
- Test: `pkg/agent_report_test.go`

**Interfaces:**
- Consumes: `CheckResult` (with Banner/Reason), `utils.Reason*` consts.
- Produces: types `AgentReportData`, `AgentTargets`, `AgentStats`, `AgentHit`, `AgentNegative`, `AgentError`, `AgentNegatives`, `AgentErrors`; `const DefaultSampleLimit = 50`; `func BuildAgentReport(protocol string, scanID string, results []CheckResult, hostsCount int, portsCount int, durationMs int64, sampleLimit int, outputFile string) AgentReportData`; `func IsAllUnreachable(r AgentReportData) bool`. Tasks 5/6/7 consume.

- [ ] **Step 1: Write the failing test**

Create `pkg/agent_report_test.go`:

```go
package pkg

import (
	"fmt"
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
	// sorted by host: 10.0.0.1 before 10.0.0.2
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/ -run 'TestBuildAgentReport|TestIsAllUnreachable' -v`
Expected: FAIL — compile error `BuildAgentReport undefined`.

- [ ] **Step 3: Write the implementation**

Create `pkg/agent_report.go`:

```go
package pkg

import (
	"encoding/json"
	"sort"
	"strconv"
)

// DefaultSampleLimit caps negatives/errors samples in the agent envelope.
// Full data is available via --output-file.
const DefaultSampleLimit = 50

// AgentReportData is the `data` payload of the kind="scan-result" envelope.
// Schema is part of the agent contract — see AGENT_INSTRUCTION.md.
type AgentReportData struct {
	Protocol   string          `json:"protocol"`
	ScanID     string          `json:"scan_id"`
	Targets    AgentTargets    `json:"targets"`
	Stats      AgentStats      `json:"stats"`
	Hits       []AgentHit      `json:"hits"`
	Negatives  AgentNegatives  `json:"negatives"`
	Errors     AgentErrors     `json:"errors"`
	OutputFile string          `json:"output_file,omitempty"`
}

type AgentTargets struct {
	Hosts       int `json:"hosts"`
	Ports       int `json:"ports"`
	TotalChecks int `json:"total_checks"`
}

type AgentStats struct {
	DurationMs int64 `json:"duration_ms"`
	Hits       int   `json:"hits"`
	Negatives  int   `json:"negatives"`
	Errors     int   `json:"errors"`
}

type AgentHit struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	ResponseTimeMs int64  `json:"response_time_ms"`
	Banner         string `json:"banner,omitempty"`
}

type AgentNegative struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Reason string `json:"reason"`
}

type AgentError struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Message string `json:"message"`
}

type AgentNegatives struct {
	Total           int             `json:"total"`
	ByReason        map[string]int  `json:"by_reason"`
	Sample          []AgentNegative `json:"sample"`
	SampleTruncated bool            `json:"sample_truncated"`
}

type AgentErrors struct {
	Total           int           `json:"total"`
	Sample          []AgentError  `json:"sample"`
	SampleTruncated bool          `json:"sample_truncated"`
}

// BuildAgentReport assembles the machine report from raw scan results.
// Pure function: no I/O, deterministic ordering (host, then numeric port).
func BuildAgentReport(protocol string, scanID string, results []CheckResult,
	hostsCount int, portsCount int, durationMs int64, sampleLimit int, outputFile string) AgentReportData {

	if sampleLimit <= 0 {
		sampleLimit = DefaultSampleLimit
	}

	sorted := make([]CheckResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Host != sorted[j].Host {
			return sorted[i].Host < sorted[j].Host
		}
		pi, _ := strconv.Atoi(sorted[i].Port)
		pj, _ := strconv.Atoi(sorted[j].Port)
		return pi < pj
	})

	report := AgentReportData{
		Protocol: protocol,
		ScanID:   scanID,
		Targets:  AgentTargets{Hosts: hostsCount, Ports: portsCount, TotalChecks: len(results)},
		Stats:    AgentStats{DurationMs: durationMs},
		Hits:     []AgentHit{},
		Negatives: AgentNegatives{
			ByReason: map[string]int{},
			Sample:   []AgentNegative{},
		},
		Errors:     AgentErrors{Sample: []AgentError{}},
		OutputFile: outputFile,
	}

	var negSample []AgentNegative
	var errSample []AgentError

	for _, r := range sorted {
		port, _ := strconv.Atoi(r.Port)
		switch {
		case r.Success:
			report.Stats.Hits++
			report.Hits = append(report.Hits, AgentHit{
				Host:           r.Host,
				Port:           port,
				ResponseTimeMs: r.ResponseTime.Milliseconds(),
				Banner:         r.Banner,
			})
		case r.Reason != "":
			// negative result — data, not an error
			report.Stats.Negatives++
			report.Negatives.ByReason[r.Reason]++
			if len(negSample) < sampleLimit {
				negSample = append(negSample, AgentNegative{Host: r.Host, Port: port, Reason: r.Reason})
			}
		default:
			// scan-level failure — actionable error
			report.Stats.Errors++
			if len(errSample) < sampleLimit {
				errSample = append(errSample, AgentError{Host: r.Host, Port: port, Message: r.ErrorMessage})
			}
		}
	}

	report.Negatives.Total = report.Stats.Negatives
	report.Negatives.Sample = negSample
	report.Negatives.SampleTruncated = len(negSample) < report.Stats.Negatives
	report.Errors.Total = report.Stats.Errors
	report.Errors.Sample = errSample
	report.Errors.SampleTruncated = len(errSample) < report.Stats.Errors

	return report
}

// IsAllUnreachable reports the conservative NETWORK_ERROR condition:
// zero hits, zero errors, and every negative is unreachable.
func IsAllUnreachable(r AgentReportData) bool {
	return r.Stats.Hits == 0 &&
		r.Stats.Errors == 0 &&
		r.Stats.Negatives > 0 &&
		r.Negatives.ByReason["unreachable"] == r.Stats.Negatives
}

// ensure json import is used when only these types are compiled in isolation
var _ = json.Marshal
```

(Remove the `var _ = json.Marshal` line and the `encoding/json` import if the linter flags it as unnecessary once the file compiles — they exist only to keep the import list stable during incremental edits. Final state: no json import needed in this file.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/ -run 'TestBuildAgentReport|TestIsAllUnreachable' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agent_report.go pkg/agent_report_test.go
git commit -m "feat(agent): machine report builder with truncation semantics

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Full-results JSON file writer

**Files:**
- Create: `pkg/full_results.go`
- Test: `pkg/full_results_test.go`

**Interfaces:**
- Consumes: `CheckResult`, `AgentHit/AgentNegative/AgentError` (Task 4).
- Produces: `type FullScanResults struct`; `func WriteFullResultsJSON(path string, protocol string, scanID string, results []CheckResult) error`. Task 7 consumes.

- [ ] **Step 1: Write the failing test**

Create `pkg/full_results_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/ -run TestWriteFullResultsJSON -v`
Expected: FAIL — `WriteFullResultsJSON undefined`.

- [ ] **Step 3: Write the implementation**

Create `pkg/full_results.go`:

```go
package pkg

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

// FullScanResults is the complete, non-truncated result set written by
// --output-file. The agent envelope carries only the file path.
type FullScanResults struct {
	Protocol  string          `json:"protocol"`
	ScanID    string          `json:"scan_id"`
	Timestamp string          `json:"timestamp"`
	Hits      []AgentHit      `json:"hits"`
	Negatives []AgentNegative `json:"negatives"`
	Errors    []AgentError    `json:"errors"`
}

// WriteFullResultsJSON writes every result (all negatives and errors included,
// no sample truncation) as indented JSON. Deterministic order: host, then port.
func WriteFullResultsJSON(path string, protocol string, scanID string, results []CheckResult) error {
	sorted := make([]CheckResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Host != sorted[j].Host {
			return sorted[i].Host < sorted[j].Host
		}
		pi, _ := strconv.Atoi(sorted[i].Port)
		pj, _ := strconv.Atoi(sorted[j].Port)
		return pi < pj
	})

	full := FullScanResults{
		Protocol:  protocol,
		ScanID:    scanID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hits:      []AgentHit{},
		Negatives: []AgentNegative{},
		Errors:    []AgentError{},
	}
	for _, r := range sorted {
		port, _ := strconv.Atoi(r.Port)
		switch {
		case r.Success:
			full.Hits = append(full.Hits, AgentHit{
				Host: r.Host, Port: port,
				ResponseTimeMs: r.ResponseTime.Milliseconds(),
				Banner:         r.Banner,
			})
		case r.Reason != "":
			full.Negatives = append(full.Negatives, AgentNegative{Host: r.Host, Port: port, Reason: r.Reason})
		default:
			full.Errors = append(full.Errors, AgentError{Host: r.Host, Port: port, Message: r.ErrorMessage})
		}
	}

	data, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal full results: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write full results file: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/ -run TestWriteFullResultsJSON -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/full_results.go pkg/full_results_test.go
git commit -m "feat(agent): full-results JSON file writer

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Envelope emission and self-describe

**Files:**
- Create: `pkg/agent_output.go`
- Test: `pkg/agent_output_test.go`

**Interfaces:**
- Consumes: `agentsdk.Writer` (`agentsdk.NewWriter(io.Writer, string)`, `(*Writer).Success(data interface{}, kind ...string) error`), `AgentReportData` (Task 4).
- Produces: `func EmitScanResultEnvelope(w *agentsdk.Writer, data AgentReportData) error`; `type SelfDescribeData` + sub-types; `func BuildSelfDescribeData(appVersion string) SelfDescribeData`; `func EmitSelfDescribeEnvelope(w *agentsdk.Writer, data SelfDescribeData) error`. Task 7 consumes.

- [ ] **Step 1: Write the failing test**

Create `pkg/agent_output_test.go`:

```go
package pkg

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type envHead struct {
	Version string          `json:"version"`
	Tool    string          `json:"tool"`
	Type    string          `json:"type"`
	Kind    string          `json:"kind"`
	Data    json.RawMessage `json:"data"`
}

func TestEmitScanResultEnvelope(t *testing.T) {
	var buf bytes.Buffer
	w := agentsdkNewWriter(&buf)
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
	wantCodes := map[string]bool{"0": true, "1": true, "2": true, "4": true, "3": true, "5": true}
	for code := range wantCodes {
		if _, ok := sd.ExitCodes[code]; !ok {
			t.Fatalf("exit code %s missing from self-describe", code)
		}
	}
	if sd.DataSchema == "" || !strings.Contains(sd.DataSchema, "scan-result") {
		t.Fatal("data_schema must be populated")
	}
	var buf bytes.Buffer
	w := agentsdkNewWriter(&buf)
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
```

Add the tiny wrapper at the bottom of the test file (single import point for the SDK):

```go
import agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"

func agentsdkNewWriter(buf *bytes.Buffer) *agentsdk.Writer {
	return agentsdk.NewWriter(buf, "go-protocol-detector")
}
```

(Merge that import into the test file's import block rather than a second import statement.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/ -run 'TestEmitScanResultEnvelope|TestBuildSelfDescribeData' -v`
Expected: FAIL — `EmitScanResultEnvelope undefined`.

- [ ] **Step 3: Write the implementation**

Create `pkg/agent_output.go`:

```go
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
	Version    string                  `json:"version"`
	Protocols  []SelfDescribeProtocol  `json:"protocols"`
	Flags      []SelfDescribeFlag      `json:"flags"`
	ExitCodes  map[string]string       `json:"exit_codes"`
	Limits     map[string]int          `json:"limits"`
	DataSchema string                  `json:"data_schema"`
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
			{Name: "format", Type: "string", Default: "auto", Usage: "output format: auto|human|jsonl (auto = human on terminal, jsonl otherwise)"},
			{Name: "agent", Type: "bool", Default: "false", Usage: "force JSONL output (alias for --format=jsonl)"},
			{Name: "output-file", Type: "string", Default: "", Usage: "write full non-truncated results as JSON to this file"},
			{Name: "self-describe", Type: "bool", Default: "false", Usage: "print this capability description and exit"},
			{Name: "csv-output", Type: "string", Default: "", Usage: "human-mode CSV output path"},
			{Name: "no-progress", Type: "bool", Default: "false", Usage: "disable progress bars (human mode)"},
		},
		ExitCodes: map[string]string{
			"0": "scan completed (empty result is still success)",
			"1": "fatal crash / internal error",
			"2": "input invalid (host/port/protocol parse failure)",
			"3": "reserved, unused by this tool",
			"4": "network error: all targets unreachable (hits=0, errors=0, every negative unreachable)",
			"5": "reserved, unused by this tool",
		},
		Limits: map[string]int{
			"max_ips_per_range":         1000,
			"max_ports_total":           65536,
			"max_threads":               1000,
			"max_concurrent_connections": 500,
			"read_timeout_ms":           5000,
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
samples are capped at 50 entries; use --output-file for full data.
banner captured for ssh/ftp/vnc/sftp only; empty otherwise.`,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/ -run 'TestEmitScanResultEnvelope|TestBuildSelfDescribeData' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agent_output.go pkg/agent_output_test.go
git commit -m "feat(agent): JSONL envelope emission and self-describe data

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: CLI rework — flags, format resolution, exit codes, agent path

**Files:**
- Modify: `cmd/go-protocol-detector/main.go` (full rework of flags and Action; human path preserved verbatim)
- Test: `cmd/go-protocol-detector/main_test.go` (new — unit tests for pure helpers)

**Interfaces:**
- Consumes: everything from Tasks 3-6 (`AllResults`, `HostsCount/PortsCount`, `BuildAgentReport`, `WriteFullResultsJSON`, `EmitScanResultEnvelope`, `BuildSelfDescribeData`, `EmitSelfDescribeEnvelope`, `IsKnownProtocol`, `IsAllUnreachable`, `DefaultSampleLimit`), `agentsdk.NewWriter/Exit*` consts, `scanErrors.ScannerError` with `ErrorTypeValidation/ErrorTypeResourceLimit`.
- Produces: CLI flags `--format` (auto|human|jsonl, default auto), `--agent` (bool, forces jsonl), `--output-file`, `--self-describe`; helpers `resolveFormat(format string, agentFlag bool, stdoutIsTTY bool) string`, `stdoutIsTerminal() bool`, `classifyExitError(err error) (int, string)`. Task 9 (E2E) exercises the binary.

- [ ] **Step 1: Write the failing test**

Create `cmd/go-protocol-detector/main_test.go`:

```go
package main

import (
	"errors"
	"net"
	"os"
	"testing"

	agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
)

func TestResolveFormat(t *testing.T) {
	cases := []struct {
		format, want string
		agent, tty   bool
	}{
		{"auto", "human", false, true},
		{"auto", "jsonl", false, false},
		{"human", "human", false, false},
		{"jsonl", "jsonl", false, true},
		{"jsonl", "jsonl", false, false},
		{"garbage", "human", false, true},  // unknown falls back to auto behavior
		{"garbage", "jsonl", false, false},
		{"auto", "jsonl", true, true},       // --agent forces jsonl even on tty
		{"human", "jsonl", true, true},      // --agent beats --format=human
	}
	for _, c := range cases {
		if got := resolveFormat(c.format, c.agent, c.tty); got != c.want {
			t.Fatalf("resolveFormat(%q,%v,%v) = %q, want %q", c.format, c.agent, c.tty, got, c.want)
		}
	}
}

func TestStdoutIsTerminalUnderPipe(t *testing.T) {
	// In `go test`, stdout is not guaranteed a terminal; on a pipe it must be false.
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
```

Note: verify `scanErrors.NewResourceLimitError(message string, cause error)` matches the actual signature in `internal/errors/errors.go` before writing (grep `func NewResourceLimitError`). If the signature differs, adapt the call in this test accordingly.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/... -v`
Expected: FAIL — `resolveFormat undefined` (compile error).

- [ ] **Step 3: Rewrite main.go**

Replace the entire content of `cmd/go-protocol-detector/main.go` with:

```go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
	"github.com/allanpk716/go-protocol-detector/internal/errors" // imported as `errors` (shadowing stdlib by name in this file — see scanErrors below
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
	"github.com/allanpk716/go-protocol-detector/pkg"
	"github.com/urfave/cli/v2"
)

var AppVersion = "unknown"

func main() {
	app := &cli.App{
		Name:        "go-protocol-detector",
		Usage:       "use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389",
		Description: "Multi-protocol scan tool",
		Version:     AppVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "protocol",
				Usage: "select only one protocol: common | ftp | rdp | rustdesk-hbbs | rustdesk-hbbr | rustdesk-hbbs-21116 | sftp | ssh | telnet | vnc",
				Value: "common",
			},
			&cli.StringFlag{
				Name:  "host",
				Usage: "support 3 diffs types: 192.168.1.1,192.168.1.100-254,192.168.1.0/24",
			},
			&cli.StringFlag{
				Name:  "port",
				Usage: "support like: 22,80,443,3380-3390",
			},
			&cli.IntFlag{
				Name:  "thread",
				Usage: "10",
				Value: 10,
			},
			&cli.IntFlag{
				Name:  "timeout",
				Usage: "1000 ms",
				Value: 1000,
			},
			&cli.StringFlag{
				Name:  "user",
				Usage: "if you scan sftp, need give a UserName: root",
				Value: "root",
			},
			&cli.StringFlag{
				Name:  "password",
				Usage: "if you scan sftp, need give a Password: root",
				Value: "root",
			},
			&cli.StringFlag{
				Name:  "prikey",
				Usage: "if you scan sftp, need give a pri key Full Path( user name or this priKeyFPath only chose one): ~/.ssh/id_rsa",
				Value: "~/.ssh/id_rsa",
			},
			&cli.StringFlag{
				Name:  "csv-output",
				Usage: "output scan results to CSV file (specify file path to enable CSV output)",
				Value: "",
			},
			&cli.BoolFlag{
				Name:    "no-progress",
				Usage:   "disable progress bar output",
				Aliases: []string{"np"},
				Value:   false,
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "output format: auto | human | jsonl (auto = human on terminal, jsonl when piped/agent)",
				Value: "auto",
			},
			&cli.BoolFlag{
				Name:  "agent",
				Usage: "force JSONL output (alias for --format=jsonl)",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "output-file",
				Usage: "write full scan results (all negatives included, no truncation) as JSON to this file",
				Value: "",
			},
			&cli.BoolFlag{
				Name:  "self-describe",
				Usage: "print machine-readable capability description (JSONL when not human) and exit",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {
			// 检查是否没有任何参数被传递，如果没有则显示帮助信息
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			format := resolveFormat(c.String("format"), c.Bool("agent"), stdoutIsTerminal())

			// --self-describe: capability introspection, works in both formats
			if c.Bool("self-describe") {
				data := pkg.BuildSelfDescribeData(AppVersion)
				if format == "jsonl" {
					w := agentsdk.NewWriter(os.Stdout, "go-protocol-detector")
					if err := pkg.EmitSelfDescribeEnvelope(w, data); err != nil {
						return cli.Exit(err.Error(), agentsdk.ExitFatalError)
					}
				} else {
					b, err := json.MarshalIndent(data, "", "  ")
					if err != nil {
						return cli.Exit(err.Error(), agentsdk.ExitFatalError)
					}
					fmt.Println(string(b))
				}
				return nil
			}

			if format == "jsonl" {
				return runAgentScan(c)
			}

			// Human mode (default on terminal) — original logic, zero changes
			protocol := c.String("protocol")
			host := c.String("host")
			port := c.String("port")
			thread := c.Int("thread")
			timeOut := c.Int("timeout")
			user := c.String("user")
			password := c.String("password")
			priKeyFullPath := c.String("prikey")
			csvOutput := c.String("csv-output")
			noProgress := c.Bool("no-progress")

			nowProtocol := pkg.String2ProtocolType(protocol)
			scanTools := pkg.NewScanTools(thread, time.Duration(timeOut)*time.Millisecond)

			var outputInfo *pkg.OutputInfo
			var err error

			// Use ScanWithOutput for all scans (it supports progress bars)
			// showProgressStep = false to disable per-port logging (too verbose)
			// enableProgress = true to show progress bars (unless --no-progress flag is set)
			outputInfo, _, err = scanTools.ScanWithOutput(nowProtocol, pkg.InputInfo{
				Host:               host,
				Port:               port,
				User:               user,
				Password:           password,
				PrivateKeyFullPath: priKeyFullPath,
			}, false, csvOutput, !noProgress)

			if err != nil {
				return err
			}

			log.Println("==========================================================")
			info := protocol + " Scan Result: \n"

			// Show console output
			if outputInfo != nil {
				for s2, i := range outputInfo.SuccessMapString {
					info += s2 + ":" + strings.Join(i, ",") + "\n"
				}
			}

			if csvOutput != "" {
				info += fmt.Sprintf("CSV results saved to: %s\n", csvOutput)
			}

			fmt.Print(info)
			log.Println("==========================================================")
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		if ec, ok := err.(cli.ExitCoder); ok {
			if ec.Error() != "" {
				fmt.Fprintln(os.Stderr, ec.Error())
			}
			os.Exit(ec.ExitCode())
		}
		log.Fatal(err)
	}
}

// resolveFormat decides the output mode. --agent forces jsonl; explicit
// --format wins; "auto" (and unknown values) fall back to TTY detection.
func resolveFormat(format string, agentFlag bool, stdoutIsTTY bool) string {
	if agentFlag {
		return "jsonl"
	}
	switch format {
	case "human", "jsonl":
		return format
	default:
		if stdoutIsTTY {
			return "human"
		}
		return "jsonl"
	}
}

// stdoutIsTerminal reports whether stdout is a character device.
// Note: redirecting to NUL on Windows also looks like a char device — acceptable.
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// classifyExitError maps an error to (exit code, envelope error_code).
// Validation and resource-limit errors are input problems (exit 2); anything
// else is internal (exit 1).
func classifyExitError(err error) (int, string) {
	var se *scanErrors.ScannerError
	if errors.As(err, &se) &&
		(se.Type == scanErrors.ErrorTypeValidation || se.Type == scanErrors.ErrorTypeResourceLimit) {
		return agentsdk.ExitInvalidParams, "INPUT_INVALID"
	}
	return agentsdk.ExitFatalError, "INTERNAL_ERROR"
}

// runAgentScan executes the scan in agent (JSONL) mode: stderr silent unless
// AGENT_DEBUG=1, single result envelope, semantic exit codes.
func runAgentScan(c *cli.Context) error {
	w := agentsdk.NewWriter(os.Stdout, "go-protocol-detector")

	if os.Getenv("AGENT_DEBUG") == "" {
		log.SetOutput(io.Discard)
	}

	defer func() {
		if r := recover(); r != nil {
			stackBuf := make([]byte, 4096)
			n := runtime.Stack(stackBuf, false)
			_ = w.ErrorWithCode("FATAL_CRASH", fmt.Sprintf("panic: %v\nStack:\n%s", r, stackBuf[:n]))
			os.Exit(agentsdk.ExitFatalError)
		}
	}()

	protocolName := c.String("protocol")
	if !pkg.IsKnownProtocol(protocolName) {
		_ = w.ErrorWithCode("INPUT_INVALID", fmt.Sprintf("unknown protocol: %q", protocolName))
		return cli.Exit("", agentsdk.ExitInvalidParams)
	}
	host := c.String("host")
	port := c.String("port")
	if host == "" || port == "" {
		_ = w.ErrorWithCode("INPUT_INVALID", "both --host and --port are required")
		return cli.Exit("", agentsdk.ExitInvalidParams)
	}

	nowProtocol := pkg.String2ProtocolType(protocolName)
	scanTools := pkg.NewScanTools(c.Int("thread"), time.Duration(c.Int("timeout"))*time.Millisecond)

	outputInfo, scanContext, err := scanTools.ScanWithOutput(nowProtocol, pkg.InputInfo{
		Host:               host,
		Port:               port,
		User:               c.String("user"),
		Password:           c.String("password"),
		PrivateKeyFullPath: c.String("prikey"),
	}, false, "", false)
	if err != nil {
		code, errCode := classifyExitError(err)
		_ = w.ErrorWithCode(errCode, err.Error())
		return cli.Exit("", code)
	}

	outputFile := c.String("output-file")
	report := pkg.BuildAgentReport(
		nowProtocol.String(),
		scanContext.ScanID,
		outputInfo.AllResults,
		scanContext.HostsCount,
		scanContext.PortsCount,
		scanContext.GetElapsedDuration().Milliseconds(),
		pkg.DefaultSampleLimit,
		outputFile,
	)

	if outputFile != "" {
		if err := pkg.WriteFullResultsJSON(outputFile, nowProtocol.String(), scanContext.ScanID, outputInfo.AllResults); err != nil {
			_ = w.ErrorWithCode("INTERNAL_ERROR", fmt.Sprintf("failed to write output file: %v", err))
			return cli.Exit("", agentsdk.ExitFatalError)
		}
	}

	if err := pkg.EmitScanResultEnvelope(w, report); err != nil {
		return cli.Exit(err.Error(), agentsdk.ExitFatalError)
	}

	// Conservative NETWORK_ERROR: scan completed but nothing was reachable at all
	if pkg.IsAllUnreachable(report) {
		return cli.Exit("", agentsdk.ExitNetworkError)
	}
	return nil
}
```

**Import fix (important):** the import block above deliberately contains a duplicate — you cannot import the same package twice under two names including its own name. Use ONLY this import for the internal errors package:

```go
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
```

and import stdlib `"errors"` for `errors.As`. Final import list: `encoding/json`, `errors` (stdlib), `fmt`, `io`, `log`, `os`, `runtime`, `strings`, `time`, `agentsdk`, `scanErrors`, `pkg`, `cli`. Delete the line importing internal/errors without alias.

- [ ] **Step 4: Run tests and build**

Run: `go test ./cmd/... -v && go build ./... && go vet ./...`
Expected: tests PASS, build and vet clean. Delete `pkg/sdk_dependency.go` (the blank-import placeholder is now superseded by the real SDK usage in `pkg/agent_output.go`):

```bash
git rm pkg/sdk_dependency.go
```

- [ ] **Step 5: Commit**

```bash
git add cmd/go-protocol-detector/main.go cmd/go-protocol-detector/main_test.go
git commit -m "feat(cli): --format/--agent/--output-file/--self-describe with semantic exit codes

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Documentation — AGENT_INSTRUCTION.md, README, CLAUDE.md

**Files:**
- Create: `AGENT_INSTRUCTION.md` (repo root, English)
- Modify: `README.md` (add "Using with AI agents" section after "How to use")
- Modify: `CLAUDE.md` (update flag documentation in "Running the Application")

**Interfaces:**
- Consumes: the final contract from Tasks 4-7 (schema, flags, exit codes).
- Produces: documentation only.

- [ ] **Step 1: Write AGENT_INSTRUCTION.md**

```markdown
# AGENT_INSTRUCTION.md — go-protocol-detector for AI agents

Multi-protocol port scanner and protocol identifier (RDP, SSH, FTP, SFTP,
Telnet, VNC, RustDesk, generic TCP). Human-oriented docs live in README.md;
this file is the machine-facing contract.

## Quick start

```bash
# One-shot scan; when your stdout is not a terminal you get JSONL automatically.
go-protocol-detector --protocol=ssh --host=192.168.1.0/24 --port=22

# Force the machine format explicitly (recommended for determinism):
go-protocol-detector --format=jsonl --protocol=common --host=10.0.0.1-254 --port=22,80,443

# Ask the tool what it can do before using it:
go-protocol-detector --self-describe --format=jsonl
```

## Output contract (JSONL)

On completion the tool writes exactly ONE JSONL line to stdout:

```json
{"version":"1.0","tool":"go-protocol-detector","type":"result","kind":"scan-result",
 "timestamp":"...","data":{ ...report... }}
```

`data` fields:

| field | type | meaning |
|---|---|---|
| `protocol` | string | protocol that was scanned |
| `scan_id` | string | unique scan identifier |
| `targets` | object | `{hosts, ports, total_checks}` |
| `stats` | object | `{duration_ms, hits, negatives, errors}` |
| `hits` | array | `[{host, port, response_time_ms, banner?}]` — port open AND protocol matched |
| `negatives` | object | `{total, by_reason, sample, sample_truncated}` — normal scan data, NOT errors |
| `errors` | object | `{total, sample, sample_truncated}` — scan-level failures worth acting on |
| `output_file` | string? | present only with `--output-file`; the file contains ALL results |

Negative reasons (fixed enum): `closed` (connection refused), `timeout`,
`protocol_mismatch` (TCP open, wrong protocol), `unreachable` (network layer),
`unknown`.

`samples` are capped at 50 entries. For complete data pass `--output-file=<path>`
and read the JSON file — do NOT rescan to recover truncated entries.

`banner` is captured for ssh / ftp / vnc / sftp only (e.g. `SSH-2.0-OpenSSH_8.9`,
`RFB 003.008`); absent otherwise.

## Exit codes

| code | meaning |
|---|---|
| 0 | scan completed — empty result is still success; check `stats.hits` |
| 1 | fatal crash / internal error (see error envelope) |
| 2 | input invalid (host/port/protocol parse failure) |
| 4 | network error: every target unreachable (hits=0, errors=0, all negatives `unreachable`) |
| 3, 5 | reserved, unused |

## Errors

Failures emit `{"type":"error","error_code":"INPUT_INVALID"|"INTERNAL_ERROR"|"FATAL_CRASH","message":"..."}`
and the matching non-zero exit code. stderr is silent unless `AGENT_DEBUG=1`.

## Concurrency & limits

Single protocol per invocation (scan multiple protocols by invoking once each).
Limits: 1000 IPs per range, 65536 ports total, 1000 threads (auto-clamped),
500 concurrent connections, 5s read timeout, 1s default connect timeout.
Pass `--thread`/`--timeout` to tune.

## Trace correlation

Set `AGENT_TRACE_ID` in the environment; its value is copied into every
envelope's `trace_id` field.
```

- [ ] **Step 2: Add README section**

In `README.md`, after the "How to use" examples (after the `--no-progress` example block around line 108), insert:

```markdown
## Using with AI agents

When stdout is not a terminal (piped, redirected, or called by an agent), the
tool emits a single-line JSONL result envelope instead of human output.
Force it explicitly with `--format=jsonl` (or `--agent`). Semantic exit codes
(0/2/4/1) and a machine-readable capability dump (`--self-describe`) are
included. Full non-truncated results can be written with `--output-file`.

See [AGENT_INSTRUCTION.md](./AGENT_INSTRUCTION.md) for the complete contract.
```

- [ ] **Step 3: Update CLAUDE.md**

In `CLAUDE.md`, in the "Running the Application" section, append after the existing examples:

```markdown
### Agent / machine output
```bash
# JSONL output is automatic when stdout is not a terminal; force it with:
go run cmd/go-protocol-detector/main.go --format=jsonl --protocol=ssh --host=192.168.1.1-254 --port=22
# Machine-readable capability description:
go run cmd/go-protocol-detector/main.go --self-describe --format=jsonl
# Full results to file (envelope carries only the path):
go run cmd/go-protocol-detector/main.go --format=jsonl --output-file=full.json --protocol=common --host=10.0.0.1-254 --port=22,80
```
```

- [ ] **Step 4: Verify docs render correctly**

Run: `head -40 AGENT_INSTRUCTION.md && grep -n "AGENT" README.md`
Expected: file present, README links to it.

- [ ] **Step 5: Commit**

```bash
git add AGENT_INSTRUCTION.md README.md CLAUDE.md
git commit -m "docs: agent-facing AGENT_INSTRUCTION.md and human doc updates

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: End-to-end tests and full verification

**Files:**
- Test: `cmd/go-protocol-detector/main_e2e_test.go` (new)

**Interfaces:**
- Consumes: the built binary (built by TestMain via `go build`).
- Produces: verification evidence; no production code.

- [ ] **Step 1: Write the E2E tests**

Create `cmd/go-protocol-detector/main_e2e_test.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
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
	cmd.Stderr = ioDiscard()
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
	// grab a port and release it — dialing it gets refused
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
		Version  string `json:"version"`
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
```

Add `ioDiscard` helper at the bottom of the file:

```go
func ioDiscard() io.Writer { return io.Discard }
```

with `"io"` in the import block (or inline `io.Discard` directly in `runBinary` and drop the helper — prefer the direct form).

- [ ] **Step 2: Run E2E tests**

Run: `go test ./cmd/... -v`
Expected: all unit + E2E tests PASS. If `TestE2EClosedPortIsNegativeNotError` flakes because the released port gets reused, retry once; if it persists, bind a listener on a *second* ephemeral port to keep the first one occupied as a known-closed sibling (dial a port adjacent to a held one is NOT reliable — prefer the listen/release approach and accept the tiny race window, or run with `-count=1`).

- [ ] **Step 3: Full verification sweep**

Run each and confirm clean output:

```bash
go build -o go-protocol-detector.exe ./cmd/go-protocol-detector
go vet ./...
go test ./internal/... ./pkg/... ./cmd/...
```

Expected: build succeeds, vet clean, all tests PASS.

Then a smoke run against a real listener in Git Bash:

```bash
# terminal-independent check: piped invocation yields one JSONL line and exit 0
go run cmd/go-protocol-detector/main.go --format=jsonl --protocol=common --host=127.0.0.1 --port=$((RANDOM%20000+20000)) --timeout=1000 | head -1
echo "exit=$?"
```

Expected: a single JSON line starting `{"version":"1.0","tool":"go-protocol-detector","type":"result"...` (hits will be 0 for a random closed port — that is a valid empty-success run) and `exit=0`. Note: `$?` after a pipe reports `head`'s status in some shells; if you need the tool's code, run without the pipe and inspect with `echo $?` directly.

- [ ] **Step 4: Commit**

```bash
git add cmd/go-protocol-detector/main_e2e_test.go
git commit -m "test(e2e): end-to-end agent-mode coverage

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (completed during planning)

1. **Spec coverage** — the 7 phase-1 items map to tasks: output contract → Tasks 2/3/4/6; `--format`+TTY autodetect+`--agent` alias → Task 7; semantic exit codes → Task 7 (+validation typing in Task 3); `--self-describe` → Tasks 6/7; `--output-file` → Tasks 5/7; banner field → Task 2; dual docs → Task 8. Phase-2 parking lot (multi-protocol, `--stream`, `--resume`, MCP wrapper, other meta-commands) intentionally absent. ✔
2. **Placeholder scan** — no TBD/TODO/"add appropriate" steps; every code step carries full code. ✔
3. **Type consistency** — `CheckDetail{Banner,Reason}`, `CheckResult.Banner/Reason`, `OutputInfo.AllResults`, `ScanContext.HostsCount/PortsCount`, `BuildAgentReport(protocol, scanID, results, hostsCount, portsCount, durationMs, sampleLimit, outputFile)`, `WriteFullResultsJSON(path, protocol, scanID, results)`, `EmitScanResultEnvelope(w, data)`, `BuildSelfDescribeData(appVersion)`, `resolveFormat(format, agentFlag, stdoutIsTTY)`, `classifyExitError(err) (int, string)` all used identically across tasks. ✔
