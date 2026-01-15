# RustDesk Protocol Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add RustDesk HBBS (ports 21115, 21116) and HBBR (port 21117) TCP protocol detection to go-protocol-detector using protobuf packet matching.

**Architecture:** Follow existing packet-based detection pattern (RDP/SSH/FTP). Create protocol helpers in `internal/feature/rustdesk/`, integrate into Detector struct, add ProtocolType enum values, update CLI with separate `rustdesk-hbbs` and `rustdesk-hbbr` options.

**Tech Stack:** Go 1.x, Protocol Buffers (protobuf), TCP sockets, existing go-protocol-detector architecture

---

## Task 1: Create RustDesk HBBS Protocol Helper

**Files:**
- Create: `internal/feature/rustdesk/hbbs.go`
- Reference: `internal/feature/ssh/ssh.go`

**Step 1: Write the test**

Create test file: `internal/feature/rustdesk/hbbs_test.go`

```go
package rustdesk

import (
	"testing"
)

func TestNewHBBSHelper(t *testing.T) {
	helper := NewHBBSHelper()
	if helper == nil {
		t.Fatal("NewHBBSHelper returned nil")
	}
	if helper.GetVersion() == "" {
		t.Error("Version should not be empty")
	}
}

func TestHBBSHelperSenderPackage(t *testing.T) {
	helper := NewHBBSHelper()
	pkg := helper.SenderPackage
	if len(pkg) == 0 {
		t.Error("SenderPackage should not be empty")
	}
	// Should start with 4-byte length prefix (big endian)
	// Expected: 0x00 0x00 0x00 0x0A (10 bytes for TestNatRequest message)
	expectedPrefix := []byte{0x00, 0x00, 0x00, 0x0A}
	if len(pkg) < 4 {
		t.Fatalf("Package too short: %d bytes", len(pkg))
	}
	if pkg[0] != expectedPrefix[0] || pkg[1] != expectedPrefix[1] ||
	   pkg[2] != expectedPrefix[2] || pkg[3] != expectedPrefix[3] {
		t.Errorf("Length prefix mismatch: got %x, want %x", pkg[0:4], expectedPrefix)
	}
}

func TestHBBSHelperReceiverFeatures(t *testing.T) {
	helper := NewHBBSHelper()
	features := helper.ReceiverFeatures
	if len(features) == 0 {
		t.Error("ReceiverFeatures should not be empty")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/feature/rustdesk && go test -v`
Expected: FAIL with "undefined: NewHBBSHelper"

**Step 3: Write minimal implementation**

Create: `internal/feature/rustdesk/hbbs.go`

```go
package rustdesk

import (
	"encoding/binary"
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

// HBBSHelper implements detection for RustDesk HBBS (rendezvous server)
// Ports: 21115 (NAT test), 21116 (TCP hole punching)
type HBBSHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
	version          string
}

// NewHBBSHelper creates a new HBBS protocol detection helper
func NewHBBSHelper() *HBBSHelper {
	// Build TestNatRequest protobuf message for port 21115 detection
	// Message format: 4-byte length prefix + protobuf data
	// TestNatRequest: field 1 (serial) = 0
	innerMsg := []byte{0x08, 0x00} // protobuf: tag 0x08, value 0

	// Wrap in RendezvousMessage: field 20 (TestNatRequest)
	// Tag: 0xA2 (field 20 << 3 | wire_type 2)
	outerMsg := []byte{0xA2, 0x02} // tag + length
	outerMsg = append(outerMsg, innerMsg...)

	// Add 4-byte length prefix (big endian)
	result := make([]byte, 4+len(outerMsg))
	binary.BigEndian.PutUint32(result[:4], uint32(len(outerMsg)))
	copy(result[4:], outerMsg...)

	hbbs := &HBBSHelper{
		SenderPackage: result,
		ReceiverFeatures: []common.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte{0x00, 0x00, 0x00}, // Response starts with length
			},
		},
		version: "v0.1",
	}
	return hbbs
}

// GetVersion returns the helper version
func (h HBBSHelper) GetVersion() string {
	return h.version
}
```

**Step 4: Run test to verify it passes**

Run: `cd internal/feature/rustdesk && go test -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/feature/rustdesk/
git commit -m "feat(rustdesk): add HBBS protocol helper with TestNatRequest"
```

---

## Task 2: Create RustDesk HBBR Protocol Helper

**Files:**
- Create: `internal/feature/rustdesk/hbbr.go`
- Modify: `internal/feature/rustdesk/hbbr_test.go`

**Step 1: Write the test**

Create: `internal/feature/rustdesk/hbbr_test.go`

```go
package rustdesk

import (
	"testing"
)

func TestNewHBBRHelper(t *testing.T) {
	helper := NewHBBRHelper()
	if helper == nil {
		t.Fatal("NewHBBRHelper returned nil")
	}
	if helper.GetVersion() == "" {
		t.Error("Version should not be empty")
	}
}

func TestHBBRHelperSenderPackage(t *testing.T) {
	helper := NewHBBRHelper()
	pkg := helper.SenderPackage
	// HBBR uses connection-based detection (like Common), no packet needed
	if len(pkg) != 0 {
		t.Error("HBBR SenderPackage should be empty for connection-based detection")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/feature/rustdesk && go test -v -run TestHBBR`
Expected: FAIL with "undefined: NewHBBRHelper"

**Step 3: Write minimal implementation**

Create: `internal/feature/rustdesk/hbbr.go`

```go
package rustdesk

// HBBRHelper implements detection for RustDesk HBBR (relay server)
// Port: 21117
// Uses connection-based detection (server accepts connections)
type HBBRHelper struct {
	version string
}

// NewHBBRHelper creates a new HBBR protocol detection helper
func NewHBBRHelper() *HBBRHelper {
	hbbr := &HBBRHelper{
		version: "v0.1",
	}
	return hbbr
}

// GetVersion returns the helper version
func (h HBBRHelper) GetVersion() string {
	return h.version
}
```

**Step 4: Run test to verify it passes**

Run: `cd internal/feature/rustdesk && go test -v -run TestHBBR`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/feature/rustdesk/hbbr.go internal/feature/rustdesk/hbbr_test.go
git commit -m "feat(rustdesk): add HBBR protocol helper for relay detection"
```

---

## Task 3: Add RustDesk Detection Methods to Detector

**Files:**
- Modify: `pkg/detector.go`
- Test: Test with live server 116.62.8.4

**Step 1: Write the integration test**

Create: `pkg/detector_rustdesk_test.go`

```go
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
```

**Step 2: Run test to verify it fails**

Run: `cd pkg && go test -v -run TestDetector_HBBS`
Expected: FAIL with "undefined: d.HBBSCheck"

**Step 3: Implement detection methods**

Add to `pkg/detector.go` (after line 13, add imports; after line 29, add helpers; after line 86, add methods):

```go
// Add imports after line 13:
	"github.com/allanpk716/go-protocol-detector/internal/feature/rustdesk"

// Add helpers to Detector struct after line 22:
type Detector struct {
	rdp     *rdp.RDPHelper
	ssh     *ssh.SSHHelper
	ftp     *ftp.FTPHelper
	rustdeskHBBS *rustdesk.HBBSHelper
	timeOut time.Duration
}

// Initialize in NewDetector after line 29:
func NewDetector(timeOut time.Duration) *Detector {
	d := Detector{
		rdp:     rdp.NewRDPHelper(),
		ssh:     ssh.NewSSHHelper(),
		ftp:     ftp.NewFTPHelper(),
		rustdeskHBBS: rustdesk.NewHBBSHelper(),
		timeOut: timeOut,
	}
	return &d
}

// Add methods after CommonPortCheck (after line 86):
func (d Detector) HBBSCheck(host, port string) error {
	return d.commonCheck(host, port, d.rustdeskHBBS.SenderPackage, d.rustdeskHBBS.ReceiverFeatures, custom_error.ErrRustDeskHBBSNotFound)
}

func (d Detector) HBBRCheck(host, port string) error {
	// HBBR uses connection-based detection (similar to Common)
	return d.CommonPortCheck(host, port)
}
```

**Step 4: Run test to verify it passes**

Run: `cd pkg && go test -v -run TestDetector_RustDesk`
Expected: PASS (may show logs if server unavailable)

**Step 5: Commit**

```bash
git add pkg/detector.go pkg/detector_rustdesk_test.go
git commit -m "feat(detector): add HBBSCheck and HBBRCheck methods"
```

---

## Task 4: Add RustDesk Protocol Types

**Files:**
- Modify: `pkg/scan_tools.go` (line ~1004)
- Test: Verify protocol string conversion

**Step 1: Write test for protocol types**

Create: `pkg/protocol_rustdesk_test.go`

```go
package pkg

import (
	"testing"
)

func TestProtocolType_RustDesk(t *testing.T) {
	tests := []struct {
		name     string
		proto    ProtocolType
		expected string
	}{
		{"RustDeskHBBS", RustDeskHBBS, "rustdesk-hbbs"},
		{"RustDeskHBBR", RustDeskHBBR, "rustdesk-hbbr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.proto.String(); got != tt.expected {
				t.Errorf("ProtocolType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestString2ProtocolType_RustDesk(t *testing.T) {
	tests := []struct {
		input    string
		expected ProtocolType
	}{
		{"rustdesk-hbbs", RustDeskHBBS},
		{"rustdesk-hbbr", RustDeskHBBR},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := String2ProtocolType(tt.input); got != tt.expected {
				t.Errorf("String2ProtocolType(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd pkg && go test -v -run TestProtocolType_RustDesk`
Expected: FAIL with "undefined: RustDeskHBBS"

**Step 3: Add protocol type constants**

Modify `pkg/scan_tools.go` at line ~1006:

```go
const (
	RDP ProtocolType = iota + 1
	SSH
	FTP
	SFTP
	Telnet
	VNC
	Common
	RustDeskHBBS  // Add after Common
	RustDeskHBBR  // Add after RustDeskHBBS
)
```

**Step 4: Update String() method**

Modify `pkg/scan_tools.go` at line ~1016 (add cases before default):

```go
func (p ProtocolType) String() string {
	switch p {
	case RDP:
		return "rdp"
	case SSH:
		return "ssh"
	case FTP:
		return "ftp"
	case SFTP:
		return "sftp"
	case Telnet:
		return "telnet"
	case VNC:
		return "vnc"
	case Common:
		return "common"
	case RustDeskHBBS:
		return "rustdesk-hbbs"
	case RustDeskHBBR:
		return "rustdesk-hbbr"
	default:
		return "unknown"
	}
}
```

**Step 5: Update String2ProtocolType() function**

Modify `pkg/scan_tools.go` at line ~1037 (add cases before default):

```go
func String2ProtocolType(input string) ProtocolType {
	switch input {
	case "rdp":
		return RDP
	case "ssh":
		return SSH
	case "ftp":
		return FTP
	case "sftp":
		return SFTP
	case "telnet":
		return Telnet
	case "vnc":
		return VNC
	case "common":
		return Common
	case "rustdesk-hbbs":
		return RustDeskHBBS
	case "rustdesk-hbbr":
		return RustDeskHBBR
	default:
		return Common
	}
}
```

**Step 6: Run test to verify it passes**

Run: `cd pkg && go test -v -run TestProtocolType_RustDesk`
Expected: PASS

**Step 7: Commit**

```bash
git add pkg/scan_tools.go pkg/protocol_rustdesk_test.go
git commit -m "feat(protocol): add RustDeskHBBS and RustDeskHBBR protocol types"
```

---

## Task 5: Add Protocol Detection Switch Cases

**Files:**
- Modify: `pkg/scan_tools.go` (line ~151 in first switch, line ~468 in second switch)
- Test: Integration test with actual scanning

**Step 1: Write integration test**

Create: `pkg/scan_rustdesk_test.go`

```go
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
	_, err := scan.Scan(RustDeskHBBS, input, false)
	if err != nil {
		t.Logf("RustDesk HBBS scan error: %v", err)
	}
}

func TestScanTools_RustDeskHBBRScan(t *testing.T) {
	scan := NewScanTools(1, 3*time.Second)
	input := InputInfo{
		Host: "116.62.8.4",
		Port: "21117",
	}
	_, err := scan.Scan(RustDeskHBBR, input, false)
	if err != nil {
		t.Logf("RustDesk HBBR scan error: %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd pkg && go test -v -run TestScanTools_RustDesk`
Expected: FAIL or warning about unhandled protocol type

**Step 3: Add first switch case (in Scan method)**

Modify `pkg/scan_tools.go` at line ~189 (before default case):

```go
		case RustDeskHBBS:
			if err := deliveryInfo.Detector.HBBSCheck(deliveryInfo.Host, deliveryInfo.Port); err == nil {
				checkResult.Success = true
			} else {
				checkResult.ErrorMessage = err.Error()
			}
		case RustDeskHBBR:
			if err := deliveryInfo.Detector.HBBRCheck(deliveryInfo.Host, deliveryInfo.Port); err == nil {
				checkResult.Success = true
			} else {
				checkResult.ErrorMessage = err.Error()
			}
		default:
			// 默认就当常规的端口来检测
```

**Step 4: Add second switch case (in ScanWithOutput method)**

Find the second switch at line ~468 and add before default case:

```go
		case RustDeskHBBS:
			if err := deliveryInfo.Detector.HBBSCheck(deliveryInfo.Host, deliveryInfo.Port); err == nil {
				checkResult.Success = true
			} else {
				checkResult.ErrorMessage = err.Error()
			}
		case RustDeskHBBR:
			if err := deliveryInfo.Detector.HBBRCheck(deliveryInfo.Host, deliveryInfo.Port); err == nil {
				checkResult.Success = true
			} else {
				checkResult.ErrorMessage = err.Error()
			}
		default:
			// 默认就当常规的端口来检测
```

**Step 5: Run test to verify it passes**

Run: `cd pkg && go test -v -run TestScanTools_RustDesk`
Expected: PASS (may show logs if server unavailable)

**Step 6: Commit**

```bash
git add pkg/scan_tools.go pkg/scan_rustdesk_test.go
git commit -m "feat(scan): add RustDesk protocol detection to scan switch"
```

---

## Task 6: Add Error Definitions

**Files:**
- Modify: `internal/custom_error/CustomError.go`
- Test: Verify error messages

**Step 1: Write test**

Create: `internal/custom_error/rustdesk_error_test.go`

```go
package custom_error

import (
	"errors"
	"testing"
)

func TestRustDeskErrors(t *testing.T) {
	if !errors.Is(ErrRustDeskHBBSNotFound, ErrRustDeskHBBSNotFound) {
		t.Error("ErrRustDeskHBBSNotFound should match itself")
	}
	if !errors.Is(ErrRustDeskHBBRNotFound, ErrRustDeskHBBRNotFound) {
		t.Error("ErrRustDeskHBBRNotFound should match itself")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/custom_error && go test -v -run TestRustDesk`
Expected: FAIL with "undefined: ErrRustDeskHBBSNotFound"

**Step 3: Add error definitions**

Add to `internal/custom_error/CustomError.go` (after existing errors):

```go
var ErrRustDeskHBBSNotFound = errors.New("rustdesk hbbs service not found")
var ErrRustDeskHBBRNotFound = errors.New("rustdesk hbbr service not found")
```

**Step 4: Run test to verify it passes**

Run: `cd internal/custom_error && go test -v -run TestRustDesk`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/custom_error/CustomError.go internal/custom_error/rustdesk_error_test.go
git commit -m "feat(errors): add RustDesk error definitions"
```

---

## Task 7: Update CLI with RustDesk Protocol Options

**Files:**
- Modify: `cmd/go-protocol-detector/main.go`
- Test: Manual CLI testing

**Step 1: Update protocol flag usage**

Modify `cmd/go-protocol-detector/main.go` at line ~38:

```go
			&cli.StringFlag{
				Name:        "protocol",
				Usage:       "select only one protocol: rdp | ssh | ftp | sftp | telnet | vnc | common | rustdesk-hbbs | rustdesk-hbbr",
				Value:       "common",
				Destination: &protocol,
			},
```

**Step 2: Test CLI help**

Run: `go run cmd/go-protocol-detector/main.go --help`
Expected: Should show rustdesk-hbbs and rustdesk-hbbr in protocol list

**Step 3: Test HBBS detection**

Run: `go run cmd/go-protocol-detector/main.go --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21115 --timeout=3000`
Expected: Should scan and report results

**Step 4: Test HBBR detection**

Run: `go run cmd/go-protocol-detector/main.go --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117 --timeout=3000`
Expected: Should scan and report results

**Step 5: Test multi-port scan**

Run: `go run cmd/go-protocol-detector/main.go --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21115,21116 --timeout=3000`
Expected: Should scan both HBBS ports

**Step 6: Commit**

```bash
git add cmd/go-protocol-detector/main.go
git commit -m "feat(cli): add rustdesk-hbbs and rustdesk-hbbr to protocol options"
```

---

## Task 8: End-to-End Testing and Documentation

**Files:**
- Update: `CLAUDE.md` (if needed)
- Create: `internal/feature/rustdesk/README.md`

**Step 1: Run full build test**

Run: `go build -o go-protocol-detector.exe ./cmd/go-protocol-detector`
Expected: Build succeeds without errors

**Step 2: Test against live server**

Run tests against 116.62.8.4:

```bash
# Test HBBS port 21115
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21115 --timeout=3000

# Test HBBS port 21116
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21116 --timeout=3000

# Test HBBR port 21117
./go-protocol-detector --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117 --timeout=3000

# Test all RustDesk ports
./go-protocol-detector --protocol=rustdesk-hbbs,rustdesk-hbbr --host=116.62.8.4 --port=21115-21117 --timeout=3000
```

Expected: All commands complete successfully

**Step 3: Create RustDesk feature documentation**

Create: `internal/feature/rustdesk/README.md`

```markdown
# RustDesk Protocol Detection

This module implements detection for RustDesk server protocols.

## Protocols

### HBBS (Rendezvous/Signaling Server)
- **Port 21115 (TCP)**: NAT type testing
- **Port 21116 (TCP)**: TCP hole punching and connection service
- Detection method: Send TestNatRequest protobuf message, verify response

### HBBR (Relay Server)
- **Port 21117 (TCP)**: Relay service
- Detection method: Connection-based (server accepts connections)

## Implementation

The HBBS helper sends a protobuf `TestNatRequest` message wrapped in a `RendezvousMessage`:
```
[4-byte length prefix][protobuf message]
```

The HBBR helper uses simple connection detection (similar to Common protocol).

## Testing

Test against live server:
```bash
go run ../../cmd/go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21115
```

## References

- [RustDesk Server](https://github.com/rustdesk/rustdesk-server)
- [Rendezvous Protocol](https://github.com/rustdesk/rustdesk-server/blob/master/libs/hbb_common/protos/rendezvous.proto)
```

**Step 4: Run all tests**

Run: `go test ./...`
Expected: All tests pass

**Step 5: Verify no regressions**

Run: Test existing protocols still work:

```bash
./go-protocol-detector --protocol=ssh --host=127.0.0.1 --port=22
./go-protocol-detector --protocol=rdp --host=127.0.0.1 --port=3389
```

Expected: Existing protocols work correctly

**Step 6: Final commit**

```bash
git add internal/feature/rustdesk/README.md
git commit -m "docs(rustdesk): add protocol documentation and testing guide"
```

---

## Verification Checklist

After completing all tasks:

- [ ] All unit tests pass: `go test ./...`
- [ ] Build succeeds: `go build ./cmd/go-protocol-detector`
- [ ] HBBS detection works on port 21115
- [ ] HBBS detection works on port 21116
- [ ] HBBR detection works on port 21117
- [ ] CLI accepts `rustdesk-hbbs` protocol option
- [ ] CLI accepts `rustdesk-hbbr` protocol option
- [ ] Existing protocols still work (no regressions)
- [ ] Code follows existing patterns (DRY, consistent naming)
- [ ] Documentation is complete

---

## Notes for Implementation

1. **Protobuf Message Format**: RustDesk uses protobuf with 4-byte length prefix. The TestNatRequest message is minimal (field 1 = 0).

2. **Detection Strategy**: HBBS uses packet matching (send TestNatRequest), HBBR uses connection verification (like Common).

3. **Test Server**: Use 116.62.8.4 for live testing. If unavailable, tests should log warnings rather than fail.

4. **TCP-Only**: UDP detection for port 21116 is deferred for future implementation.

5. **Error Handling**: Use custom errors defined in `internal/custom_error/` for consistent error reporting.

6. **Code Style**: Follow existing patterns - use commonCheck for packet-based, CommonPortCheck for connection-based.
