# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Environment and Guidelines

### Communication Language
- **Use Chinese (中文) for all responses and explanations** to the user
- Code comments and documentation may remain in English for consistency with the codebase

### Development Platform
- **Primary development OS: Windows**
- Build and test commands should account for Windows environment (e.g., use `./go-protocol-detector.exe` not `./go-protocol-detector`)
- Shell commands may use Git Bash or Windows CMD syntax as appropriate

### Script Development Rules
- **BAT scripts MUST NOT contain Chinese characters** - use only ASCII/English to ensure proper execution on Windows
- **Script modification**: When asked to fix a script, edit the existing script file directly. Only create a new script if explicitly necessary or requested.

## Project Overview

This is a Go-based network protocol detector that identifies active services for multiple protocols (RDP, SSH, FTP, SFTP, Telnet, VNC, RustDesk) across IP ranges and port ranges. The tool uses packet-based detection for most protocols and connection-based detection for others.

## Build and Development Commands

### Building
```bash
go build -o go-protocol-detector ./cmd/go-protocol-detector
```

### Building with GoReleaser
```bash
# Quick configuration check
goreleaser check

# Build for current platform only
goreleaser build --single-target --snapshot --rm-dist

# Build for all platforms (development)
goreleaser build --snapshot --rm-dist

# Full release simulation (without publishing)
goreleaser release --snapshot --skip-publish --rm-dist
```

### Running Tests
```bash
go test ./pkg/...
go test ./internal/...

# Run specific test suites
go test ./pkg -run TestDetector_RDPCheck
go test ./pkg -run TestDetector_SSHCheck
go test ./pkg -run TestScanTools_Scan

# Run tests with environment configuration (copy test.env.example to .env first)
cp test.env.example .env
# Edit .env with your test server details
export $(cat .env | xargs)
go test ./pkg/...
```

### Running the Application
```bash
# Basic usage
go run cmd/go-protocol-detector/main.go --protocol=rdp --host=192.168.1.1-254 --port=3389

# With custom threads and timeout
go run cmd/go-protocol-detector/main.go --protocol=ssh --host=192.168.1.0/24 --port=22 --thread=20 --timeout=5000

# SFTP with authentication
go run cmd/go-protocol-detector/main.go --protocol=sftp --host=192.168.1.100-150 --port=22 --user=root --password=mypassword

# RustDesk detection examples
go run cmd/go-protocol-detector/main.go --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21115
go run cmd/go-protocol-detector/main.go --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117
go run cmd/go-protocol-detector/main.go --protocol=rustdesk-hbbs-21116 --host=192.168.1.1-254 --port=21116

# Multiple hosts and ports
go run cmd/go-protocol-detector/main.go --protocol=common --host=192.168.1.1,192.168.1.100-150,10.0.0.0/24 --port=22,80,443,3389,8000-8100
```

### Running with Progress Bars

The scanner displays dual progress bars by default when outputting to a terminal:
- **Top bar**: Overall IP scan progress
- **Bottom bar**: Current IP port scan progress

```bash
# With progress bars (default when outputting to terminal)
go run cmd/go-protocol-detector/main.go --protocol=ssh --host=192.168.1.1-254 --port=22,80,443

# Redirect output to file (automatically disables progress bars)
go run cmd/go-protocol-detector/main.go --protocol=ssh --host=192.168.1.1-254 --port=22 > scan.log
```

### Progress Bar Features

- **Cross-platform**: Works on Windows, Linux, and macOS using `github.com/vbauerster/mpb`
- **Automatic fallback**: Disables when output is redirected to a file or piped to another command
- **Thread-safe**: Multiple goroutines can update progress concurrently using atomic operations
- **Performance**: Minimal overhead with benchmark results showing <1 ns/op per increment
- **Memory efficient**: Zero allocations for most operations (0 B/op for increment operations)

## Architecture

### Core Components

1. **Main Entry Point** (`cmd/go-protocol-detector/main.go`)
   - CLI interface using `urfave/cli/v2`
   - Parses command-line arguments (protocol, host, port, threading, timeout, auth)
   - Supports all protocol types including RustDesk variants (rustdesk-hbbs, rustdesk-hbbr, rustdesk-hbbs-21116) with authentication options for SFTP

2. **Scanning Engine** (`pkg/scan_tools.go`)
   - Main orchestration with configurable threading (using `ants` goroutine pool)
   - IP range parsing (supports CIDR, range notation, single IPs, multiple comma-separated values)
   - Port range parsing (supports single ports, ranges, comma-separated combinations)
   - Concurrent scanning with resource limiting, rate limiting, and panic recovery
   - Connection guard and resource limiter for system protection

3. **Protocol Detection** (`pkg/detector.go`)
   - Individual protocol detection methods with unified timeout handling
   - Two detection approaches:
     - **Packet-based**: Send protocol-specific packets, match response features (RDP, SSH, FTP, RustDesk)
     - **Connection-based**: Establish connection and verify service (Telnet, VNC, Common)
     - **Protocol-based**: SFTP uses 3-layer detection (TCP → SSH Banner → SFTP subsystem query); RustDesk HBBR uses send-only detection
   - Common packet matching logic with safety bounds and error handling

4. **Protocol Implementations** (`internal/feature/*/`)
   - Each protocol has its own helper with packet definitions and response features
   - RDP, SSH, FTP use packet matching with specific byte pattern detection
   - RustDesk (HBBS, HBBR, HBBS21116) uses protobuf-encoded messages for protocol-specific detection
   - SFTP uses 3-layer protocol detection (TCP → SSH Banner → SFTP subsystem query) as the primary method, with auth-based detection as fallback when credentials are provided

5. **Supporting Infrastructure**
   - `internal/common/feature.go`: Defines `ReceiverFeature` for packet matching
   - `internal/utils/`: Resource limiting, connection management, file validation
   - `internal/errors/`: Custom error types with structured error handling
   - `internal/custom_error/`: Protocol-specific error definitions

### Key Data Structures

- `ProtocolType`: Enum for supported protocols (RDP, SSH, FTP, SFTP, Telnet, VNC, Common, RustDeskHBBS, RustDeskHBBR, RustDeskHBBS21116)
- `InputInfo`: Scanning parameters (hosts, ports, credentials, authentication)
- `OutputInfo`: Results with success/failure maps organized by host
- `DeliveryInfo`: Job data for worker goroutines with channels for results
- `ReceiverFeature`: Packet response matching criteria with byte offset and pattern
- `IPRangeInfo`: Parsed host information supporting CIDR and range notation
- `CheckResult`: Individual scan result with success status and metadata

### Detection Methods

1. **Packet Matching** (`commonCheck` in detector.go:82)
   - Send protocol-specific handshake packet
   - Read response with timeout and size limits (max 4KB)
   - Match expected byte patterns at specific offsets using `ReceiverFeature` array
   - Used by RDP, SSH, FTP, RustDesk (HBBS, HBBS21116) with protocol-specific packet signatures

2. **Connection Verification**
   - Establish TCP connection with configurable timeout
   - Verify service response or perform basic protocol handshake
   - Used by Telnet (response reading), VNC (protocol handshake), and generic port checking

3. **3-Layer SFTP Detection** (`checkSFTPProtocolWithDiagnostics`)
   - Layer 1: TCP connection test to target host:port
   - Layer 2: SSH Banner reading to verify SSH protocol (e.g. `SSH-2.0-OpenSSH_8.9`)
   - Layer 3: SSH subsystem query to confirm SFTP subsystem support
   - Returns detailed diagnostics (`SFTPDiagnostics`) including TCP status, SSH banner/version, and SFTP support
   - Auth-based detection (`CheckWithAuth`) remains available as fallback when credentials are provided

4. **RustDesk HBBR Detection** (send-only)
   - Sends protobuf `RequestRelay` message to target port
   - HBBR servers accept the message and keep connection open (no immediate response)
   - Detection is confirmed by successful send without connection reset
   - Note: HBBS port 21115 (NAT test) is NOT detected — see `internal/feature/rustdesk/README.md`

### Concurrency and Resource Management

- **Goroutine Pool**: Uses `ants` library for efficient goroutine reuse
- **Resource Limiting**: Connection guard with max connection limits (2x thread count, max 500)
- **Rate Limiting**: Configurable request rate to prevent network flooding
- **Panic Recovery**: Individual goroutine isolation with panic recovery
- **Thread Safety**: Mutex protection for shared result maps and concurrent operations

## Testing

### Test Categories
- **Protocol Detection Tests** (`detector_test.go`): Require actual running services
- **Input Validation Tests** (`input_validation_test.go`, `port_validation_test.go`): Edge cases and boundary testing
- **Performance Tests** (`large_range_test.go`): Large IP/port range handling
- **Concurrency Tests** (`race_test.go`, `race_simple_test.go`): Thread safety and race condition detection
- **Integration Tests** (`scan_tools_test.go`): End-to-end scanning workflow

### Test Environment Setup
1. Copy `test.env.example` to `.env` and configure with test server details
2. Load environment variables before running tests
3. Tests will skip if required environment variables are not set
4. Some tests require actual running services (RDP, SSH, FTP, etc.)

## Configuration

### Threading and Performance
- **Default**: 10 concurrent threads
- **Maximum**: 1000 threads (auto-limited for system protection)
- **Connection Limit**: 2x thread count (max 500 connections)
- **Memory Limit**: 512MB for resource limiter

### Timeout Configuration
- **Default**: 1000ms for connection attempts
- **Read Timeout**: 5 seconds for packet responses
- **Context Timeout**: Connection scan timeout for resource acquisition

### Input Formats
- **Host Formats**:
  - Single IP: `192.168.1.1`
  - Range: `192.168.1.1-254` (max 1000 IPs per range)
  - CIDR: `192.168.1.0/24`
  - Multiple: `192.168.1.1,192.168.1.100-150,10.0.0.0/24`
- **Port Formats**:
  - Single: `22`
  - Multiple: `22,80,443`
  - Range: `8000-8100`
  - Mixed: `22,80,443,8000-8100,3389` (max 10000 ports total)

### Safety Limits
- IP ranges limited to prevent resource exhaustion
- Port ranges validated for boundaries (1-65535)
- Connection and rate limiting to protect network resources
- Panic recovery to maintain application stability

## Protocol Specific Notes

- **SFTP**: Uses 3-layer protocol detection (TCP → SSH Banner → SFTP subsystem query) as the primary method, requiring no authentication credentials. Auth-based detection is available as fallback when username/password or private key are provided. Private key files are validated for existence and format.
- **RDP**: Detects RDP service across Windows versions (2003, 2008, 2012, 2016, 2019, Win7, Win10) using connection request packet matching.
- **SSH**: Packet-based detection using SSH-2.0 protocol identification string, no authentication required.
- **FTP**: Basic FTP service detection using connection packet matching with standard FTP response patterns.
- **Telnet**: Connection verification with response reading and basic telnet protocol handshake.
- **VNC**: VNC protocol detection via RFB (Remote Frame Buffer) protocol connection handshake.
- **Common**: Generic TCP port open/closed detection using simple socket connection.
- **RustDesk**: Three detection modes for RustDesk remote desktop infrastructure:
  - **rustdesk-hbbs**: Sends protobuf `TestNatRequest` message; verifies `TestNatResponse` with port field. Detects HBBS rendezvous/signaling server.
  - **rustdesk-hbbr**: Sends protobuf `RequestRelay` message; detection by successful send without connection reset. Detects HBBR relay server.
  - **rustdesk-hbbs-21116**: Sends protobuf `RegisterPk` message with `no_register_device=true`; verifies `RegisterPkResponse` field. Detects HBBS TCP hole punching service on port 21116.

## Development Notes

### Error Handling
- Structured error types in `internal/errors/` for different failure scenarios
- Validation errors include context about failed constraints
- Resource limit errors prevent system overload
- Protocol-specific errors provide clear diagnostic information

### Code Organization
- Clear separation between detection logic, scanning orchestration, and protocol implementations
- Modular design allows easy addition of new protocols
- Consistent interfaces across protocol helpers
- Comprehensive input validation and sanitization

### Performance Considerations
- Efficient goroutine pooling to minimize allocation overhead
- Connection reuse and limiting to prevent resource exhaustion
- Early timeout handling to avoid hanging on unresponsive services
- Concurrent result collection with buffered channels