# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based network protocol detector that identifies active services for multiple protocols (RDP, SSH, FTP, SFTP, Telnet, VNC) across IP ranges and port ranges. The tool uses packet-based detection for most protocols and connection-based detection for others.

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

# Multiple hosts and ports
go run cmd/go-protocol-detector/main.go --protocol=common --host=192.168.1.1,192.168.1.100-150,10.0.0.0/24 --port=22,80,443,3389,8000-8100
```

## Architecture

### Core Components

1. **Main Entry Point** (`cmd/go-protocol-detector/main.go`)
   - CLI interface using `urfave/cli/v2`
   - Parses command-line arguments (protocol, host, port, threading, timeout, auth)
   - Supports all protocol types with authentication options for SFTP

2. **Scanning Engine** (`pkg/scan_tools.go`)
   - Main orchestration with configurable threading (using `ants` goroutine pool)
   - IP range parsing (supports CIDR, range notation, single IPs, multiple comma-separated values)
   - Port range parsing (supports single ports, ranges, comma-separated combinations)
   - Concurrent scanning with resource limiting, rate limiting, and panic recovery
   - Connection guard and resource limiter for system protection

3. **Protocol Detection** (`pkg/detector.go`)
   - Individual protocol detection methods with unified timeout handling
   - Two detection approaches:
     - **Packet-based**: Send protocol-specific packets, match response features (RDP, SSH, FTP)
     - **Connection-based**: Establish connection and verify service (Telnet, VNC, SFTP, Common)
   - Common packet matching logic with safety bounds and error handling

4. **Protocol Implementations** (`internal/feature/*/`)
   - Each protocol has its own helper with packet definitions and response features
   - RDP, SSH, FTP use packet matching with specific byte pattern detection
   - Telnet, VNC use connection verification with protocol-specific handshakes
   - SFTP requires full SSH authentication (password or private key)

5. **Supporting Infrastructure**
   - `internal/common/feature.go`: Defines `ReceiverFeature` for packet matching
   - `internal/utils/`: Resource limiting, connection management, file validation
   - `internal/errors/`: Custom error types with structured error handling
   - `internal/custom_error/`: Protocol-specific error definitions

### Key Data Structures

- `ProtocolType`: Enum for supported protocols (RDP, SSH, FTP, SFTP, Telnet, VNC, Common)
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
   - Used by RDP, SSH, FTP with protocol-specific packet signatures

2. **Connection Verification**
   - Establish TCP connection with configurable timeout
   - Verify service response or perform basic protocol handshake
   - Used by Telnet (response reading), VNC (protocol handshake), and generic port checking

3. **Authenticated Detection** (SFTP)
   - Full SSH connection establishment with authentication
   - Supports both password and private key authentication methods
   - Validates SFTP subsystem availability after successful SSH auth

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

### Current Test Issues
Several tests have known failures due to validation logic differences:
- Port validation tests expect port 0 to be valid (implementation rejects it)
- Thread validation tests expect 0/negative threads to default to 1 (implementation defaults to 10)
- Input validation tests expect stricter empty host/port validation

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

- **SFTP**: Requires valid credentials - username/password or private key file path. Private key files are validated for existence and format.
- **RDP**: Detects RDP service across Windows versions (2003, 2008, 2012, 2016, 2019, Win7, Win10) using connection request packet matching.
- **SSH**: Packet-based detection using SSH-2.0 protocol identification string, no authentication required.
- **FTP**: Basic FTP service detection using connection packet matching with standard FTP response patterns.
- **Telnet**: Connection verification with response reading and basic telnet protocol handshake.
- **VNC**: VNC protocol detection via RFB (Remote Frame Buffer) protocol connection handshake.
- **Common**: Generic TCP port open/closed detection using simple socket connection.

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