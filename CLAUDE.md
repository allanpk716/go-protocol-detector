# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based network protocol detector that identifies active services for multiple protocols (RDP, SSH, FTP, SFTP, Telnet, VNC) across IP ranges and port ranges. The tool uses packet-based detection for most protocols and connection-based detection for others.

## Build and Development Commands

### Building
```bash
go build -o go-protocol-detector ./cmd/go-protocol-detector
```

### Running Tests
```bash
go test ./pkg/...
go test ./internal/...
```

### Running Individual Tests
```bash
go test ./pkg -run TestDetector_RDPCheck
go test ./pkg -run TestDetector_SSHCheck
```

### Running the Application
```bash
# Basic usage
go run cmd/go-protocol-detector/main.go --protocol=rdp --host=192.168.1.1-254 --port=3389

# With custom threads and timeout
go run cmd/go-protocol-detector/main.go --protocol=ssh --host=192.168.1.0/24 --port=22 --thread=20 --timeout=5000

# SFTP with authentication
go run cmd/go-protocol-detector/main.go --protocol=sftp --host=192.168.1.100-150 --port=22 --user=root --password=mypassword
```

## Architecture

### Core Components

1. **Main Entry Point** (`cmd/go-protocol-detector/main.go`)
   - CLI interface using `urfave/cli/v2`
   - Parses command-line arguments (protocol, host, port, threading, timeout, auth)
   - Calls scanning functionality

2. **Scanning Engine** (`pkg/scan_tools.go`)
   - Main orchestration with configurable threading (using `ants` goroutine pool)
   - IP range parsing (supports CIDR, range notation, single IPs)
   - Port range parsing (supports single ports and ranges)
   - Concurrent scanning with result collection

3. **Protocol Detection** (`pkg/detector.go`)
   - Individual protocol detection methods
   - Two detection approaches:
     - **Packet-based**: Send protocol-specific packets, match response features (RDP, SSH, FTP)
     - **Connection-based**: Establish connection and verify service (Telnet, VNC, SFTP, Common)

4. **Protocol Implementations** (`internal/feature/*/`)
   - Each protocol has its own helper with packet definitions and response features
   - RDP, SSH, FTP use packet matching
   - Telnet, VNC use connection verification
   - SFTP requires authentication (password or private key)

### Key Data Structures

- `ProtocolType`: Enum for supported protocols
- `InputInfo`: Scanning parameters (hosts, ports, credentials)
- `OutputInfo`: Results with success/failure maps
- `DeliveryInfo`: Job data for worker goroutines
- `ReceiverFeature`: Packet response matching criteria

### Detection Methods

1. **Packet Matching** (`commonCheck` in detector.go:81)
   - Send protocol-specific handshake packet
   - Read response and match expected byte patterns at specific offsets
   - Used by RDP, SSH, FTP

2. **Connection Verification**
   - Establish TCP connection with timeout
   - Verify service response or perform basic protocol handshake
   - Used by Telnet, VNC, and generic port checking

3. **Authenticated Detection** (SFTP)
   - Full SSH connection with authentication
   - Requires username/password or private key credentials

## Testing

- Tests in `pkg/detector_test.go` require actual running services to validate
- Update test IP addresses and ports to match your test environment
- SFTP tests require valid credentials and private key files

## Configuration

- **Threading**: Default 10, max 1000 threads for concurrent scanning
- **Timeout**: Default 1000ms for connection attempts
- **Host Formats**: Single IP (192.168.1.1), range (192.168.1.1-254), CIDR (192.168.1.0/24)
- **Port Formats**: Single port (22), comma-separated (22,80,443), ranges (8000-8100)

## Protocol Specific Notes

- **SFTP**: Requires valid credentials - username/password or private key file path
- **RDP**: Detects RDP service across Windows versions (2003, 2008, 2012, 2016, 2019, Win7, Win10)
- **SSH**: Packet-based detection without authentication
- **FTP**: Basic FTP service detection
- **Telnet**: Connection verification with response reading
- **VNC**: VNC protocol detection via connection handshake
- **Common**: Generic TCP port open/closed detection