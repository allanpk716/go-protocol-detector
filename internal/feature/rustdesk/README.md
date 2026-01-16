# RustDesk Protocol Detection

This module implements detection for RustDesk server protocols.

## Protocols

### HBBS (Rendezvous/Signaling Server) - Port 21116
- **Port 21116 (TCP)**: ID registration, heartbeat, and TCP hole punching
- **Port 21116 (UDP)**: ID registration and heartbeat (not currently supported)
- Detection method: Send `RegisterPk` protobuf message, verify response

> **Note**: Port 21115 is a client-side NAT testing port and is **NOT detected** by this tool.
> See the [Port 21115 Analysis](#port-21115-analysis) section below for details.

### HBBR (Relay Server) - Port 21117
- **Port 21117 (TCP)**: Relay service for P2P connections
- Detection method: Send `RequestRelay` protobuf message, verify acceptance

## Implementation

### HBBS Detection (Port 21116)

The HBBS 21116 helper sends a protobuf `RegisterPk` message wrapped in a `RendezvousMessage`:
```
[BytesCodec length header][RendezvousMessage with RegisterPk]
```

The `RegisterPk` message includes:
- `id`: "test" (any string works for detection)
- `no_register_device`: true (skip device binding)

Expected response features:
- Field 16 (`register_pk_response`) tag: `0x82`

This method is **reliable** because:
- Port 21116 is the primary HBBS service port
- All RustDesk servers require port 21116 for core functionality
- The `RegisterPk` message is always handled by the HBBS server

### HBBR Detection (Port 21117)

The HBBR helper sends a protobuf `RequestRelay` message:
```
[BytesCodec length header][RendezvousMessage with RequestRelay]
```

The HBBR server:
- Accepts the `RequestRelay` message
- Stores the connection waiting for relay pairing
- Does not close the connection (keeps it open for 30 seconds)

This method is **reliable** because:
- Port 21117 is exclusively used by RustDesk HBBR
- Only HBBR servers understand the `RequestRelay` message
- No false positives from other services

## Usage Examples

### Quick Start (Built Binary)

```bash
# Scan a single server - HBBS (port 21116)
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21116

# Scan a single server - HBBR (port 21117)
./go-protocol-detector --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117

# Scan an IP range - HBBS
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116

# Scan an IP range - HBBR
./go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117
```

### Scan Both HBBS and HBBR (Sequential)

```bash
# Method 1: Run two separate commands
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 --timeout=3000
./go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117 --timeout=3000

# Method 2: Use shell script (Linux/Mac)
./examples/scan-rustdesk.sh 192.168.1.1-254

# Method 3: Use batch script (Windows)
examples\scan-rustdesk.bat 192.168.1.1-254

# Method 4: Use PowerShell (Windows, parallel)
.\examples\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 20
```

### Development Mode (Go Run)

```bash
# Scan HBBS port 21116
go run cmd/go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116

# Scan HBBR port 21117
go run cmd/go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117

# Scan both protocols
go run cmd/go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.0/24 --port=21116
go run cmd/go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.0/24 --port=21117
```

### Advanced Examples

```bash
# High-performance scan (more threads, longer timeout)
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 --thread=50 --timeout=5000

# Scan CIDR notation
./go-protocol-detector --protocol=rustdesk-hbbs --host=10.0.0.0/24 --port=21116

# Scan multiple specific hosts
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1,192.168.1.100,192.168.1.200 --port=21116

# Combine multiple ranges
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-100,192.168.2.1-100 --port=21116
```

### Batch Scanning Multiple Networks

```bash
# Linux/Mac - Scan multiple subnets
for subnet in 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24; do
    ./go-protocol-detector --protocol=rustdesk-hbbs --host=$subnet --port=21116
    ./go-protocol-detector --protocol=rustdesk-hbbr --host=$subnet --port=21117
done

# Windows - Scan multiple subnets
FOR %%s IN (192.168.1.0/24,192.168.2.0/24,192.168.3.0/24) DO (
    go-protocol-detector --protocol=rustdesk-hbbs --host=%%s --port=21116
    go-protocol-detector --protocol=rustdesk-hbbr --host=%%s --port=21117
)
```

### Using Example Scripts

See [`examples/README.md`](../examples/README.md) for detailed documentation of example scripts:

- **scan-rustdesk.bat** (Windows): Simple sequential scan
- **scan-rustdesk-parallel.bat** (Windows): Parallel scan for speed
- **scan-rustdesk.ps1** (PowerShell): Advanced scan with result aggregation
- **scan-rustdesk.sh** (Linux/Mac): Shell script for Unix systems

```bash
# Windows examples
cd examples
scan-rustdesk.bat 192.168.1.1-254
scan-rustdesk-parallel.bat 192.168.1.1-254
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 20

# Linux/Mac examples
cd examples
chmod +x scan-rustdesk.sh
./scan-rustdesk.sh 192.168.1.1-254
```

## Testing

### Test against live server
```bash
# Build the detector
go build -o go-protocol-detector.exe ./cmd/go-protocol-detector

# Test HBBS port 21116
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21116 --timeout=3000

# Test HBBR port 21117
./go-protocol-detector --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117 --timeout=3000

# Test both protocols
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21116 --timeout=3000
./go-protocol-detector --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117 --timeout=3000
```

### Unit tests
```bash
go test ./internal/feature/rustdesk/...
go test ./pkg -run TestDetector_HBBS21116
go test ./pkg -run TestDetector_HBBR
```

## Protocol Details

### RustDesk Architecture
RustDesk uses a client-server architecture with three main components:
- **Client**: Desktop application for remote desktop access
- **HBBS**: Rendezvous server for NAT traversal and signaling (port 21116)
- **HBBR**: Relay server for direct connection fallback (port 21117)

### HBBS Protocol (Port 21116)
The HBBS server handles:
- Client ID registration
- Public key registration
- Heartbeat/keepalive
- TCP hole punching coordination
- Connection signaling

### HBBR Protocol (Port 21117)
The HBBR server provides:
- Relay service for connections that cannot establish P2P
- Fallback routing when direct connection fails
- Traffic forwarding between clients

## Detection Accuracy

### HBBS (Port 21116)
- **True Positive**: Server responds with valid `RegisterPkResponse`
- **False Positive**: Very unlikely (requires valid protobuf response)
- **False Negative**: Rare (server must be down or port blocked)
- **Timeout**: 3 seconds default (configurable)

### HBBR (Port 21117)
- **True Positive**: Server accepts `RequestRelay` message
- **False Positive**: Very unlikely (only HBBR understands this message)
- **False Negative**: Rare (server must be down or port blocked)
- **Timeout**: 3 seconds default (configurable)

## Performance Considerations

- HBBS detection requires sending protobuf message and reading response
- HBBR detection requires sending protobuf message
- Default timeout is 3000ms for both protocols
- Recommended: Use 10-20 threads for large IP ranges
- Connection limit: 2x thread count (max 500)

## Troubleshooting

### No results on HBBS port 21116
- Check if server is running: `netstat -an | grep 21116`
- Verify server configuration
- Try increasing timeout: `--timeout=5000`
- Check firewall rules

### No results on HBBR port 21117
- Verify relay service is enabled
- Check if port 21117 is open
- Ensure server is not overloaded
- Test with direct connection: `telnet <host> 21117`

### Connection timeouts
- Server may be overloaded or offline
- Network connectivity issues
- Firewall blocking connections
- Try with increased timeout

## Port 21115 Analysis

### What is Port 21115?

Port 21115 is officially documented by RustDesk as the "NAT type testing" port. However, after extensive research, we determined that **port 21115 is NOT suitable for server detection**.

### Why Port 21115 is Different

Port 21115 is a **client-side diagnostic tool**, not a server service:

1. **Client-Initiated Only**: Port 21115 is only used by RustDesk clients during startup to test their own NAT type

2. **Optional Feature**: Clients work perfectly without port 21115. The NAT test is purely diagnostic

3. **No Persistent Service**: Unlike ports 21116 and 21117, port 21115 doesn't handle:
   - ID registration
   - Authentication
   - P2P hole punching
   - Relay coordination

4. **Server Configuration**: Many RustDesk server deployments configure port 21115 minimally or disable it entirely

### Why We Don't Detect Port 21115

| Issue | Impact |
|-------|--------|
| Unreliable responses | Many servers don't respond to TestNatRequest |
| Optional feature | Servers work fine without it |
| False negatives | Would mislead users about server availability |
| Not a service indicator | Presence doesn't indicate server functionality |

### Recommendation

To verify HBBS server availability, **detect port 21116** using the `RegisterPk` message. Port 21116 is the primary HBBS service port and is always required for core functionality.

### Technical Details

For a detailed analysis of port 21115 and the client-side NAT testing flow, see:
- [Research Document](../../docs/research/rustdesk-hbbs-detection-research.md#appendix-port-21115-analysis-2025-01-16)
- [RustDesk Client Source](https://github.com/rustdesk/rustdesk/blob/master/src/common.rs)
- [RustDesk Server Source](https://github.com/rustdesk/rustdesk-server/blob/master/src/rendezvous_server.rs)

## References

- [RustDesk Server Documentation](https://github.com/rustdesk/rustdesk-server)
- [Rendezvous Protocol](https://github.com/rustdesk/rustdesk-server/blob/master/libs/hbb_common/protos/rendezvous.proto)
- [RustDesk Architecture](https://github.com/rustdesk/rustdesk/wiki/Architecture)
- [Installation Guide](https://github.com/rustdesk/rustdesk-server/blob/master/docs/en/install.md)
- [Self-Host Documentation](https://rustdesk.com/docs/en/self-host/)

## License

This implementation is part of the go-protocol-detector project.
See main project LICENSE for details.
