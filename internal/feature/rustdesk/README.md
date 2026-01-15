# RustDesk Protocol Detection

This module implements detection for RustDesk server protocols.

## Protocols

### HBBS (Rendezvous/Signaling Server)
- **Port 21115 (TCP)**: NAT type testing service
- **Port 21116 (TCP)**: TCP hole punching and connection service
- Detection method: Send TestNatRequest protobuf message, verify response

### HBBR (Relay Server)
- **Port 21117 (TCP)**: Relay service for P2P connections
- Detection method: Connection-based (server accepts connections)

## Implementation

### HBBS Detection
The HBBS helper sends a protobuf `TestNatRequest` message wrapped in a `RendezvousMessage`:
```
[4-byte length prefix][protobuf message]
```

Expected response features:
- Byte 0: `0x09` (message length marker)
- Byte 1: `0x08` (field identifier)
- Byte 2: `0x01` or `0x02` (NAT type value)

### HBBR Detection
The HBBR helper uses simple connection detection (similar to Common protocol).
If the server accepts a TCP connection on port 21117, it's considered an active HBBR service.

## Usage Examples

### Scan HBBS ports
```bash
go run cmd/go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21115,21116
```

### Scan HBBR port
```bash
go run cmd/go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117
```

### Scan all RustDesk ports
```bash
go run cmd/go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.0/24 --port=21115-21117
```

### With custom timeout and threads
```bash
go run cmd/go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21115-21117 --timeout=5000 --thread=20
```

## Testing

### Test against live server
```bash
# Build the detector
go build -o go-protocol-detector.exe ./cmd/go-protocol-detector

# Test HBBS port 21115
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21115 --timeout=3000

# Test HBBS port 21116
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21116 --timeout=3000

# Test HBBR port 21117
./go-protocol-detector --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117 --timeout=3000

# Test all RustDesk ports
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21115,21116,21117 --timeout=3000
```

### Unit tests
```bash
go test ./internal/feature/rustdesk/...
go test ./pkg -run TestDetector_RustDeskHBBS
go test ./pkg -run TestDetector_RustDeskHBBR
```

## Protocol Details

### RustDesk Architecture
RustDesk uses a client-server architecture with three main components:
- **Client**: Desktop application for remote desktop access
- **HBBS**: Rendezvous server for NAT traversal and signaling
- **HBBR**: Relay server for direct connection fallback

### HBBS Protocol (Ports 21115, 21116)
The HBBS server handles:
- NAT type detection (port 21115)
- TCP hole punching (port 21116)
- Client registration and discovery
- Connection signaling

### HBBR Protocol (Port 21117)
The HBBR server provides:
- Relay service for connections that cannot establish P2P
- Fallback routing when direct connection fails
- Traffic forwarding between clients

## Detection Accuracy

### HBBS
- **True Positive**: Server responds with valid protobuf message
- **False Positive**: Unlikely (requires specific protobuf response)
- **False Negative**: Possible if server is busy or configured differently
- **Timeout**: 3 seconds default (configurable)

### HBBR
- **True Positive**: Server accepts TCP connection
- **False Positive**: Possible (any service listening on 21117)
- **False Negative**: Possible if server is overloaded
- **Timeout**: 3 seconds default (configurable)

## Performance Considerations

- HBBS detection requires sending and receiving protobuf messages
- HBBR detection is faster (simple TCP connection)
- Default timeout is 3000ms for both protocols
- Recommended: Use 10-20 threads for large IP ranges
- Connection limit: 2x thread count (max 500)

## Troubleshooting

### No results on HBBS ports
- Check if server is running (`netstat -an | grep 21115`)
- Verify server configuration (HBBS may be disabled)
- Try increasing timeout: `--timeout=5000`
- Check firewall rules

### No results on HBBR port
- Verify relay service is enabled
- Check if port 21117 is open
- Ensure server is not overloaded
- Test with direct connection: `telnet <host> 21117`

### Connection timeouts
- Server may be overloaded or offline
- Network connectivity issues
- Firewall blocking connections
- Try with increased timeout

## References

- [RustDesk Server Documentation](https://github.com/rustdesk/rustdesk-server)
- [Rendezvous Protocol](https://github.com/rustdesk/rustdesk-server/blob/master/libs/hbb_common/protos/rendezvous.proto)
- [RustDesk Architecture](https://github.com/rustdesk/rustdesk/wiki/Architecture)
- [Installation Guide](https://github.com/rustdesk/rustdesk-server/blob/master/docs/en/install.md)

## License

This implementation is part of the go-protocol-detector project.
See main project LICENSE for details.
