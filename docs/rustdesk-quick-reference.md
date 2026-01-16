# RustDesk Detection - Quick Reference

Quick reference for RustDesk server detection using go-protocol-detector.

## TL;DR - Most Common Commands

```bash
# Scan single server (both protocols)
./go-protocol-detector --protocol=rustdesk-hbbs --host=116.62.8.4 --port=21116
./go-protocol-detector --protocol=rustdesk-hbbr --host=116.62.8.4 --port=21117

# Scan network range (both protocols)
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116
./go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117

# Use convenience script
./examples/scan-rustdesk.sh 192.168.1.1-254
```

## Protocol Selection

| Protocol | Port | Use When... | Command |
|----------|------|-------------|---------|
| rustdesk-hbbs | 21116 | Detect HBBS servers | `--protocol=rustdesk-hbbs` |
| rustdesk-hbbr | 21117 | Detect relay servers | `--protocol=rustdesk-hbbr` |

## Host Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.1` | One host |
| Range | `192.168.1.1-254` | Range of IPs |
| CIDR | `192.168.1.0/24` | Subnet (converted to range) |
| Multiple | `192.168.1.1,192.168.1.100` | Specific hosts |
| Combined | `192.168.1.1-100,10.0.0.1-50` | Multiple ranges |

## Common Scenarios

### Scenario 1: Check My Server

```bash
# Single server check
./go-protocol-detector --protocol=rustdesk-hbbs --host=YOUR_SERVER_IP --port=21116
./go-protocol-detector --protocol=rustdesk-hbbr --host=YOUR_SERVER_IP --port=21117
```

### Scenario 2: Scan Local Network

```bash
# Full /24 network
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 --thread=20
./go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117 --thread=20
```

### Scenario 3: Quick Network Audit

```bash
# Use provided script
cd examples
./scan-rustdesk-parallel.bat 192.168.1.1-254
```

### Scenario 4: High-Performance Scan

```bash
# More threads = faster
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 --thread=50 --timeout=5000
./go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117 --thread=50 --timeout=5000
```

### Scenario 5: Remote Network (WAN)

```bash
# Longer timeout for remote networks
./go-protocol-detector --protocol=rustdesk-hbbs --host=REMOTE_IP --port=21116 --timeout=5000
./go-protocol-detector --protocol=rustdesk-hbbr --host=REMOTE_IP --port=21117 --timeout=5000
```

## Understanding Results

### Console Output

```
rustdesk-hbbs 192.168.1.100:21116 true (45ms)  ← Found HBBS server
rustdesk-hbbs 192.168.1.101:21116 false (100ms) ← Not HBBS (timeout/no response)
rustdesk-hbbr 192.168.1.100:21117 true (30ms)  ← Found relay server
```

### CSV Output

```csv
timestamp,protocol,host,port,result,latency_ms,error
2026-01-16T10:00:00Z,rustdesk-hbbs,192.168.1.100,21116,true,45.5,
2026-01-16T10:00:01Z,rustdesk-hbbr,192.168.1.100,21117,true,30.2,
```

### Result Interpretation

| HBBS | HBBR | Server Type | Action |
|------|------|-------------|--------|
| ✅ true | ✅ true | Full RustDesk Server | Normal deployment |
| ✅ true | ❌ false | HBBS Only | Relay not configured |
| ❌ false | ✅ true | Unusual | Check configuration |
| ❌ false | ❌ false | No RustDesk | Not a RustDesk server |

## Performance Tuning

### Thread Count

- **Small network** (< 100 IPs): `--thread=10`
- **Medium network** (100-1000 IPs): `--thread=20` (default)
- **Large network** (> 1000 IPs): `--thread=50`

### Timeout

- **Local network** (LAN): `--timeout=1000` (1s, default)
- **Remote network** (WAN): `--timeout=3000` (3s)
- **Very remote/slow**: `--timeout=5000` (5s)

### Formula

```
Estimated Time = (Number of IPs × Timeout × 2) / Thread Count

Example: 254 IPs × 3s × 2 / 20 threads = ~76 seconds
```

## Automation Examples

### Windows Batch File

```batch
@echo off
REM daily_scan.bat

FOR %%s IN (192.168.1.0/24,192.168.2.0/24) DO (
    echo Scanning %%s
    go-protocol-detector --protocol=rustdesk-hbbs --host=%%s --port=21116
    go-protocol-detector --protocol=rustdesk-hbbr --host=%%s --port=21117
)
```

### Linux Shell Script

```bash
#!/bin/bash
# daily_scan.sh

for subnet in 192.168.1.0/24 192.168.2.0/24; do
    echo "Scanning $subnet"
    ./go-protocol-detector --protocol=rustdesk-hbbs --host=$subnet --port=21116
    ./go-protocol-detector --protocol=rustdesk-hbbr --host=$subnet --port=21117
done
```

## Troubleshooting

### Problem: All scans timeout

```bash
# Check connectivity
ping TARGET_IP
telnet TARGET_IP 21116

# Try longer timeout
./go-protocol-detector --protocol=rustdesk-hbbs --host=TARGET_IP --port=21116 --timeout=10000
```

### Problem: Slow scans

```bash
# Increase threads
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 --thread=50

# Reduce timeout (if network is fast)
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 --timeout=1000
```

### Problem: Permission denied (Linux/Mac)

```bash
# Fix permissions
chmod +x go-protocol-detector
chmod +x examples/scan-rustdesk.sh
```

## Best Practices

1. **Start with small ranges** to verify connectivity
2. **Use appropriate timeout** for your network latency
3. **Adjust thread count** based on your system resources
4. **Scan during off-peak hours** for large networks
5. **Save CSV results** for later analysis
6. **Use provided scripts** for common scenarios

## Integration Examples

### Parse JSON Output

```bash
# Convert to JSON
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 |
    grep -E "true|false" |
    jq -R 'split(" ") | {host: .[0], status: .[2]}'
```

### Export to Excel

```powershell
# Import CSV to Excel
Import-Csv scan_results_*.csv | Export-Excel -Path results.xlsx
```

### Send to Monitoring

```bash
# Send to webhook
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 |
    grep "true" |
    curl -X POST https://your-monitoring.com/webhook -d @-
```

## Further Reading

- [Full Documentation](../internal/feature/rustdesk/README.md)
- [Example Scripts](../examples/README.md)
- [Research Document](../docs/research/rustdesk-hbbs-detection-research.md)
- [RustDesk Official Docs](https://rustdesk.com/docs/en/self-host/)

## Tips & Tricks

### Tip 1: Use CIDR notation

```bash
# Instead of 192.168.1.1-254
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.0/24 --port=21116
```

### Tip 2: Combine multiple protocols in one script

```bash
# Scan everything
for proto in rustdesk-hbbs rustdesk-hbbr; do
    ./go-protocol-detector --protocol=$proto --host=192.168.1.1-254 --port=${proto##*-}
done
```

### Tip 3: Save results with timestamp

```bash
# Timestamped output
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 \
    > results_$(date +%Y%m%d_%H%M%S).log
```

### Tip 4: Filter found servers only

```bash
# Show only successful detections
./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116 \
    | grep "true" \
    > found_servers.txt
```

### Tip 5: Rate limiting for large scans

```bash
# Add delay between batches
for i in {0..10}; do
    start=$((i*25+1))
    end=$((start+24))
    ./go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.$start-$end --port=21116
    sleep 5  # 5 second delay
done
```

## Command Reference

```
go-protocol-detector [OPTIONS]

OPTIONS:
    --protocol value    Protocol to scan (rustdesk-hbbs|rustdesk-hbbr)
    --host value        Target host(s) (IP, range, CIDR, or comma-separated)
    --port value        Port number (21116 or 21117)
    --thread value      Number of concurrent threads (default: 10)
    --timeout value     Connection timeout in milliseconds (default: 1000)
    --help, -h          Show help

EXAMPLES:
    go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116
    go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.0/24 --port=21117 --thread=20
```

## Quick Decision Tree

```
Need to scan RustDesk servers?
│
├─ Single server?
│  └─ Run two commands:
│     ./go-protocol-detector --protocol=rustdesk-hbbs --host=IP --port=21116
│     ./go-protocol-detector --protocol=rustdesk-hbbr --host=IP --port=21117
│
├─ Network range?
│  ├─ Small (< 100 IPs)?
│  │  └─ Use default: --thread=10
│  ├─ Medium (100-1000 IPs)?
│  │  └─ Increase threads: --thread=20
│  └─ Large (> 1000 IPs)?
│     └─ Use script: ./examples/scan-rustdesk-parallel.bat RANGE
│
└─ Automated scan?
   └─ Use provided scripts or create batch file
```
