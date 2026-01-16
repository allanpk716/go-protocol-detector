# RustDesk Detection Examples

This directory contains example scripts for scanning RustDesk servers (HBBS and HBBR).

## Quick Start

### Windows

```batch
# Simple scan (sequential)
scan-rustdesk.bat 192.168.1.1-254

# Parallel scan (faster)
scan-rustdesk-parallel.bat 192.168.1.1-254

# PowerShell with result aggregation
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 20
```

### Linux/Mac

```bash
# Make script executable
chmod +x scan-rustdesk.sh

# Run scan
./scan-rustdesk.sh 192.168.1.1-254
```

## Script Descriptions

### 1. scan-rustdesk.bat (Windows)

Sequential scanning of HBBS and HBBR. Best for:
- Small IP ranges
- When you want to see results immediately
- When network bandwidth is limited

**Usage:**
```batch
scan-rustdesk.bat [host_range] [output_prefix]

# Examples:
scan-rustdesk.bat 192.168.1.1-254 scan
scan-rustdesk.bat 10.0.0.0/24 results
scan-rustdesk.bat 116.62.8.4 single
```

### 2. scan-rustdesk-parallel.bat (Windows)

Parallel scanning of HBBS and HBBR. Best for:
- Large IP ranges
- When speed is important
- Multi-core systems

**Usage:**
```batch
scan-rustdesk-parallel.bat [host_range]

# Examples:
scan-rustdesk-parallel.bat 192.168.1.1-254
scan-rustdesk-parallel.bat 10.0.0.0/24
```

### 3. scan-rustdesk.ps1 (PowerShell)

Advanced scanning with PowerShell. Features:
- Parallel execution
- Result aggregation
- Progress display
- Customizable parameters

**Usage:**
```powershell
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" [-OutputDir "results"] [-Threads 20] [-Timeout 3000]

# Examples:
.\scan-rustdesk.ps1 -Host "192.168.1.1-254"
.\scan-rustdesk.ps1 -Host "10.0.0.0/24" -OutputDir ".\scan_results"
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 50 -Timeout 5000
```

### 4. scan-rustdesk.sh (Linux/Mac)

Shell script for Unix-like systems. Features:
- Sequential scanning
- Error handling
- Clear output

**Usage:**
```bash
./scan-rustdesk.sh [host_range] [output_prefix]

# Examples:
./scan-rustdesk.sh 192.168.1.1-254 scan
./scan-rustdesk.sh 10.0.0.0/24 results
```

## Common Use Cases

### 1. Scan a Single Server

```batch
# Windows
scan-rustdesk.bat 116.62.8.4 single

# Linux/Mac
./scan-rustdesk.sh 116.62.8.4 single
```

### 2. Scan a Local Network

```batch
# Windows - Scan entire /24 network
scan-rustdesk-parallel.bat 192.168.1.1-254

# Linux/Mac
./scan-rustdesk.sh 192.168.1.1-254
```

### 3. Scan Multiple Subnets

```batch
# Windows
FOR %%i IN (192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24) DO (
    scan-rustdesk.bat %%i subnet_%%i
)

# Linux/Mac
for subnet in 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24; do
    ./scan-rustdesk.sh $subnet subnet_$subnet
done
```

### 4. High-Performance Scan

```powershell
# PowerShell - More threads, longer timeout
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 50 -Timeout 5000
```

### 5. Scheduled Scan (Windows Task Scheduler)

```batch
# Create a batch file for scheduled scans
@echo off
REM daily_rustdesk_scan.bat

set DATE=%date:~0,4%%date:~5,2%%date:~8,2%
set TIME=%time:~0,2%%time:~3,2%%time:~6,2%
set TIME=%TIME: =0%

scan-rustdesk-parallel.bat 192.168.1.1-254 > logs\rustdesk_scan_%DATE%_%TIME%.log 2>&1
```

## Understanding the Results

### CSV Output Format

The scanner generates CSV files with the following format:

```csv
timestamp,protocol,host,port,result,latency_ms,error
2026-01-16T09:46:15Z,rustdesk-hbbs,116.62.8.4,21116,true,71.1289,
2026-01-16T09:46:23Z,rustdesk-hbbr,116.62.8.4,21117,true,33.3777,
```

### Interpreting Results

- **result=true**: Server detected and responding
- **result=false**: Server not detected or timeout
- **latency_ms**: Response time in milliseconds
- **error**: Error message if scan failed

### Result Combinations

| HBBS | HBBR | Meaning |
|------|------|---------|
| true | true | Full RustDesk server (normal deployment) |
| true | false | HBBS only (relay not configured) |
| false | true | Unusual configuration (relay without HBBS) |
| false | false | No RustDesk service detected |

## Troubleshooting

### Script Not Found

```batch
# Windows - Make sure you're in the correct directory
cd C:\path\to\go-protocol-detector
dir *.bat

# Linux/Mac - Make script executable
chmod +x scan-rustdesk.sh
```

### Permission Denied

```bash
# Linux/Mac - Fix permissions
chmod +x scan-rustdesk.sh
sudo ./scan-rustdesk.sh 192.168.1.1-254
```

### No Results

Check:
1. Firewall settings (allow outbound connections)
2. Network connectivity
3. Correct IP range format
4. Server is actually running

```batch
# Test connectivity
ping 192.168.1.1
telnet 192.168.1.1 21116
```

## Advanced Usage

### Custom Thread Count

Higher threads = faster but more resource usage:

```powershell
# Conservative (10 threads)
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 10

# Aggressive (100 threads)
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Threads 100
```

### Custom Timeout

Increase timeout for slow networks:

```powershell
# 5 second timeout
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Timeout 5000

# 10 second timeout
.\scan-rustdesk.ps1 -Host "192.168.1.1-254" -Timeout 10000
```

### Output Organization

```batch
# Create dated directories
set DATE=%date:~0,4%%date:~5,2%%date:~8,2%
mkdir results\%DATE%
scan-rustdesk.bat 192.168.1.1-254 results\%DATE%\scan
```

## Performance Tips

1. **Use parallel scripts for large ranges** (21116-21117)
2. **Adjust thread count** based on your CPU cores
3. **Increase timeout** for remote networks over WAN
4. **Scan during off-peak hours** for large deployments
5. **Use CIDR notation** for subnet scanning (e.g., 192.168.1.0/24)

## Integration Examples

### with CSV Analysis Tools

```powershell
# Export to Excel
Import-Csv scan_results_*.csv | Export-Excel -Path rustdesk_results.xlsx

# Filter results
Import-Csv scan_results_*.csv | Where-Object { $_.result -eq "true" } | Export-Csv found_servers.csv
```

### with Monitoring Systems

```bash
# Generate JSON for monitoring
./scan-rustdesk.sh 192.168.1.1-254 | jq -R 'split(",") | {host: .[2], port: .[3], status: .[4]}'
```

## Support

For issues or questions:
- Check main README.md
- Review documentation in `docs/`
- Check RustDesk official documentation
