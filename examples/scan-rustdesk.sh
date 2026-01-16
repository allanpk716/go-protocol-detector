#!/bin/bash
# RustDesk Server Scanner - Scan both HBBS and HBBR
# Usage: ./scan-rustdesk.sh [host] [output_prefix]
# Example: ./scan-rustdesk.sh 192.168.1.1-254 scan

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 [host_range] [output_prefix]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.1-254 scan"
    echo "  $0 10.0.0.0/24 results"
    echo "  $0 116.62.8.4 single"
    exit 1
fi

HOST="$1"
PREFIX="${2:-rustdesk_scan}"

echo "========================================================"
echo "RustDesk Server Scanner"
echo "========================================================"
echo "Target: $HOST"
echo "Output Prefix: $PREFIX"
echo ""

echo "Scanning HBBS (port 21116)..."
./go-protocol-detector --protocol=rustdesk-hbbs --host="$HOST" --port=21116 --thread=20 --timeout=3000

echo ""
echo "Scanning HBBR (port 21117)..."
./go-protocol-detector --protocol=rustdesk-hbbr --host="$HOST" --port=21117 --thread=20 --timeout=3000

echo ""
echo "========================================================"
echo "Scan Complete!"
echo "========================================================"
echo "HBBS results: scan_results_*_hbbs*.csv"
echo "HBBR results: scan_results_*_hbbr*.csv"
echo ""
echo "To view results:"
echo "  cat scan_results_*_hbbs*.csv"
echo "  cat scan_results_*_hbbr*.csv"
echo ""
