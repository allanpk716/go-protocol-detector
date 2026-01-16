# RustDesk Server Scanner - PowerShell Script with Result Aggregation
# Usage: .\scan-rustdesk.ps1 -Host "192.168.1.1-254" [-OutputDir "results"]

param(
    [Parameter(Mandatory=$true)]
    [string]$Host,

    [string]$OutputDir = ".\results",

    [int]$Threads = 20,

    [int]$Timeout = 3000
)

$ErrorActionPreference = "Continue"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "RustDesk Server Scanner (PowerShell)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Target: $Host"
Write-Host "Output: $OutputDir"
Write-Host "Threads: $Threads"
Write-Host "Timeout: ${Timeout}ms"
Write-Host ""

# Run HBBS scan
Write-Host "Scanning HBBS (port 21116)..." -ForegroundColor Yellow
$HBBSJob = Start-Job -ScriptBlock {
    param($Host, $Threads, $Timeout)
    .\go-protocol-detector.exe --protocol=rustdesk-hbbs --host=$Host --port=21116 --thread=$Threads --timeout=$Timeout
} -ArgumentList $Host, $Threads, $Timeout

# Run HBBR scan
Write-Host "Scanning HBBR (port 21117)..." -ForegroundColor Yellow
$HBBRJob = Start-Job -ScriptBlock {
    param($Host, $Threads, $Timeout)
    .\go-protocol-detector.exe --protocol=rustdesk-hbbr --host=$Host --port=21117 --thread=$Threads --timeout=$Timeout
} -ArgumentList $Host, $Threads, $Timeout

# Wait for both jobs
Write-Host ""
Write-Host "Waiting for scans to complete..." -ForegroundColor Green

$HBBSResult = Receive-Job -Job $HBBSJob -Wait
$HBBRResult = Receive-Job -Job $HBBRJob -Wait

Remove-Job -Job $HBBSJob
Remove-Job -Job $HBBRJob

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Scan Complete!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Display summary
Write-Host "HBBS Scan Results:" -ForegroundColor Yellow
Write-Host $HBBSResult
Write-Host ""

Write-Host "HBBR Scan Results:" -ForegroundColor Yellow
Write-Host $HBBRResult
Write-Host ""

# Find and organize CSV files
$CSVFiles = Get-ChildItem -Path . -Filter "scan_results_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 2

if ($CSVFiles) {
    Write-Host "CSV files generated:" -ForegroundColor Green
    $CSVFiles | ForEach-Object { Write-Host "  $($_.Name)" }
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
