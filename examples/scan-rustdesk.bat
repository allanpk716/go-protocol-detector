@echo off
REM RustDesk Server Scanner - Scan both HBBS and HBBR
REM Usage: scan-rustdesk.bat [host] [output_prefix]
REM Example: scan-rustdesk.bat 192.168.1.1-254 results

setlocal

if "%1"=="" (
    echo Usage: scan-rustdesk.bat [host_range] [output_prefix]
    echo.
    echo Examples:
    echo   scan-rustdesk.bat 192.168.1.1-254 scan
    echo   scan-rustdesk.bat 10.0.0.0/24 results
    echo   scan-rustdesk.bat 116.62.8.4 single
    goto :eof
)

set HOST=%1
set PREFIX=%2
if "%PREFIX%"=="" set PREFIX=rustdesk_scan

echo ========================================================
echo RustDesk Server Scanner
echo ========================================================
echo Target: %HOST%
echo Output Prefix: %PREFIX%
echo.
echo Scanning HBBS (port 21116)...
go-protocol-detector --protocol=rustdesk-hbbs --host=%HOST% --port=21116 --thread=20 --timeout=3000

echo.
echo Scanning HBBR (port 21117)...
go-protocol-detector --protocol=rustdesk-hbbr --host=%HOST% --port=21117 --thread=20 --timeout=3000

echo.
echo ========================================================
echo Scan Complete!
echo ========================================================
echo HBBS results: scan_results_*_hbbs*.csv
echo HBBR results: scan_results_*_hbbr*.csv
echo.
echo To view results:
echo   type scan_results_*_hbbs*.csv
echo   type scan_results_*_hbbr*.csv
echo.

endlocal
