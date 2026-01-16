@echo off
REM RustDesk Server Scanner - Parallel Scan (HBBS and HBBR)
REM This script runs both scans in parallel using START command

setlocal

if "%1"=="" (
    echo Usage: scan-rustdesk-parallel.bat [host_range]
    echo.
    echo Examples:
    echo   scan-rustdesk-parallel.bat 192.168.1.1-254
    echo   scan-rustdesk-parallel.bat 10.0.0.0/24
    echo   scan-rustdesk-parallel.bat 116.62.8.4
    goto :eof
)

set HOST=%1
set TIMESTAMP=%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

echo ========================================================
echo RustDesk Server Scanner (Parallel Mode)
echo ========================================================
echo Target: %HOST%
echo Start Time: %date% %time%
echo.

echo Starting parallel scans...
echo.

REM Start HBBS scan in background
start /B go-protocol-detector --protocol=rustdesk-hbbs --host=%HOST% --port=21116 --thread=20 --timeout=3000

REM Start HBBR scan in background
start /B go-protocol-detector --protocol=rustdesk-hbbr --host=%HOST% --port=21117 --thread=20 --timeout=3000

echo.
echo Both scans started. Waiting for completion...
echo.

REM Wait for a moment to ensure scans complete
timeout /t 10 /nobreak >nul

echo.
echo ========================================================
echo Scans Complete!
echo ========================================================
echo.
echo Results saved to CSV files with timestamp: %TIMESTAMP%
echo.

endlocal
