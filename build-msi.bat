@echo off
echo Building CryptoTool MSI package...
echo.

REM Check if PowerShell is available
where powershell >nul 2>nul
if %errorlevel% neq 0 (
    echo PowerShell not found! Please install PowerShell.
    pause
    exit /b 1
)

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "build-msi.ps1" %*

echo.
echo Press any key to continue...
pause >nul