@echo off
setlocal

echo CryptoTool Version Management
echo =============================
echo.

if "%~1"=="" (
    echo Usage: bump-version.bat [version] [options]
    echo.
    echo Options:
    echo   -tag    Create git tag
    echo   -push   Push tag to origin
    echo.
    echo Examples:
    echo   bump-version.bat 1.2.3
    echo   bump-version.bat 1.2.3 -tag
    echo   bump-version.bat 1.2.3 -tag -push
    echo.
    pause
    exit /b 1
)

set VERSION=%1
set CREATE_TAG=false
set PUSH_TAG=false

:parse_args
shift
if "%~1"=="" goto :done_parsing
if /i "%~1"=="-tag" set CREATE_TAG=true
if /i "%~1"=="-push" set PUSH_TAG=true
goto :parse_args

:done_parsing

echo Updating to version: %VERSION%
echo Create tag: %CREATE_TAG%
echo Push tag: %PUSH_TAG%
echo.

REM Check if PowerShell is available
where powershell >nul 2>nul
if %errorlevel% neq 0 (
    echo PowerShell not found! Please install PowerShell.
    pause
    exit /b 1
)

REM Build PowerShell command
set PS_COMMAND=.\bump-version.ps1 -NewVersion "%VERSION%"
if "%CREATE_TAG%"=="true" set PS_COMMAND=%PS_COMMAND% -CreateTag
if "%PUSH_TAG%"=="true" set PS_COMMAND=%PS_COMMAND% -PushTag

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -Command "%PS_COMMAND%"

echo.
echo Press any key to continue...
pause >nul