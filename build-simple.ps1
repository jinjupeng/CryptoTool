# CryptoTool MSI Builder Script (Simplified)
# This script helps build MSI packages locally using WiX toolset

param(
    [Parameter(Mandatory=$false)]
    [string]$Configuration = "Release",
    
    [Parameter(Mandatory=$false)]
    [string]$Version = $null
)

# Get version from csproj if not provided
if ([string]::IsNullOrEmpty($Version)) {
    try {
        [xml]$csproj = Get-Content "CryptoTool.Win\CryptoTool.Win.csproj"
        $versionElement = $csproj.Project.PropertyGroup | Where-Object { $_.Version -ne $null } | Select-Object -First 1
        if ($versionElement -and $versionElement.Version) {
            $Version = $versionElement.Version.Trim()
        }
        if ([string]::IsNullOrEmpty($Version)) {
            $Version = "1.0.0"
        }
    }
    catch {
        $Version = "1.0.0"
        Write-Warning "Could not read version from csproj, using default: $Version"
    }
}

Write-Host "Building CryptoTool MSI package version: $Version" -ForegroundColor Green

# Check if WiX is installed
try {
    $wixVersion = wix --version 2>$null
    if ($wixVersion -like "*6.*") {
        Write-Host "WiX version: $wixVersion" -ForegroundColor Yellow
        Write-Warning "WiX v6 detected. MSI creation may require different syntax."
        Write-Host "Continuing with executable creation only..." -ForegroundColor Yellow
        $createMsi = $false
    } else {
        Write-Host "WiX version: $wixVersion" -ForegroundColor Yellow
        $createMsi = $true
    }
}
catch {
    Write-Warning "WiX toolset not found. Continuing with executable creation only."
    Write-Host "To install WiX, run: dotnet tool install --global wix" -ForegroundColor Yellow
    $createMsi = $false
}

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
dotnet clean CryptoTool.sln --configuration $Configuration --verbosity quiet

# Build the application first
Write-Host "Building application..." -ForegroundColor Yellow
dotnet build CryptoTool.sln --configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

# Publish the application
Write-Host "Publishing application..." -ForegroundColor Yellow
$publishPath = "./publish/CryptoTool.Win-SelfContained"

# Remove existing publish directory
if (Test-Path $publishPath) {
    Remove-Item $publishPath -Recurse -Force
}

# Publish with explicit settings to avoid PDB issues
dotnet publish CryptoTool.Win\CryptoTool.Win.csproj `
    --configuration $Configuration `
    --runtime win-x64 `
    --self-contained true `
    --output $publishPath `
    -p:PublishSingleFile=true `
    -p:PublishTrimmed=false `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:Version="$Version" `
    -p:AssemblyVersion="$Version.0" `
    -p:FileVersion="$Version.0"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Publish failed"
    exit 1
}

# Check if executable exists and rename it
$oldExe = Join-Path $publishPath "CryptoTool.Win.exe"
$newExeName = "CryptoTool-v$Version-win-x64-SelfContained.exe"
$newExe = Join-Path $publishPath $newExeName

if (Test-Path $oldExe) {
    try {
        Move-Item $oldExe $newExe -Force
        Write-Host "Renamed executable to: $newExe" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to rename executable: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Error "Published executable not found at: $oldExe"
    # List what files are actually in the publish directory
    Write-Host "Files in publish directory:"
    if (Test-Path $publishPath) {
        Get-ChildItem $publishPath | ForEach-Object { Write-Host "  $($_.Name)" }
    }
    exit 1
}

# Also publish framework-dependent version
Write-Host "Publishing framework-dependent version..." -ForegroundColor Yellow
$publishPathFx = "./publish/CryptoTool.Win-FrameworkDependent"

# Remove existing publish directory
if (Test-Path $publishPathFx) {
    Remove-Item $publishPathFx -Recurse -Force
}

dotnet publish CryptoTool.Win\CryptoTool.Win.csproj `
    --configuration $Configuration `
    --runtime win-x64 `
    --self-contained false `
    --output $publishPathFx `
    -p:PublishSingleFile=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:Version="$Version" `
    -p:AssemblyVersion="$Version.0" `
    -p:FileVersion="$Version.0"

if ($LASTEXITCODE -eq 0) {
    $oldExeFx = Join-Path $publishPathFx "CryptoTool.Win.exe"
    $newExeNameFx = "CryptoTool-v$Version-win-x64-FrameworkDependent.exe"
    $newExeFx = Join-Path $publishPathFx $newExeNameFx
    
    if (Test-Path $oldExeFx) {
        Move-Item $oldExeFx $newExeFx -Force
        Write-Host "Created framework-dependent version: $newExeFx" -ForegroundColor Green
    }
}

# Create ZIP packages
Write-Host "Creating ZIP packages..." -ForegroundColor Yellow

$zipSelfContained = "CryptoTool-v$Version-SelfContained-$Configuration.zip"
$zipFrameworkDependent = "CryptoTool-v$Version-FrameworkDependent-$Configuration.zip"

if (Test-Path $zipSelfContained) { Remove-Item $zipSelfContained -Force }
if (Test-Path $zipFrameworkDependent) { Remove-Item $zipFrameworkDependent -Force }

if (Test-Path $publishPath) {
    Compress-Archive -Path "$publishPath\*" -DestinationPath $zipSelfContained
    Write-Host "Created ZIP: $zipSelfContained" -ForegroundColor Green
}

if (Test-Path $publishPathFx) {
    Compress-Archive -Path "$publishPathFx\*" -DestinationPath $zipFrameworkDependent
    Write-Host "Created ZIP: $zipFrameworkDependent" -ForegroundColor Green
}

# Skip MSI creation if WiX is not compatible
if (!$createMsi) {
    Write-Host ""
    Write-Host "MSI creation skipped due to WiX compatibility issues." -ForegroundColor Yellow
    Write-Host "Executable and ZIP packages have been created successfully." -ForegroundColor Green
} else {
    Write-Host "MSI creation would be attempted here, but skipped for now." -ForegroundColor Yellow
}

# Show summary
Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Cyan
Write-Host "  Version: $Version" -ForegroundColor White
Write-Host "  Configuration: $Configuration" -ForegroundColor White
Write-Host "  Self-contained executable: $newExe" -ForegroundColor White
if (Test-Path $newExeFx) {
    Write-Host "  Framework-dependent executable: $newExeFx" -ForegroundColor White
}
Write-Host "  ZIP packages created" -ForegroundColor White

$totalSize = 0
if (Test-Path $newExe) { $totalSize += (Get-Item $newExe).Length }
if (Test-Path $zipSelfContained) { $totalSize += (Get-Item $zipSelfContained).Length }

Write-Host "  Total size: $([math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor White

Write-Host ""
Write-Host "Build process completed successfully!" -ForegroundColor Green