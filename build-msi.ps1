# CryptoTool MSI Builder Script
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
    Write-Host "WiX version: $wixVersion" -ForegroundColor Yellow
}
catch {
    Write-Error "WiX toolset not found. Please install WiX using: dotnet tool install --global wix"
    exit 1
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
    Get-ChildItem $publishPath | ForEach-Object { Write-Host "  $($_.Name)" }
    exit 1
}

# Create installer directory
$installerDir = "./installer"
if (!(Test-Path $installerDir)) {
    New-Item -Path $installerDir -ItemType Directory -Force
}

# Generate WiX source file
Write-Host "Generating WiX configuration..." -ForegroundColor Yellow

# Convert to absolute path for WiX
$absoluteExePath = (Get-Item $newExe).FullName

# Generate a GUID for the package
$packageGuid = [System.Guid]::NewGuid().ToString().ToUpper()

$wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Id="*" Name="CryptoTool" Language="1033" Version="$Version" Manufacturer="jinjupeng" UpgradeCode="12345678-1234-1234-1234-123456789012">
    <SummaryInformation Keywords="Installer" Description="CryptoTool 加解密工具安装程序" Manufacturer="jinjupeng" />
    
    <MajorUpgrade DowngradeErrorMessage="已安装更新版本的 [ProductName]。" />
    <MediaTemplate EmbedCab="yes" />
    
    <Feature Id="ProductFeature" Title="CryptoTool" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
    
    <Property Id="WIXUI_INSTALLDIR" Value="INSTALLFOLDER" />
    <UIRef Id="WixUI_InstallDir" />
    
    <StandardDirectory Id="ProgramFilesFolder">
      <Directory Id="INSTALLFOLDER" Name="CryptoTool">
        <Component Id="MainExecutable">
          <File Id="CryptoToolExe" Source="$absoluteExePath" KeyPath="yes">
            <Shortcut Id="ApplicationStartMenuShortcut" Directory="ProgramMenuFolder" Name="CryptoTool" Description="CryptoTool 加解密工具" WorkingDirectory="INSTALLFOLDER" Icon="CryptoTool.exe" IconIndex="0" Advertise="yes" />
            <Shortcut Id="ApplicationDesktopShortcut" Directory="DesktopFolder" Name="CryptoTool" Description="CryptoTool 加解密工具" WorkingDirectory="INSTALLFOLDER" Icon="CryptoTool.exe" IconIndex="0" Advertise="yes" />
          </File>
        </Component>
      </Directory>
    </StandardDirectory>
    
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <ComponentRef Id="MainExecutable" />
    </ComponentGroup>
    
    <Icon Id="CryptoTool.exe" SourceFile="$absoluteExePath" />
  </Package>
</Wix>
"@

$wxsPath = "$installerDir\CryptoTool.wxs"
$wxsContent | Out-File -FilePath $wxsPath -Encoding UTF8
Write-Host "WiX configuration saved to: $wxsPath" -ForegroundColor Green

# Build MSI
Write-Host "Building MSI package..." -ForegroundColor Yellow
$msiPath = ".\CryptoTool-v$Version-win-x64-Setup.msi"

# Remove existing MSI
if (Test-Path $msiPath) {
    Remove-Item $msiPath -Force
}

try {
    $wixResult = wix build $wxsPath -o $msiPath 2>&1
    
    if (Test-Path $msiPath) {
        Write-Host "MSI package created successfully: $msiPath" -ForegroundColor Green
        
        # Get file size
        $fileSize = (Get-Item $msiPath).Length / 1MB
        Write-Host "File size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Yellow
        
        # Show summary
        Write-Host ""
        Write-Host "Build Summary:" -ForegroundColor Cyan
        Write-Host "  Version: $Version" -ForegroundColor White
        Write-Host "  Configuration: $Configuration" -ForegroundColor White
        Write-Host "  Executable: $newExe" -ForegroundColor White
        Write-Host "  MSI Package: $msiPath" -ForegroundColor White
        Write-Host "  Package Size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor White
    }
    else {
        Write-Error "MSI package was not created"
        Write-Host "WiX output:" -ForegroundColor Red
        $wixResult | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
}
catch {
    Write-Error "Failed to create MSI package: $($_.Exception.Message)"
    Write-Host "WiX error details may be available above" -ForegroundColor Yellow
}

Write-Host "Build process completed!" -ForegroundColor Green