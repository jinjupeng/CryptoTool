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

# Create main publish directory
$mainPublishPath = "./publish"
if (!(Test-Path $mainPublishPath)) {
    New-Item -Path $mainPublishPath -ItemType Directory -Force
}

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
$publishPath = "$mainPublishPath/CryptoTool.Win-SelfContained"

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
$publishPathFx = "$mainPublishPath/CryptoTool.Win-FrameworkDependent"

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

# Create ZIP packages in publish directory
Write-Host "Creating ZIP packages..." -ForegroundColor Yellow

$zipSelfContained = "$mainPublishPath/CryptoTool-v$Version-SelfContained-$Configuration.zip"
$zipFrameworkDependent = "$mainPublishPath/CryptoTool-v$Version-FrameworkDependent-$Configuration.zip"

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

# Create MSI package in publish directory (if WiX is available)
if ($createMsi) {
    Write-Host "Creating MSI package..." -ForegroundColor Yellow
    
    # Create installer directory inside publish
    $installerDir = "$mainPublishPath/installer"
    if (!(Test-Path $installerDir)) {
        New-Item -Path $installerDir -ItemType Directory -Force
    }

    # Generate WiX source file
    Write-Host "Generating WiX configuration..." -ForegroundColor Yellow

    # Convert to absolute path for WiX
    $absoluteExePath = (Get-Item $newExe).FullName

    # Use a simple, reliable WiX configuration that works with WiX v4
    $wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Id="CryptoToolPackage" Name="CryptoTool" Language="1033" Version="$Version" Manufacturer="jinjupeng" UpgradeCode="12345678-1234-1234-1234-123456789012">
    <SummaryInformation Keywords="Installer" Description="CryptoTool Setup" Manufacturer="jinjupeng" />
    
    <MajorUpgrade DowngradeErrorMessage="A newer version of CryptoTool is already installed." />
    <MediaTemplate EmbedCab="yes" />
    
    <Feature Id="ProductFeature" Title="CryptoTool" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
    
    <StandardDirectory Id="ProgramFilesFolder">
      <Directory Id="INSTALLFOLDER" Name="CryptoTool">
        <Component Id="MainExecutable" Guid="*">
          <File Id="CryptoToolExe" Source="$absoluteExePath" KeyPath="yes">
            <Shortcut Id="ApplicationStartMenuShortcut" 
                     Directory="ProgramMenuFolder" 
                     Name="CryptoTool" 
                     Description="CryptoTool Application" 
                     WorkingDirectory="INSTALLFOLDER" 
                     Icon="CryptoTool.exe" 
                     IconIndex="0" />
            <Shortcut Id="ApplicationDesktopShortcut" 
                     Directory="DesktopFolder" 
                     Name="CryptoTool" 
                     Description="CryptoTool Application" 
                     WorkingDirectory="INSTALLFOLDER" 
                     Icon="CryptoTool.exe" 
                     IconIndex="0" />
          </File>
        </Component>
        
        <!-- Component for uninstall shortcut cleanup -->
        <Component Id="ApplicationShortcuts" Guid="*">
          <RemoveFolder Id="INSTALLFOLDER" On="uninstall" />
          <RegistryValue Root="HKCU" 
                        Key="Software\jinjupeng\CryptoTool" 
                        Name="installed" 
                        Type="integer" 
                        Value="1" 
                        KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>
    
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <ComponentRef Id="MainExecutable" />
      <ComponentRef Id="ApplicationShortcuts" />
    </ComponentGroup>
    
    <Icon Id="CryptoTool.exe" SourceFile="$absoluteExePath" />
  </Package>
</Wix>
"@

    $wxsPath = "$installerDir\CryptoTool.wxs"
    $wxsContent | Out-File -FilePath $wxsPath -Encoding UTF8
    Write-Host "WiX configuration saved to: $wxsPath" -ForegroundColor Green

    # Build MSI in publish directory
    $msiPath = "$mainPublishPath\CryptoTool-v$Version-win-x64-Setup.msi"

    # Remove existing MSI
    if (Test-Path $msiPath) {
        Remove-Item $msiPath -Force
    }

    try {
        Write-Host "Building MSI package..." -ForegroundColor Yellow
        
        $wixResult = wix build $wxsPath -o $msiPath 2>&1
        
        if (Test-Path $msiPath) {
            Write-Host "MSI package created successfully: $msiPath" -ForegroundColor Green
        } else {
            Write-Warning "MSI package creation failed"
            Write-Host "WiX output: $wixResult" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Failed to create MSI package: $($_.Exception.Message)"
    }
} else {
    Write-Host ""
    Write-Host "MSI creation skipped due to WiX compatibility issues." -ForegroundColor Yellow
}

# Show summary
Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Cyan
Write-Host "  Version: $Version" -ForegroundColor White
Write-Host "  Configuration: $Configuration" -ForegroundColor White
Write-Host "  Output directory: $mainPublishPath" -ForegroundColor White
Write-Host ""
Write-Host "Created files:" -ForegroundColor Cyan

# List all created files in publish directory
if (Test-Path $mainPublishPath) {
    Get-ChildItem $mainPublishPath -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring((Get-Item $mainPublishPath).FullName.Length + 1)
        $fileSize = [math]::Round($_.Length / 1KB, 1)
        Write-Host "  $relativePath ($fileSize KB)" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "Build process completed successfully!" -ForegroundColor Green
Write-Host "All output files are located in the '$mainPublishPath' directory." -ForegroundColor Green