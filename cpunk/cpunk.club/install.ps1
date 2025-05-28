# CPUNK Network Installation Script for Windows
# This script installs the CPUNK network configuration for Cellframe node

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CPUNK Network Installation Script for Windows" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator. Exiting..." -ForegroundColor Red
    Exit 1
}

# Set paths
$cellframePath = "C:\Program Files\cellframe-node"
$cellframeDocsPath = "C:\Users\Public\Documents\cellframe-node"

# Check if Cellframe node is installed
if (-NOT (Test-Path $cellframePath)) {
    Write-Host "Cellframe node not found. Installing..." -ForegroundColor Yellow
    
    # Download installer
    $installerUrl = "https://pub.cellframe.net/windows/5.2-stable/cellframe-node-5.2-14817-amd64.exe"
    $installerPath = "$env:TEMP\cellframe-installer.exe"
    
    Write-Host "Downloading Cellframe node installer..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
    
    Write-Host "Running installer..."
    Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
    
    # Wait for installation to complete
    Start-Sleep -Seconds 10
    
    if (-NOT (Test-Path $cellframePath)) {
        Write-Host "Installation failed. Please install Cellframe node manually." -ForegroundColor Red
        Exit 1
    }
}

Write-Host "Cellframe node found. Installing CPUNK network..." -ForegroundColor Green

# Create directories
$networkPath = "$cellframeDocsPath\etc\network\Cpunk"
$caPath = "$cellframeDocsPath\share\ca"

if (-NOT (Test-Path $networkPath)) {
    New-Item -ItemType Directory -Path $networkPath -Force | Out-Null
}
if (-NOT (Test-Path $caPath)) {
    New-Item -ItemType Directory -Path $caPath -Force | Out-Null
}

# Download configuration files
Write-Host "Downloading configuration files..." -ForegroundColor Yellow

try {
    Invoke-WebRequest -Uri "https://cpunk.club/configs/Cpunk.cfg" -OutFile "$cellframeDocsPath\etc\network\Cpunk.cfg"
    Invoke-WebRequest -Uri "https://cpunk.club/configs/chain-0.cfg" -OutFile "$networkPath\chain-0.cfg"
    Invoke-WebRequest -Uri "https://cpunk.club/configs/main.cfg" -OutFile "$networkPath\main.cfg"
} catch {
    Write-Host "Failed to download configuration files: $_" -ForegroundColor Red
    Exit 1
}

# Download certificates
Write-Host "Downloading certificates..." -ForegroundColor Yellow

try {
    for ($i = 0; $i -le 2; $i++) {
        Invoke-WebRequest -Uri "https://cpunk.club/certs/cpunk.root.$i.dcert" -OutFile "$caPath\cpunk.root.$i.dcert"
        Invoke-WebRequest -Uri "https://cpunk.club/certs/cpunk.master.$i.dcert" -OutFile "$caPath\cpunk.master.$i.dcert"
    }
} catch {
    Write-Host "Failed to download certificates: $_" -ForegroundColor Red
    Exit 1
}

# Restart the node service
Write-Host "Restarting Cellframe node..." -ForegroundColor Yellow

try {
    Restart-Service -Name "Cellframe Node" -Force -ErrorAction Stop
} catch {
    Write-Host "Warning: Could not restart service automatically. Please restart manually." -ForegroundColor Yellow
}

# Wait for node to start
Start-Sleep -Seconds 5

# Verify installation
Write-Host ""
Write-Host "Verifying installation..." -ForegroundColor Yellow

$cliPath = "$cellframePath\cellframe-node-cli.exe"
if (Test-Path $cliPath) {
    $networks = & $cliPath net list 2>$null
    
    if ($networks -match "Cpunk") {
        Write-Host ""
        Write-Host "✅ SUCCESS! CPUNK network has been installed." -ForegroundColor Green
        Write-Host ""
        Write-Host "You can now use the following commands:" -ForegroundColor Cyan
        Write-Host "  - Check network status: & '$cliPath' net get status -net Cpunk"
        Write-Host "  - Get sync status: & '$cliPath' net get sync_status -net Cpunk"
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "⚠️  WARNING: CPUNK network not found in network list." -ForegroundColor Yellow
        Write-Host "Please restart the Cellframe Node service manually and check again." -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "CLI not found. Please verify installation manually." -ForegroundColor Yellow
}

Write-Host "Installation complete!" -ForegroundColor Green