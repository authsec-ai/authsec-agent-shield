# AuthSec Agent Shield — one-click installer for Windows
# Usage (from elevated PowerShell):
#   irm https://get.authsec.ai/shield.ps1 | iex
#   or: .\install.ps1
#   or: $env:CLIENT_ID="xxx"; $env:TENANT="my.authsec.ai"; .\install.ps1

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ClientId    = $env:CLIENT_ID,
    [string]$Tenant      = $env:TENANT,
    [string]$JwtToken    = $env:JWT_TOKEN,
    [string]$UserEmail   = $env:USER_EMAIL,
    [string]$InstallDir  = "$env:ProgramFiles\AuthSec\Shield",
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BINARY = "authsec-shield.exe"
$REPO   = "authsec-ai/authsec-agent-shield"

# ── colors ──────────────────────────────────────────────────────────────────
function Write-Info  { param([string]$m) Write-Host "[shield] $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "[shield] $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "[shield] WARN $m" -ForegroundColor Yellow }
function Write-Die   { param([string]$m) Write-Host "[shield] ERROR $m" -ForegroundColor Red; exit 1 }
function Write-Hdr   { param([string]$m) Write-Host "`n$m" -ForegroundColor White }

# ── elevation check ──────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator. Re-launching elevated..."
    $argList = @("-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($ClientId)  { $argList += "-ClientId `"$ClientId`"" }
    if ($Tenant)    { $argList += "-Tenant `"$Tenant`"" }
    if ($JwtToken)  { $argList += "-JwtToken `"$JwtToken`"" }
    Start-Process powershell -ArgumentList $argList -Verb RunAs -Wait
    exit
}

Write-Hdr "AuthSec Agent Shield — Installer (Windows)"
Write-Host "  Install dir: $InstallDir"
Write-Host ""

# ── detect arch ─────────────────────────────────────────────────────────────
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$asset = "authsec-shield-windows-$arch.exe"

# ── Step 1: download binary ──────────────────────────────────────────────────
Write-Hdr "Step 1/4: Downloading binary"

$tmpDir = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
New-Item -ItemType Directory -Path $tmpDir | Out-Null
$tmpBin = Join-Path $tmpDir $BINARY

$downloaded = $false
try {
    $releaseInfo = Invoke-RestMethod "https://api.github.com/repos/$REPO/releases/latest" -ErrorAction SilentlyContinue
    $version = $releaseInfo.tag_name
    if ($version) {
        $url = "https://github.com/$REPO/releases/download/$version/$asset"
        Write-Info "Downloading version $version..."
        Invoke-WebRequest -Uri $url -OutFile $tmpBin -UseBasicParsing
        $downloaded = $true
        Write-Ok "Downloaded $version"
    }
} catch {
    Write-Warn "GitHub download failed: $_"
}

# Fallback: build from source if in source tree
if (-not $downloaded) {
    $goMod = Join-Path (Split-Path $PSCommandPath) "go.mod"
    if ((Test-Path $goMod) -and (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Info "Building from source..."
        Push-Location (Split-Path $PSCommandPath)
        go build -o $tmpBin .\cmd\shield\
        Pop-Location
        $downloaded = $true
        Write-Ok "Built from source"
    } else {
        Write-Die "Cannot download binary and Go is not available. Download manually from https://github.com/$REPO/releases"
    }
}

# ── Step 2: install binary ───────────────────────────────────────────────────
Write-Hdr "Step 2/4: Installing binary to $InstallDir"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$installPath = Join-Path $InstallDir $BINARY
Copy-Item -Force $tmpBin $installPath
Remove-Item -Recurse -Force $tmpDir

# Add to system PATH if not already there
$sysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($sysPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$sysPath;$InstallDir", "Machine")
    $env:Path += ";$InstallDir"
    Write-Ok "Added to system PATH"
}
Write-Ok "Installed: $installPath"

# ── Step 3: login / configure ────────────────────────────────────────────────
Write-Hdr "Step 3/4: Authentication"

$configDir = "$env:LOCALAPPDATA\authsec-shield"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

if ($JwtToken -and $ClientId -and $Tenant) {
    Write-Info "Non-interactive mode: writing config directly..."
    $sshPath   = "$env:USERPROFILE\.ssh"   -replace '\\', '\\'
    $awsPath   = "$env:USERPROFILE\.aws"   -replace '\\', '\\'
    $kubePath  = "$env:USERPROFILE\.kube"  -replace '\\', '\\'
    $confPath  = "$env:USERPROFILE\.config" -replace '\\', '\\'
    $configJson = @"
{
  "client_id": "$ClientId",
  "tenant_domain": "$Tenant",
  "access_token": "$JwtToken",
  "user_email": "$UserEmail",
  "enabled": true,
  "risk_threshold": 30,
  "auto_approve_read": true,
  "protected_paths": [
    "$sshPath",
    "$awsPath",
    "$kubePath",
    "$confPath",
    "C:\\Windows",
    "C:\\Program Files"
  ]
}
"@
    $configJson | Set-Content -Path "$configDir\config.json" -Encoding UTF8
    Write-Ok "Config written (non-interactive)"
} else {
    Write-Info "Starting device login flow..."
    Write-Host ""
    Write-Host "  You will need:"
    Write-Host "    * Your AuthSec client ID (from your tenant admin)"
    Write-Host "    * Your AuthSec tenant domain (e.g., mycompany.authsec.ai)"
    Write-Host ""
    try {
        & $installPath login
    } catch {
        Write-Warn "Login failed or skipped. Run 'authsec-shield login' to complete."
    }
}

# ── Step 4: install kernel driver (AuthSecShield.sys) ────────────────────────
Write-Hdr "Step 4/5: Installing kernel driver (process + filesystem monitor)"

$driverDir = Join-Path (Split-Path $PSCommandPath) "kernel\windows\minifilter"
$sysFile   = Join-Path $InstallDir "AuthSecShield.sys"

if (Test-Path $driverDir) {
    # Pre-built .sys should be packaged alongside the installer in releases.
    # For source builds, user must build with WDK: msbuild AuthSecShield.sln /p:Configuration=Release
    $prebuiltSys = Join-Path $driverDir "AuthSecShield.sys"
    if (Test-Path $prebuiltSys) {
        Copy-Item -Force $prebuiltSys $sysFile
        # Register the driver service
        $scArgs = @("create", "AuthSecShield",
                    "type=", "kernel",
                    "start=", "auto",
                    "binpath=", $sysFile,
                    "displayname=", "AuthSec Agent Shield Filter")
        sc.exe @scArgs 2>$null | Out-Null
        sc.exe description AuthSecShield "AuthSec Agent Shield - intercepts all process creations and file writes for AI safety" 2>$null | Out-Null
        # Load via fltMC (filter manager)
        try {
            fltMC load AuthSecShield 2>$null | Out-Null
            Write-Ok "Kernel driver loaded: AuthSecShield.sys"
            Write-Ok "ALL process executions and file writes are now intercepted"
        } catch {
            Write-Warn "Driver load failed (may need system restart or test-signing enabled): $_"
        }
    } else {
        Write-Warn "AuthSecShield.sys not found — skipping kernel driver install"
        Write-Warn "To build: open kernel\windows\minifilter\AuthSecShield.sln in Visual Studio with WDK"
        Write-Info "Process monitoring will use bridge-only mode (less secure)"
    }
} else {
    Write-Warn "Kernel driver source not found — skipping"
}

# ── Step 5: install shims + hooks + filesystem protection ────────────────────
Write-Hdr "Step 5/5: Installing OS protections"

try {
    & $installPath install
} catch {
    Write-Warn "Install step had errors: $_"
    Write-Warn "Run 'authsec-shield doctor --fix' to repair."
}

# ── done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "AuthSec Agent Shield installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Commands:"
Write-Host "    authsec-shield status          - show current state"
Write-Host "    authsec-shield doctor          - health check"
Write-Host "    authsec-shield doctor --fix    - auto-repair installation"
Write-Host "    authsec-shield pause 1h        - pause for 1 hour"
Write-Host "    authsec-shield enable          - re-enable"
Write-Host "    authsec-shield uninstall       - remove everything"
Write-Host ""
Write-Host "  Open a new PowerShell window to pick up PATH changes." -ForegroundColor Yellow
Write-Host ""
