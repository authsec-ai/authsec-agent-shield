$ErrorActionPreference = "Stop"
$env:AUTHSEC_SHIELD_ACTIVE = "1"

$shieldBin = Join-Path $PSScriptRoot "shield.exe"
if (-not (Test-Path $shieldBin)) {
    Write-Host "shield.exe not found in $PSScriptRoot"
    exit 1
}

# NOTE: git is NOT shimmed — it self-calls internally causing fork bombs.
# Git is protected via shell hooks + PATH wrappers instead.
$targets = @{
    "docker" = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    "az"     = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    "mysql"  = "C:\Program Files\MySQL\MySQL Server 9.2\bin\mysql.exe"
    "psql"   = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
}

foreach ($name in $targets.Keys) {
    $path = $targets[$name]
    $dir = Split-Path $path
    $base = [System.IO.Path]::GetFileNameWithoutExtension($path)
    $ext = [System.IO.Path]::GetExtension($path)
    $backup = Join-Path $dir ("." + $base + ".shield-real" + $ext)

    if (-not (Test-Path $path)) {
        Write-Host "  SKIP  $name - not found at $path"
        continue
    }

    if (Test-Path $backup) {
        Write-Host "  SKIP  $name - already shimmed (backup exists)"
        continue
    }

    try {
        Write-Host "  [$name] Taking ownership..."
        & takeown /f $path 2>&1 | Out-Null
        & takeown /f $dir 2>&1 | Out-Null
        & icacls $dir /grant ("${env:USERNAME}:(OI)(CI)F") /T /C /Q 2>&1 | Out-Null
        & icacls $path /grant ("${env:USERNAME}:F") /C /Q 2>&1 | Out-Null

        Write-Host "  [$name] Backing up original..."
        Move-Item $path $backup -Force

        Write-Host "  [$name] Writing shim..."
        # Use .NET directly to bypass any PowerShell hook or permission issue
        [System.IO.File]::Copy($shieldBin, $path, $true)

        Write-Host "  OK    $name"
    }
    catch {
        Write-Host ("  FAIL  $name - " + $_.Exception.Message)
        # Rollback
        if ((Test-Path $backup) -and (-not (Test-Path $path))) {
            Move-Item $backup $path -Force
            Write-Host "  [$name] Rolled back"
        }
    }
}

Write-Host ""
Write-Host "Done."
