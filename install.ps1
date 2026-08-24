# sagy Windows PowerShell Installer
param(
    [string]$Repo = "lauzhihao/sagy",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

$SagyHome = if ($env:SAGY_HOME) { $env:SAGY_HOME } else { Join-Path $HOME ".sagy" }
$InstallBin = Join-Path $SagyHome "bin"
$TmpRoot = Join-Path $SagyHome "tmp"
$DownloadTimeoutSec = if ($env:SAGY_DOWNLOAD_TIMEOUT_SEC) { [int]$env:SAGY_DOWNLOAD_TIMEOUT_SEC } else { 120 }
if ($DownloadTimeoutSec -le 0) {
    throw "SAGY_DOWNLOAD_TIMEOUT_SEC must be a positive number"
}

if (-not (Test-Path $InstallBin)) {
    New-Item -ItemType Directory -Force -Path $InstallBin | Out-Null
}
if (-not (Test-Path $TmpRoot)) {
    New-Item -ItemType Directory -Force -Path $TmpRoot | Out-Null
}

if (-not $Version) {
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
    $Version = $response.tag_name
}

$assetName = "sagy-$Version-x86_64-pc-windows-msvc.zip"
$downloadUrl = "https://github.com/$Repo/releases/download/$Version/$assetName"
$zipPath = Join-Path $TmpRoot $assetName

Write-Host "Downloading $downloadUrl..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec $DownloadTimeoutSec

# Verify SHA256 Checksum
$sumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS.txt"
$sumsPath = Join-Path $TmpRoot "SHA256SUMS.txt"
$null = Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
$seenFiles = @{}
$expectedHash = $null
$sumLines = (Get-Content -Path $sumsPath -Raw) -split "`r?`n"
foreach ($line in $sumLines) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }
    if ($line -notmatch '^\s*([0-9A-Fa-f]{64})\s+(\*?[^\s]+)\s*$') {
        throw "Malformed checksum entry in $sumsPath"
    }
    $hash = $Matches[1].ToLowerInvariant()
    $file = $Matches[2]
    if ($file.StartsWith('*')) {
        $file = $file.Substring(1)
    }
    if ([string]::IsNullOrEmpty($file) -or $seenFiles.ContainsKey($file)) {
        throw "Duplicate or empty checksum target in $sumsPath"
    }
    $seenFiles[$file] = $true
    if ($file -ceq $assetName) {
        $expectedHash = $hash
    }
}
if ($null -eq $expectedHash) {
    throw "Checksum entry for $assetName is missing"
}
$actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "SHA-256 checksum mismatch for $assetName! Expected: $expectedHash, got: $actualHash"
}
Write-Host "Checksum verified: $expectedHash"

Expand-Archive -Path $zipPath -DestinationPath $TmpRoot -Force
$extractedExe = Join-Path $TmpRoot "sagy.exe"
$targetExe = Join-Path $InstallBin "sagy.exe"

Copy-Item $extractedExe $targetExe -Force

# 清理旧版本安装的模型别名二进制
foreach ($legacy in @("flash", "pro", "think")) {
    $legacyFile = "$legacy.exe"
    $legacyPath = Join-Path $InstallBin $legacyFile
    if (Test-Path $legacyPath) {
        Remove-Item $legacyPath -Force
        Write-Host "Removed legacy model alias $legacyPath"
    }
}

# Install sagy-original passthrough wrapper for Windows cmd/powershell
$originalWrapperCmd = Join-Path $InstallBin "sagy-original.cmd"
@"
@echo off
if defined AGY_BIN (
    "%AGY_BIN%" %*
    exit /b %ERRORLEVEL%
)
where agy >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    agy %*
    exit /b %ERRORLEVEL%
)
if exist "%USERPROFILE%\.gemini\antigravity-cli\bin\agy.cmd" (
    "%USERPROFILE%\.gemini\antigravity-cli\bin\agy.cmd" %*
    exit /b %ERRORLEVEL%
)
echo agy not found in PATH or ~/.gemini/antigravity-cli/bin/agy.cmd 1>&2
exit /b 1
"@ | Out-File -FilePath $originalWrapperCmd -Encoding ascii -Force

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

# Post-install auto import of existing ~/.gemini credentials
$geminiDir = Join-Path $HOME ".gemini"
if (Test-Path $geminiDir) {
    try {
        & $targetExe import-known *>$null
        Write-Host "Imported current Antigravity credentials into sagy state."
    } catch {
        Write-Host "Installed sagy, but auto-importing current credentials skipped."
    }
}

Write-Host "sagy installed successfully to $targetExe"
Write-Host "Binaries: sagy, sagy-original"
Write-Host "Please ensure '$InstallBin' is in your PATH."
