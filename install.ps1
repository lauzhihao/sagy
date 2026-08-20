# sagy Windows PowerShell Installer
param(
    [string]$Repo = "lauzhihao/sagy",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

$SagyHome = if ($env:SAGY_HOME) { $env:SAGY_HOME } else { Join-Path $HOME ".sagy" }
$InstallBin = Join-Path $SagyHome "bin"
$TmpRoot = Join-Path $SagyHome "tmp"

if (-not (Test-Path $InstallBin)) {
    New-Item -ItemType Directory -Force -Path $InstallBin | Out-Null
}
if (-not (Test-Path $TmpRoot)) {
    New-Item -ItemType Directory -Force -Path $TmpRoot | Out-Null
}

if (-not $Version) {
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
    $Version = $response.tag_name
}

$assetName = "sagy-$Version-x86_64-pc-windows-msvc.zip"
$downloadUrl = "https://github.com/$Repo/releases/download/$Version/$assetName"
$zipPath = Join-Path $TmpRoot $assetName

Write-Host "Downloading $downloadUrl..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

# Verify SHA256 Checksum
$sumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS.txt"
$sumsPath = Join-Path $TmpRoot "SHA256SUMS.txt"
try {
    Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing -TimeoutSec 15
    if (Test-Path $sumsPath) {
        $expectedHash = (Get-Content $sumsPath | Select-String $assetName | ForEach-Object { ($_ -split '\s+')[0] })
        if ($expectedHash) {
            $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
            if ($actualHash -ne $expectedHash.ToLower()) {
                throw "SHA-256 checksum mismatch for $assetName! Expected: $expectedHash, got: $actualHash"
            }
            Write-Host "Checksum verified: $expectedHash"
        }
    }
} catch {
    Write-Warning "Checksum verification skipped or failed: $_"
}

Expand-Archive -Path $zipPath -DestinationPath $TmpRoot -Force
$extractedExe = Join-Path $TmpRoot "sagy.exe"
$targetExe = Join-Path $InstallBin "sagy.exe"

Copy-Item $extractedExe $targetExe -Force

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
