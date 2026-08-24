# Run with: powershell -NoProfile -ExecutionPolicy Bypass -File tests/p0_checksum.ps1
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("sagy-checksum-" + [guid]::NewGuid().ToString("N"))
$source = Join-Path $root "source"
$zip = Join-Path $root "release.zip"
$installer = Join-Path (Split-Path -Parent $PSScriptRoot) "install.ps1"
New-Item -ItemType Directory -Force -Path $source | Out-Null
Set-Content -Path (Join-Path $source "sagy.exe") -Value "test binary" -Encoding ascii
[System.IO.Compression.ZipFile]::CreateFromDirectory($source, $zip)
$asset = "sagy-v1.0.0-x86_64-pc-windows-msvc.zip"
$hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLowerInvariant()

function Invoke-WebRequest {
    param(
        [string]$Uri,
        [string]$OutFile,
        [switch]$UseBasicParsing,
        [int]$TimeoutSec
    )
    if ($env:FAKE_SUMS_MODE -eq "archive-timeout") {
        throw "fake archive timeout"
    }
    if ($Uri -like "*SHA256SUMS.txt") {
        switch ($env:FAKE_SUMS_MODE) {
            "checksum-timeout" { throw "fake checksum timeout" }
            "http-error" { throw "fake HTTP 404" }
            "empty" { Set-Content -Path $OutFile -Value "" -NoNewline }
            "missing" { Set-Content -Path $OutFile -Value ("{0}  other.zip" -f $hash) }
            "duplicate" { Set-Content -Path $OutFile -Value (("{0}  {1}`n{0}  {1}" -f $hash, $asset)) }
            "malformed" { Set-Content -Path $OutFile -Value ("not-a-hash  {0}" -f $asset) }
            "mismatch" { Set-Content -Path $OutFile -Value (("{0}  {1}" -f ("0" * 64), $asset)) }
            "valid" { Set-Content -Path $OutFile -Value ("{0}  {1}" -f $hash, $asset) }
            default { throw "unknown fake checksum mode" }
        }
    } else {
        Copy-Item -Path $zip -Destination $OutFile -Force
    }
}

try {
    Set-Variable -Name HOME -Scope Global -Value $root
    foreach ($mode in @("archive-timeout", "checksum-timeout", "http-error", "empty", "missing", "duplicate", "malformed", "mismatch")) {
        $home = Join-Path $root $mode
        $env:SAGY_HOME = Join-Path $home ".sagy"
        $env:FAKE_SUMS_MODE = $mode
        $failed = $false
        try { . $installer -Repo "test/repo" -Version "v1.0.0" } catch { $failed = $true }
        if (-not $failed) { throw "installer unexpectedly succeeded for $mode" }
        if (Test-Path (Join-Path $home ".sagy/bin/sagy.exe")) {
            throw "installer copied binary for failed checksum mode $mode"
        }
        if (Get-ChildItem -Path (Join-Path $home ".sagy/tmp") -Filter "sagy.exe" -Recurse -ErrorAction SilentlyContinue) {
            throw "installer extracted binary for failed checksum mode $mode"
        }
    }

    $home = Join-Path $root "valid"
    $env:SAGY_HOME = Join-Path $home ".sagy"
    $env:FAKE_SUMS_MODE = "valid"
    . $installer -Repo "test/repo" -Version "v1.0.0"
    if (-not (Test-Path (Join-Path $home ".sagy/bin/sagy.exe"))) {
        throw "valid checksum was not installed"
    }
    Write-Host "PowerShell checksum harness passed."
} finally {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
}
