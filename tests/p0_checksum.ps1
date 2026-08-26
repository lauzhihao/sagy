# Windows installer fail-closed harness.
# Run with: pwsh -NoProfile -ExecutionPolicy Bypass -File tests/p0_checksum.ps1
#
# 每个场景都在**独立子进程**里跑 install.ps1，因此可以断言真正的进程退出码，
# 而不只是"抛没抛异常"。每个场景都预先放一份 sentinel 二进制，
# 用来证明失败路径既不安装也不覆盖已有二进制（INSTALL-002 / CI-001）。

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot "install.ps1"
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("sagy-checksum-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $root | Out-Null

$psName = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }
$psExe = Join-Path $PSHOME $psName
if (-not (Test-Path -LiteralPath $psExe)) {
    $psExe = Join-Path $PSHOME "$psName.exe"
}

$sentinel = "previous version sentinel"
$asset = "sagy-v1.0.0-x86_64-pc-windows-msvc.zip"

# 正常归档：顶层含 sagy.exe。若调用方提供了真实构建产物就用它，否则退回文本占位。
$source = Join-Path $root "source"
New-Item -ItemType Directory -Force -Path $source | Out-Null
if ($env:SAGY_TEST_BINARY) {
    # 设了却指不到文件，说明 CI 的构建步骤没跑或路径写错了。
    # 静默退回文本占位会让成功路径只证明"能装上一个文本文件"，必须直接失败。
    if (-not (Test-Path -LiteralPath $env:SAGY_TEST_BINARY -PathType Leaf)) {
        throw "SAGY_TEST_BINARY points at a missing file: $($env:SAGY_TEST_BINARY)"
    }
    Copy-Item -LiteralPath $env:SAGY_TEST_BINARY -Destination (Join-Path $source "sagy.exe") -Force
} else {
    Set-Content -Path (Join-Path $source "sagy.exe") -Value "test binary" -Encoding ascii
}
$fixtureHash = (Get-FileHash -LiteralPath (Join-Path $source "sagy.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
$zip = Join-Path $root "release.zip"
Compress-Archive -Path (Join-Path $source "*") -DestinationPath $zip -Force
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()

# 缺少顶层 sagy.exe 的归档：完整性守卫必须 fail-closed。
$badSource = Join-Path $root "bad-source"
$badNested = Join-Path $badSource "nested"
New-Item -ItemType Directory -Force -Path $badNested | Out-Null
Set-Content -Path (Join-Path $badNested "sagy.exe") -Value "nested binary" -Encoding ascii
$badZip = Join-Path $root "release-missing-binary.zip"
Compress-Archive -Path $badNested -DestinationPath $badZip -Force
$badHash = (Get-FileHash -LiteralPath $badZip -Algorithm SHA256).Hash.ToLowerInvariant()

# 子进程里注入的 mock：只替换网络与 hash 工具探测，其余逻辑全部走真实 install.ps1。
$mockScript = @'
param(
    [string]$Installer,
    [string]$SandboxHome,
    [string]$Zip,
    [string]$BadZip,
    [string]$Hash,
    [string]$BadHash,
    [string]$Asset,
    [string]$Version
)

$ErrorActionPreference = "Stop"
$env:GEMINI_HOME = Join-Path $SandboxHome ".gemini"

function Get-ModeHash {
    if ($env:FAKE_SUMS_MODE -eq "missing-binary") { return $BadHash }
    return $Hash
}

function Write-Text {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text)
}

function Invoke-WebRequest {
    param(
        [string]$Uri,
        [string]$OutFile,
        [switch]$UseBasicParsing,
        [int]$TimeoutSec
    )
    $mode = $env:FAKE_SUMS_MODE
    if ($Uri -like "*api.github.com*") {
        switch ($mode) {
            "metadata-timeout" { throw "fake metadata timeout" }
            "metadata-oversize" {
                $padding = "pad" * 500000
                Write-Text -Path $OutFile -Text ('{"tag_name": "v1.0.0", "body": "' + $padding + '"}')
            }
            default { Write-Text -Path $OutFile -Text '{"tag_name": "v1.0.0"}' }
        }
        return
    }
    if ($Uri -like "*SHA256SUMS.txt") {
        $modeHash = Get-ModeHash
        switch ($mode) {
            "checksum-timeout" { throw "fake checksum timeout" }
            "http-error" { throw "fake HTTP 404 for SHA256SUMS.txt" }
            "empty" { Write-Text -Path $OutFile -Text "" }
            "missing" { Write-Text -Path $OutFile -Text ("{0}  other.zip`n" -f $modeHash) }
            "duplicate" { Write-Text -Path $OutFile -Text ("{0}  {1}`n{0}  {1}`n" -f $modeHash, $Asset) }
            "malformed" { Write-Text -Path $OutFile -Text ("not-a-hash  {0}`n" -f $Asset) }
            "mismatch" { Write-Text -Path $OutFile -Text ("{0}  {1}`n" -f ("0" * 64), $Asset) }
            "unsafe-target" { Write-Text -Path $OutFile -Text ("{0}  ../{1}`n" -f $modeHash, $Asset) }
            "sums-oversize" {
                $builder = New-Object System.Text.StringBuilder
                [void]$builder.AppendFormat("{0}  {1}`n", $modeHash, $Asset)
                for ($i = 0; $i -lt 2000; $i++) {
                    [void]$builder.AppendFormat("{0}  padding-{1}.txt`n", $modeHash, $i)
                }
                Write-Text -Path $OutFile -Text $builder.ToString()
            }
            default { Write-Text -Path $OutFile -Text ("{0}  {1}`n" -f $modeHash, $Asset) }
        }
        return
    }
    switch ($mode) {
        "archive-timeout" { throw "fake archive timeout" }
        "empty-archive" { Write-Text -Path $OutFile -Text "" }
        "missing-binary" { Copy-Item -LiteralPath $BadZip -Destination $OutFile -Force }
        default { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
    }
}

function Get-Command {
    param(
        [Parameter(Position = 0)][string]$Name,
        [string]$ErrorAction
    )
    if ($env:FAKE_SUMS_MODE -eq "no-hash-tool" -and $Name -eq "Get-FileHash") {
        return $null
    }
    return (Microsoft.PowerShell.Core\Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

$requestedVersion = if ($Version -eq "none") { "" } else { $Version }
. $Installer -Repo "test/repo" -Version $requestedVersion
exit 0
'@

$mockPath = Join-Path $root "mock-install.ps1"
Set-Content -LiteralPath $mockPath -Value $mockScript -Encoding ascii

function Invoke-InstallerScenario {
    param(
        [string]$Mode,
        [string]$SandboxHome,
        [string]$RequestedVersion
    )
    $logPath = Join-Path $root ("$Mode.log")
    $env:FAKE_SUMS_MODE = $Mode
    $env:SAGY_HOME = Join-Path $SandboxHome ".sagy"
    # 子进程写 stderr 不等于失败，判据只有退出码，所以这里必须临时放开
    # ErrorActionPreference；PowerShell 7.4 起 native 命令的非零退出码在 Stop
    # 之下会直接抛异常，那样连"退出码是几"都拿不到。
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # $LASTEXITCODE 是会话级变量：子进程万一没启动起来，它会保留上一次的值，
    # 让"退出码非 0"的断言变成 fail-open。先清空，取不到就直接判失败。
    Set-Variable -Name LASTEXITCODE -Scope Global -Value $null
    try {
        & $psExe -NoProfile -ExecutionPolicy Bypass -File $mockPath `
            -Installer $Installer -SandboxHome $SandboxHome `
            -Zip $zip -BadZip $badZip -Hash $hash -BadHash $badHash `
            -Asset $asset -Version $RequestedVersion *> $logPath
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($null -eq $code) {
        throw "installer scenario ${Mode} never produced an exit code; the harness could not run ${psExe}"
    }
    $log = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { "" }
    return [pscustomobject]@{ ExitCode = $code; Log = $log }
}

function New-Sandbox {
    param([string]$Name)
    $sandbox = Join-Path $root $Name
    $installBin = Join-Path $sandbox ".sagy/bin"
    New-Item -ItemType Directory -Force -Path $installBin | Out-Null
    Set-Content -LiteralPath (Join-Path $installBin "sagy.exe") -Value $sentinel -Encoding ascii
    return $sandbox
}

function Assert-TempRootIsClean {
    param([string]$Sandbox, [string]$Context)
    $tmpRoot = Join-Path $Sandbox ".sagy/tmp"
    if (-not (Test-Path -LiteralPath $tmpRoot)) {
        return
    }
    $leftovers = @(Get-ChildItem -LiteralPath $tmpRoot -Force -ErrorAction SilentlyContinue)
    if ($leftovers.Count -ne 0) {
        throw "installer left temp entries for ${Context}: $($leftovers.Name -join ', ')"
    }
}

$failClosedModes = @(
    "metadata-timeout",
    "metadata-oversize",
    "archive-timeout",
    "empty-archive",
    "checksum-timeout",
    "http-error",
    "empty",
    "missing",
    "duplicate",
    "malformed",
    "mismatch",
    "unsafe-target",
    "sums-oversize",
    "no-hash-tool",
    "missing-binary"
)

try {
    foreach ($mode in $failClosedModes) {
        $sandbox = New-Sandbox -Name $mode
        $targetExe = Join-Path $sandbox ".sagy/bin/sagy.exe"
        $requestedVersion = if ($mode -like "metadata-*") { "none" } else { "v1.0.0" }
        $result = Invoke-InstallerScenario -Mode $mode -SandboxHome $sandbox -RequestedVersion $requestedVersion

        if ($result.ExitCode -eq 0) {
            throw "installer exited 0 for ${mode}:`n$($result.Log)"
        }
        $current = (Get-Content -LiteralPath $targetExe -Raw).Trim()
        if ($current -ne $sentinel) {
            throw "installer replaced the existing binary on the fail-closed path for ${mode}"
        }
        Assert-TempRootIsClean -Sandbox $sandbox -Context $mode
    }

    $sandbox = New-Sandbox -Name "valid"
    $targetExe = Join-Path $sandbox ".sagy/bin/sagy.exe"
    $result = Invoke-InstallerScenario -Mode "valid" -SandboxHome $sandbox -RequestedVersion "v1.0.0"
    if ($result.ExitCode -ne 0) {
        throw "valid checksum was rejected:`n$($result.Log)"
    }
    if (-not (Test-Path -LiteralPath $targetExe -PathType Leaf)) {
        throw "valid checksum was not installed"
    }
    if ((Get-FileHash -LiteralPath $targetExe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $fixtureHash) {
        throw "valid install did not replace the sentinel with the archived binary"
    }
    Assert-TempRootIsClean -Sandbox $sandbox -Context "valid"

    # 版本解析走 metadata 时也必须能成功装上。
    $sandbox = New-Sandbox -Name "valid-metadata"
    $targetExe = Join-Path $sandbox ".sagy/bin/sagy.exe"
    $result = Invoke-InstallerScenario -Mode "valid" -SandboxHome $sandbox -RequestedVersion "none"
    if ($result.ExitCode -ne 0) {
        throw "resolved release metadata was rejected:`n$($result.Log)"
    }
    if ((Get-FileHash -LiteralPath $targetExe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $fixtureHash) {
        throw "metadata resolved install did not land the archived binary"
    }
    Assert-TempRootIsClean -Sandbox $sandbox -Context "valid-metadata"

    Write-Host "PowerShell checksum harness passed."
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

# 走到这里说明全部场景都通过了。显式 exit 0，让"退出码 0"只有这一个来源。
exit 0
