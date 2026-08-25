# sagy Windows PowerShell Installer
param(
    [string]$Repo = "lauzhihao/sagy",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

# 下载体积上限（字节）。超时只能挡住"慢"，挡不住"大"，因此每条下载都必须显式限量，
# 超限一律 fail-closed。数值与 install.sh / src/core/update.rs 保持一致：
# - metadata: GitHub releases/latest 的 JSON 实测在 10KB 量级，1MiB 留出百倍余量。
# - sums: SHA256SUMS.txt 每行约 100 字节，一次 release 至多十几个 asset，64KiB 绰绰有余。
# - archive: 当前 release job 产出的最大归档在 10MB 量级，128MiB 用于防止无界下载撑爆磁盘。
$MaxMetadataBytes = 1048576
$MaxSumsBytes = 65536
$MaxArchiveBytes = 134217728

function Assert-SafeReleaseComponent {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]*\z' -or $Value -eq "." -or $Value -eq "..") {
        throw "Unsafe ${Label}: ${Value}"
    }
}

# 体积上限的语义在三条安装路径上并不完全一致，这是有意保留的（R7-4.3）：
# - src/core/update.rs：流式读取，读满上限即截断，进程内存永远不超过上限。
# - install.sh：curl --max-filesize 在服务端声明 Content-Length 时于传输中止；
#   没有声明时事后按 %{size_download} 复核，因此最坏情况也会先落一份超限文件。
# - install.ps1：只能"整份落盘之后再量"。Invoke-WebRequest -OutFile 没有任何
#   体积上限参数，Windows PowerShell 5.1 也没有可直接使用的流式下载 cmdlet；
#   改写成 System.Net.Http.HttpClient 手工分块读取能对齐语义，但本仓库没有
#   任何可以在提交前执行 PowerShell 的开发环境（唯一的执行证据是 CI 的
#   windows job），盲改一条下载主路径引入的风险高于它消除的风险。
# 残余风险与缓解：超限响应会先占用磁盘，最多到实际传输量为止；文件落在本次安装
#   专属的 GUID 工作目录里，finally 无条件删除；并且在 Assert-DownloadedFile
#   通过之前，它不会被解压、参与校验、或复制进 $InstallBin。
function Assert-DownloadedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Limit,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $info = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($info.Length -le 0) {
        throw "$Label is empty: $Path"
    }
    if ($info.Length -gt $Limit) {
        throw "$Label exceeded the $Limit byte download limit ($($info.Length) bytes): $Path"
    }
}

if ($Repo -notmatch '\A[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\z') {
    throw "Unsafe GitHub repository name: $Repo"
}
$repoParts = $Repo.Split('/')
if ($repoParts[0] -in @('.', '..') -or $repoParts[1] -in @('.', '..')) {
    throw "Unsafe GitHub repository name: $Repo"
}
if ($Version) {
    Assert-SafeReleaseComponent -Value $Version -Label "release version"
}

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

# 每次安装使用独立的一次性工作目录：固定的 $TmpRoot 里残留的旧 sagy.exe
# 会让下一次安装的完整性守卫 fail-open，把上一个版本当成新版本装上。
# GUID 目录名同时保证并发执行的两个 installer 不会互相覆盖临时文件。
$WorkDir = Join-Path $TmpRoot ("install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

try {
    if (-not $Version) {
        $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
        $metadataPath = Join-Path $WorkDir "release-latest.json"
        Invoke-WebRequest -Uri $apiUrl -OutFile $metadataPath -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
        Assert-DownloadedFile -Path $metadataPath -Limit $MaxMetadataBytes -Label "Release metadata"
        $Version = (Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json).tag_name
    }
    Assert-SafeReleaseComponent -Value $Version -Label "release version"

    $assetName = "sagy-$Version-x86_64-pc-windows-msvc.zip"
    Assert-SafeReleaseComponent -Value $assetName -Label "release asset name"
    $downloadUrl = "https://github.com/$Repo/releases/download/$Version/$assetName"
    $zipPath = Join-Path $WorkDir $assetName
    $sumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS.txt"
    $sumsPath = Join-Path $WorkDir "SHA256SUMS.txt"
    $targetExe = Join-Path $InstallBin "sagy.exe"

    Write-Host "Downloading $downloadUrl..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
    Assert-DownloadedFile -Path $zipPath -Limit $MaxArchiveBytes -Label "Downloaded archive"

    # Verify SHA256 Checksum
    Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
    Assert-DownloadedFile -Path $sumsPath -Limit $MaxSumsBytes -Label "Checksum manifest"
    if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
        throw "Checksum verification requires Get-FileHash."
    }
    $seenFiles = @{}
    $expectedHash = $null
    $sumLines = (Get-Content -LiteralPath $sumsPath -Raw) -split "`r?`n"
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
        if ($file -notmatch '\A[A-Za-z0-9._-]+\z') {
            throw "Unsafe checksum target in $sumsPath"
        }
        $seenFiles[$file] = $true
        if ($file -ceq $assetName) {
            $expectedHash = $hash
        }
    }
    if ($null -eq $expectedHash) {
        throw "Checksum entry for $assetName is missing"
    }
    $hashResult = Get-FileHash -LiteralPath $zipPath -Algorithm SHA256 -ErrorAction Stop
    if ($null -eq $hashResult -or $hashResult.Hash -notmatch '\A[0-9A-Fa-f]{64}\z') {
        throw "Hash tool returned an invalid SHA-256 digest."
    }
    $actualHash = $hashResult.Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 checksum mismatch for $assetName! Expected: $expectedHash, got: $actualHash"
    }
    Write-Host "Checksum verified: $expectedHash"

    # 解压到本次安装专属的空目录，任何残留都不可能被误当成本次归档的产物。
    $extractDir = Join-Path $WorkDir "extract"
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
    $extractedExe = Join-Path $extractDir "sagy.exe"

    if (-not (Test-Path -LiteralPath $extractedExe -PathType Leaf)) {
        throw "Release archive did not contain a top-level sagy.exe binary."
    }
    $extractedInfo = Get-Item -LiteralPath $extractedExe -ErrorAction Stop
    if ($extractedInfo.PSIsContainer -or $extractedInfo.Length -le 0) {
        throw "Release archive contained an empty or invalid sagy.exe binary."
    }
    Copy-Item -LiteralPath $extractedExe -Destination $targetExe -Force

    # 清理旧版本安装的模型别名二进制
    foreach ($legacy in @("flash", "pro", "think")) {
        $legacyFile = "$legacy.exe"
        $legacyPath = Join-Path $InstallBin $legacyFile
        if (Test-Path $legacyPath) {
            Remove-Item $legacyPath -Force
            Write-Host "Removed legacy model alias $legacyPath"
        }
    }

    # Install sagy-original passthrough wrapper for Windows cmd/powershell.
    # sagy-original resolution order: AGY_BIN -> ~/.gemini/antigravity-cli/bin/agy -> PATH agy.
    # 供应商自带的安装位置优先于 PATH，因为 PATH 上的 agy 可能是别的 wrapper 或别名，
    # 会造成回环调用；install.sh 保持同一顺序。
    $originalWrapperCmd = Join-Path $InstallBin "sagy-original.cmd"
    @"
@echo off
if defined AGY_BIN (
    "%AGY_BIN%" %*
    exit /b %ERRORLEVEL%
)
if exist "%USERPROFILE%\.gemini\antigravity-cli\bin\agy.cmd" (
    "%USERPROFILE%\.gemini\antigravity-cli\bin\agy.cmd" %*
    exit /b %ERRORLEVEL%
)
where agy >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    agy %*
    exit /b %ERRORLEVEL%
)
echo agy not found in PATH or ~/.gemini/antigravity-cli/bin/agy.cmd 1>&2
exit /b 1
"@ | Out-File -FilePath $originalWrapperCmd -Encoding ascii -Force

    # Post-install auto import of existing ~/.gemini credentials.
    # 安装后动作不得吞掉失败：把子命令的输出原样转给用户，并让脚本退出码如实反映结果。
    $geminiDir = Join-Path $HOME ".gemini"
    if (Test-Path $geminiDir) {
        $importLog = Join-Path $WorkDir "import-known.log"
        # 子进程往 stderr 写字节不等于失败；判据只有退出码，所以这里临时放开
        # ErrorActionPreference，避免把普通日志误判成终止性错误。
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $targetExe import-known > $importLog 2>&1
            $importExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousPreference
        }
        if ($importExitCode -ne 0) {
            Write-Host "Install failed: '$targetExe import-known' exited with status $importExitCode."
            if (Test-Path -LiteralPath $importLog -PathType Leaf) {
                Get-Content -LiteralPath $importLog | ForEach-Object { Write-Host $_ }
            }
            throw "Post-install credential import failed with status $importExitCode."
        }
        Write-Host "Imported current Antigravity credentials into sagy state."
    }

    Write-Host "sagy installed successfully to $targetExe"
    Write-Host "Binaries: sagy, sagy-original"
    Write-Host "Please ensure '$InstallBin' is in your PATH."
}
finally {
    # 成功与失败路径都必须把一次性工作目录清理干净。
    Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}
