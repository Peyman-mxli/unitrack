<#
Re-connect C:\unitrack after a privacy-driven Git history rewrite.
Creates a fresh clone while preserving the prior checkout as a local backup.
Never commits, deletes, or uploads photographs, databases, or secrets.
Run after stopping Flask (Ctrl+C).
#>
param(
    [string]$ProjectRoot = "C:\unitrack",
    [switch]$SkipStart
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Git([string[]]$Arguments) {
    & git @Arguments
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed." }
}
$repo = "https://github.com/Peyman-mxli/unitrack.git"
$original = [System.IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
$parent = Split-Path $original -Parent
$name = Split-Path $original -Leaf
if (-not (Test-Path -LiteralPath (Join-Path $original ".git") -PathType Container)) {
    throw "Original UniTrack checkout not found at $original"
}
Push-Location $original
try {
    # Do not silently discard user edits. We keep the entire old checkout,
    # but require a clean working tree before switching locations.
    $status = @(& git status --porcelain)
    if ($LASTEXITCODE -ne 0) { throw "Unable to read the current Git status." }
    if ($status.Count -gt 0) {
        throw "Local Git changes exist. They must be backed up or committed before reconnecting. No files were changed."
    }
} finally { Pop-Location }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$fresh = Join-Path $parent "$name-clean-$stamp"
$archived = Join-Path $parent "$name-history-backup-$stamp"
if ((Test-Path $fresh) -or (Test-Path $archived)) {
    throw "A backup directory already exists. No files were changed."
}

Write-Host "Cloning current clean Git history..." -ForegroundColor Cyan
Invoke-Git @("clone", "--branch", "main", "--single-branch", $repo, $fresh)

$preserve = @(
    ".unitrack-secret",
    ".env",
    ".env.local",
    "unitrack.db",
    "instance",
    "backups",
    "app\static\uploads",
    "app\static\img\profiles",
    "app\routes\static\uploads",
    "private_uploads"
)
foreach ($relative in $preserve) {
    $src = Join-Path $original $relative
    $dest = Join-Path $fresh $relative
    if (-not (Test-Path -LiteralPath $src)) { continue }
    if (Test-Path -LiteralPath $src -PathType Container) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $src "*") -Destination $dest -Recurse -Force -ErrorAction Stop
    } else {
        New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop
    }
}

# Check all files in preserved directories, not just directory existence.
foreach ($relative in $preserve) {
    $src = Join-Path $original $relative
    $dest = Join-Path $fresh $relative
    if (-not (Test-Path -LiteralPath $src)) { continue }
    if (-not (Test-Path -LiteralPath $dest)) {
        throw "Backup verification failed: $relative. Original checkout untouched."
    }
    if (Test-Path -LiteralPath $src -PathType Container) {
        $sourceFiles = @(Get-ChildItem -LiteralPath $src -File -Recurse -Force)
        foreach ($photo in $sourceFiles) {
            $subpath = $photo.FullName.Substring($src.Length).TrimStart([char[]]@('\', '/'))
            $copy = Join-Path $dest $subpath
            if ((-not (Test-Path -LiteralPath $copy -PathType Leaf)) -or
                ((Get-Item -LiteralPath $copy).Length -ne $photo.Length)) {
                throw "Backup verification failed for $relative. Original checkout untouched."
            }
        }
    } elseif ((Get-Item -LiteralPath $src).Length -ne (Get-Item -LiteralPath $dest).Length) {
        throw "Backup verification failed for $relative. Original checkout untouched."
    }
}

# Rename rather than deleting anything. If the second move fails, recover.
Move-Item -LiteralPath $original -Destination $archived -ErrorAction Stop
try {
    Move-Item -LiteralPath $fresh -Destination $original -ErrorAction Stop
} catch {
    Move-Item -LiteralPath $archived -Destination $original -ErrorAction Stop
    throw
}
Write-Host "Clean UniTrack history installed at $original" -ForegroundColor Green
Write-Host "Your previous checkout is SAFE at $archived" -ForegroundColor Yellow
Write-Host "Database, configuration and upload folders have been preserved." -ForegroundColor Green

Set-Location $original
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    & py -3.11 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11 is required; prior checkout backup remains safe." }
}
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency install failed; prior checkout backup remains safe." }
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
if ($LASTEXITCODE -ne 0) { throw "Tests failed; prior checkout backup remains safe." }
if (-not $SkipStart) {
    & .\.venv\Scripts\python.exe run.py
}
