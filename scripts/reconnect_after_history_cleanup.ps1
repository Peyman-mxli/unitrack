<#
Safely connect to UniTrack's rewritten Git history WITHOUT renaming C:\unitrack.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File $script -ProjectRoot "C:\unitrack"

Windows and VS Code can lock a working directory, so this script never moves,
deletes, rebases, resets, or modifies the original checkout. It makes a fresh
sibling checkout, transfers locally-held app state, verifies it, and starts
the fresh project. The original checkout and all local edits remain intact.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\unitrack",
    [string]$DestinationRoot = "",
    [switch]$SkipStart
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-ExitCode([string]$Label) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed (exit $LASTEXITCODE). Original project remains untouched."
    }
}
function Copy-DirectoryContents([string]$Source, [string]$Destination) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $Source -Force)) {
        Copy-Item -LiteralPath $item.FullName -Destination $Destination -Force -Recurse -ErrorAction Stop
    }
}
function Test-CopiedFiles([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "Copy verification failed (missing destination). Original unchanged."
    }
    if (Test-Path -LiteralPath $Source -PathType Container) {
        foreach ($item in @(Get-ChildItem -LiteralPath $Source -File -Recurse -Force)) {
            $sub = $item.FullName.Substring($Source.Length).TrimStart([char[]]@('\', '/'))
            $copy = Join-Path $Destination $sub
            if (-not (Test-Path -LiteralPath $copy -PathType Leaf) -or
                (Get-Item -LiteralPath $copy).Length -ne $item.Length) {
                throw "Copied file verification failed: $sub. Original unchanged."
            }
        }
    } elseif ((Get-Item -LiteralPath $Source).Length -ne (Get-Item -LiteralPath $Destination).Length) {
        throw "Copied file verification failed. Original unchanged."
    }
}

$original = [System.IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
$parent = Split-Path $original -Parent
$name = Split-Path $original -Leaf
if (-not (Test-Path -LiteralPath (Join-Path $original ".git") -PathType Container) -or
    -not (Test-Path -LiteralPath (Join-Path $original "run.py") -PathType Leaf)) {
    throw "UniTrack project does not exist at $original. Nothing changed."
}
if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
    $DestinationRoot = Join-Path $parent ($name + "-reconnected")
}
$dest = [System.IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\')
if ([String]::Equals($dest, $original, [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $dest)) {
    throw "Destination is already in use: $dest. Nothing changed. Specify a new -DestinationRoot."
}
$originUrl = (& git -C $original remote get-url origin).Trim()
Assert-ExitCode "Checking Git origin"
if ($originUrl -notmatch '^((https://github\.com/)|(git@github\.com:))Peyman-mxli/unitrack(\.git)?$') {
    throw "Unexpected Git origin. Refusing to copy account data to an untrusted checkout."
}
$dirty = @(& git -C $original status --porcelain --untracked-files=normal)
Assert-ExitCode "Checking existing local changes"
Write-Host "Existing project stays at $original (including $($dirty.Count) local changes)." -ForegroundColor Yellow
Write-Host "New clean project will be $dest. Windows directory locks cannot block the switch." -ForegroundColor Cyan

# Git clone is public-code-only; never publish or commit personal data.
& git clone --branch main --single-branch "https://github.com/Peyman-mxli/unitrack.git" $dest
Assert-ExitCode "Cloning clean UniTrack history"

$preserve = @(
    ".unitrack-secret", ".env", ".env.local",
    "instance", "backups",
    "app\static\uploads", "app\static\img\profiles",
    "app\routes\static\uploads", "private_uploads"
)
foreach ($relative in $preserve) {
    $source = Join-Path $original $relative
    if (-not (Test-Path -LiteralPath $source)) { continue }
    $target = Join-Path $dest $relative
    if (Test-Path -LiteralPath $source -PathType Container) {
        Copy-DirectoryContents $source $target
    } else {
        New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop
    }
    Test-CopiedFiles $source $target
    Write-Host "Preserved $relative" -ForegroundColor Green
}

$sourceDb = Join-Path $original "unitrack.db"
$targetDb = Join-Path $dest "unitrack.db"
if (-not (Test-Path -LiteralPath $sourceDb -PathType Leaf)) {
    throw "Existing unitrack.db missing. Refusing to start a blank project. Original unchanged."
}
# Unlike Copy-Item, the SQLite backup API captures WAL transactions safely.
# This also refuses corrupted databases and verifies the transferred snapshot.
$python = Join-Path $original ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Existing Python environment missing: $python. Original unchanged."
}
$backupCode = @'
import sqlite3, sys
from contextlib import closing
from pathlib import Path
source_path, target_path = map(Path, sys.argv[1:3])
if not source_path.is_file() or target_path.exists():
    raise SystemExit("Source missing or destination already exists; refusing overwrite.")
with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source:
    if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("Original database failed integrity_check.")
    with closing(sqlite3.connect(str(target_path))) as dest:
        source.backup(dest, pages=128, sleep=0.05)
with closing(sqlite3.connect(target_path.as_uri() + "?mode=ro", uri=True)) as snapshot:
    if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("Transferred database failed integrity_check.")
    count = snapshot.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    if count < 1:
        raise SystemExit("Database has no tables; refusing to start a blank installation.")
print("Verified SQLite snapshot:", target_path, "(" + str(count) + " tables)")
'@
$backupRunner = Join-Path $env:TEMP ("unitrack-reconnect-db-" + [Guid]::NewGuid().ToString("N") + ".py")
try {
    [System.IO.File]::WriteAllText($backupRunner, $backupCode, (New-Object System.Text.UTF8Encoding($false)))
    & $python $backupRunner $sourceDb $targetDb
    Assert-ExitCode "Verified SQLite transfer"
} finally {
    if (Test-Path -LiteralPath $backupRunner) {
        Remove-Item -LiteralPath $backupRunner -Force
    }
}
if ($dirty.Count -gt 0) {
    $inventory = Join-Path $dest "LOCAL-CHANGES-FROM-OLD-CHECKOUT.txt"
    $lines = @(
        "Existing project remains intact at: $original",
        "Old code edits were not auto-merged into the clean checkout.",
        "Review changes in the original folder before manually transferring.",
        ""
    ) + $dirty
    [System.IO.File]::WriteAllLines($inventory, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
}

Write-Host "Installing dependencies into the new project..." -ForegroundColor Cyan
Push-Location $dest
try {
    & py -3.11 -m venv .venv
    Assert-ExitCode "Creating new virtual environment"
    $freshPython = Join-Path $dest ".venv\Scripts\python.exe"
    & $freshPython -m pip install -r requirements.txt
    Assert-ExitCode "Installing dependencies"
    & $freshPython scripts/database_health.py --schema
    Assert-ExitCode "Checking database integrity and schema"
    & $freshPython -m unittest discover -s tests -v
    Assert-ExitCode "Running isolated tests"
    Write-Host "SUCCESS: New UniTrack project: $dest" -ForegroundColor Green
    Write-Host "Original with every local change: $original" -ForegroundColor Yellow
    Write-Host "Open this new folder in VS Code: $dest" -ForegroundColor Cyan
    if (-not $SkipStart) {
        & $freshPython run.py
        Assert-ExitCode "Running UniTrack"
    }
} finally {
    Pop-Location
}
