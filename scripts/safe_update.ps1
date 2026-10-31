# UniTrack safe local update, Windows PowerShell 5.1+.
# Usage from C:\unitrack:  .\scripts\safe_update.ps1
# This script preserves the database, profile photos, virtual environments,
# local backups, and git stash, including when Git stops tracking old photo files. It refuses to update a dirty/diverged checkout.
[CmdletBinding()]
param([switch]$SkipStart)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Get-Location).Path
if (-not (Test-Path -LiteralPath (Join-Path $root 'run.py') -PathType Leaf)) {
    throw 'Open PowerShell in your UniTrack project folder before running this updater.'
}

function Fail([string]$message) {
    throw "UniTrack safe update stopped: $message"
}
function RunNative([string]$program, [string[]]$arguments) {
    & $program @arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$program exited with code $LASTEXITCODE"
    }
}

Write-Host 'UniTrack: checking repository and Python environment...' -ForegroundColor Cyan
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail 'Git is not installed or not on PATH.'
}
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    Fail "Expected the working .venv Python at $python. No environment was deleted."
}
RunNative $python @('-m', 'pip', 'show', 'flask', 'sqlalchemy')
Write-Host 'Python environment OK' -ForegroundColor Green

$branch = (& git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $branch -ne 'main') {
    Fail 'Expected the main branch; no changes were made.'
}
$origin = (& git remote get-url origin).Trim()
if ($LASTEXITCODE -ne 0 -or $origin -notmatch '^((https://github\.com/)|(git@github\.com:))Peyman-mxli/unitrack(\.git)?$') {
    Fail 'Unexpected Git origin. Check the repository before updating.'
}
& git diff --quiet --exit-code
if ($LASTEXITCODE -ne 0) {
    Fail 'Tracked files have local modifications; review them before pulling.'
}
& git diff --cached --quiet --exit-code
if ($LASTEXITCODE -ne 0) {
    Fail 'Staged changes are present; review them before pulling.'
}

# Backup is first, before pulling. SQLite online backup is safe even if a
# different process currently has the database open.
$db = Join-Path $root 'unitrack.db'
if (-not (Test-Path -LiteralPath $db -PathType Leaf)) {
    Fail 'The local unitrack.db was not found; refusing an update that could create a blank database.'
}
# Self-contained backup works even when the local checkout is older than the
# current remote repository. The backup happens BEFORE the git pull.
$backupCode = @'
from datetime import datetime
from pathlib import Path
import sqlite3

root = Path.cwd()
source = root / "unitrack.db"
destination_dir = root / "backups"
destination_dir.mkdir(exist_ok=True)
target = destination_dir / ("unitrack-before-update-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".db")
with sqlite3.connect(str(source), timeout=30) as original:
    with sqlite3.connect(str(target), timeout=30) as backup:
        original.backup(backup, pages=128, sleep=0.05)
        result = backup.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise RuntimeError("Backup failed integrity check: " + result)
print("Verified backup:", target)
'@
Write-Host 'Backing up and checking SQLite database...' -ForegroundColor Cyan
# Windows PowerShell 5.1 strips quotes from python -c arguments. Run the
# multi-line backup code as a temporary .py file to preserve it exactly.
$backupRunner = Join-Path $env:TEMP ("unitrack-backup-runner-" + [guid]::NewGuid().ToString('N') + ".py")
try {
    [System.IO.File]::WriteAllText(
        $backupRunner, $backupCode,
        (New-Object System.Text.UTF8Encoding($false))
    )
    RunNative $python @($backupRunner)
}
finally {
    if (Test-Path -LiteralPath $backupRunner) {
        Remove-Item -LiteralPath $backupRunner -Force
    }
}

# Copy local account images before git updates. Some old repository
# revisions tracked uploaded photos, so a pull may alter tracked paths.
# These are private local backups, never checked in to Git.
$photoBackup = Join-Path $root ('backups\\photos-before-update-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
foreach ($relativePath in @('app/static/uploads', 'app/static/img/profiles', 'app/routes/static/uploads', 'private_uploads')) {
    $source = Join-Path $root $relativePath
    if (Test-Path -LiteralPath $source -PathType Container) {
        $destination = Join-Path $photoBackup ($relativePath -replace '/', '\\')
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        $items = @(Get-ChildItem -LiteralPath $source -Force)
        foreach ($item in $items) {
            Copy-Item -LiteralPath $item.FullName -Destination $destination -Recurse -Force -ErrorAction Stop
        }
        Write-Host "Photo backup: $relativePath" -ForegroundColor Cyan
    }
}

# --ff-only prevents accidental merges, rebases, or overwriting local work.
Write-Host 'Pulling the latest verified main branch...' -ForegroundColor Cyan
RunNative 'git' @('pull', '--ff-only', 'origin', 'main')

# Never start against a corrupted database. This command reads the actual
# local SQLite file without changing tables, rows, indexes or schema.
# Print missing tables/columns as migration warnings, not automatic fixes.
Write-Host 'Auditing existing SQLite database without modifying records...' -ForegroundColor Cyan
RunNative $python @('scripts/database_health.py', '--database', $db, '--schema')

# IMPORTANT: older commits used to track account photos. When Git removes
# those tracked paths from the public repository, restore the local originals
# from the private backup above. Never overwrite a newer on-disk photo.
if (Test-Path -LiteralPath $photoBackup -PathType Container) {
    $restoredCount = 0
    $backedUpPhotos = @(Get-ChildItem -LiteralPath $photoBackup -File -Recurse -Force)
    foreach ($savedPhoto in $backedUpPhotos) {
        $relativePhotoPath = $savedPhoto.FullName.Substring($photoBackup.Length).TrimStart([char[]]@('\', '/'))
        if ([string]::IsNullOrWhiteSpace($relativePhotoPath)) {
            Fail 'Photo backup contained an invalid relative path.'
        }
        $targetPhoto = Join-Path $root $relativePhotoPath
        if (-not (Test-Path -LiteralPath $targetPhoto -PathType Leaf)) {
            $targetDirectory = Split-Path -Path $targetPhoto -Parent
            New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
            Copy-Item -LiteralPath $savedPhoto.FullName -Destination $targetPhoto -ErrorAction Stop
            $restoredCount++
        }
    }
    $remainingMissing = @(
        $backedUpPhotos | Where-Object {
            $relativePhotoPath = $_.FullName.Substring($photoBackup.Length).TrimStart([char[]]@('\', '/'))
            -not (Test-Path -LiteralPath (Join-Path $root $relativePhotoPath) -PathType Leaf)
        }
    )
    if ($remainingMissing.Count -gt 0) {
        Fail 'Some backed-up profile photos could not be restored. Backups were preserved.'
    }
    Write-Host "Profile photos verified; restored $restoredCount local originals after Git update." -ForegroundColor Green
}


Write-Host 'Installing required packages into .venv only...' -ForegroundColor Cyan
RunNative $python @('-m', 'pip', 'install', '-r', 'requirements.txt')

Write-Host 'Running isolated integration tests (never against unitrack.db)...' -ForegroundColor Cyan
RunNative $python @('-m', 'unittest', 'discover', '-s', 'tests', '-v')

Write-Host 'UniTrack updated; database, uploads and stash were preserved.' -ForegroundColor Green
if (-not $SkipStart) {
    Write-Host 'Starting UniTrack on your existing machine...' -ForegroundColor Cyan
    RunNative $python @('run.py')
}
