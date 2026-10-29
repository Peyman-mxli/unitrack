# UniTrack safe local update, Windows PowerShell 5.1+.
# Usage from C:\unitrack:  .\scripts\safe_update.ps1
# This script never deletes the original database, photos, virtual environments,
# local backup, or git stash. It refuses to update a dirty/diverged checkout.
[CmdletBinding()]
param([switch]$SkipStart)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root

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
RunNative $python @('-c', 'import flask, sqlalchemy; print("Python environment OK")')

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
$backupScript = Join-Path $root 'scripts\backup_sqlite.py'
if (-not (Test-Path -LiteralPath $backupScript -PathType Leaf)) {
    Fail 'The SQLite backup tool is missing.'
}
Write-Host 'Backing up and checking SQLite database...' -ForegroundColor Cyan
RunNative $python @($backupScript)

# --ff-only prevents accidental merges, rebases, or overwriting local work.
Write-Host 'Pulling the latest verified main branch...' -ForegroundColor Cyan
RunNative 'git' @('pull', '--ff-only', 'origin', 'main')

Write-Host 'Installing required packages into .venv only...' -ForegroundColor Cyan
RunNative $python @('-m', 'pip', 'install', '-r', 'requirements.txt')

Write-Host 'Running isolated integration tests (never against unitrack.db)...' -ForegroundColor Cyan
RunNative $python @('-m', 'unittest', 'discover', '-s', 'tests', '-v')

Write-Host 'UniTrack updated; database, uploads and stash were preserved.' -ForegroundColor Green
if (-not $SkipStart) {
    Write-Host 'Starting UniTrack on your existing machine...' -ForegroundColor Cyan
    RunNative $python @('run.py')
}
