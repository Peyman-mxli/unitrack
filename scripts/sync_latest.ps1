<#
UniTrack – one safe source-code update command for Windows/VS Code.
Run from the current UniTrack folder, or specify -ProjectRoot.
- Compatible clean clone: use the existing verified database-safe updater
- Rewritten/dirty checkout: create a new sibling copy, retain the original,
  and preserve the local DB/photos through the tested reconnect helper
- New laptop: clone GitHub's latest main into C:\unitrack-latest

NO force-pull, hard reset, stash pop, database upload, or deletion.
GitHub synchronizes CODE. Each laptop's private SQLite and uploads are local.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [switch]$SkipStart,
    [switch]$OpenVSCode
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = "https://github.com/Peyman-mxli/unitrack.git"
$rawBase = "https://raw.githubusercontent.com/Peyman-mxli/unitrack/main/scripts"
function Fail([string]$message) { throw "UniTrack sync: $message" }
function RunChecked([string]$program, [string[]]$arguments) {
    & $program @arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$program exited with code $LASTEXITCODE. Existing private data was not intentionally deleted."
    }
}
function DownloadHelper([string]$scriptName) {
    $output = Join-Path $env:TEMP ("unitrack-" + [Guid]::NewGuid().ToString("N") + "-" + $scriptName)
    Invoke-WebRequest -UseBasicParsing -Uri ($rawBase + "/" + $scriptName) -OutFile $output
    return $output
}
function IsUniTrackFolder([string]$folder) {
    return (Test-Path -LiteralPath (Join-Path $folder ".git") -PathType Container) -and
           (Test-Path -LiteralPath (Join-Path $folder "run.py") -PathType Leaf)
}
function EnsureVenv([string]$folder) {
    $python = Join-Path $folder ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Push-Location $folder
        try {
            RunChecked "py" @("-3.11", "-m", "venv", ".venv")
        } finally { Pop-Location }
    }
    return $python
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail "Git must be installed before cloning UniTrack."
}
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    if (IsUniTrackFolder (Get-Location).Path) {
        $ProjectRoot = (Get-Location).Path
    } else {
        $known = @("C:\unitrack-reconnected", "C:\unitrack-latest", "C:\unitrack")
        $found = $known | Where-Object { IsUniTrackFolder $_ } | Select-Object -First 1
        $ProjectRoot = if ($found) { $found } else { "C:\unitrack-latest" }
    }
}
$root = [System.IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
$active = $root
$createdFresh = $false

if (-not (Test-Path -LiteralPath $root)) {
    Write-Host "New laptop: cloning latest UniTrack main from GitHub into $root" -ForegroundColor Cyan
    RunChecked "git" @("clone", "--branch", "main", "--single-branch", $repo, $root)
    $createdFresh = $true
} else {
    if (-not (IsUniTrackFolder $root)) {
        Fail "Folder already exists but is not a valid UniTrack Git checkout: $root. No changes were made."
    }
    $origin = (& git -C $root remote get-url origin).Trim()
    if ($LASTEXITCODE -ne 0 -or
        $origin -notmatch '^((https://github\.com/)|(git@github\.com:))Peyman-mxli/unitrack(\.git)?$') {
        Fail "Unexpected Git origin. Refusing to synchronize private data with an unknown repository."
    }
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne "main") {
        Fail "Expected the main branch; existing files were not changed."
    }
    Write-Host "Checking the actual latest GitHub main (not cached origin/main)..." -ForegroundColor Cyan
    RunChecked "git" @("-C", $root, "fetch", "--quiet", "origin", "main")
    & git -C $root merge-base --is-ancestor HEAD refs/remotes/origin/main
    $fastForward = ($LASTEXITCODE -eq 0)
    $trackedChanges = @(& git -C $root status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0) { Fail "Cannot read local Git status." }
    $locallyModified = ($trackedChanges.Count -gt 0)

    if ($fastForward -and -not $locallyModified) {
        if (Test-Path -LiteralPath (Join-Path $root "unitrack.db") -PathType Leaf) {
            $null = EnsureVenv $root
            $helper = DownloadHelper "safe_update.ps1"
            try {
                Push-Location $root
                try {
                    RunChecked "powershell" @("-NoProfile", "-ExecutionPolicy", "Bypass",
                                             "-File", $helper, "-SkipStart")
                } finally { Pop-Location }
            } finally { Remove-Item -LiteralPath $helper -Force -ErrorAction SilentlyContinue }
        } else {
            Write-Host "No local unitrack.db in this folder. Syncing source only; no accounts are imported." -ForegroundColor Yellow
            RunChecked "git" @("-C", $root, "pull", "--ff-only", "origin", "main")
        }
    } else {
        # Old branch tips can diverge after a privacy-history rewrite. Never
        # use force-push, reset --hard, or overwrite edits to resolve this.
        $suffix = Get-Date -Format "yyyyMMdd-HHmmss"
        $active = "$root-latest-$suffix"
        if (Test-Path -LiteralPath $active) {
            $active = "$active-$([Guid]::NewGuid().ToString('N').Substring(0,6))"
        }
        Write-Host "Old checkout is diverged or has local edits. Preserving it at $root" -ForegroundColor Yellow
        if (Test-Path -LiteralPath (Join-Path $root "unitrack.db") -PathType Leaf) {
            $helper = DownloadHelper "reconnect_after_history_cleanup.ps1"
            try {
                RunChecked "powershell" @("-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", $helper, "-ProjectRoot", $root,
                    "-DestinationRoot", $active, "-SkipStart")
            } finally { Remove-Item -LiteralPath $helper -Force -ErrorAction SilentlyContinue }
            # Reconnector already installed packages and ran integration tests.
        } else {
            Write-Host "Old checkout has no unitrack.db; cloning code without transferring private records." -ForegroundColor Yellow
            RunChecked "git" @("clone", "--branch", "main", "--single-branch", $repo, $active)
            $createdFresh = $true
        }
    }
}
# Newly cloned code needs a private local venv. An existing DB-safe update
# and the reconnect helper install packages/tests before reaching this point.
$python = EnsureVenv $active
if ($createdFresh -or -not (Test-Path -LiteralPath (Join-Path $active "unitrack.db"))) {
    Push-Location $active
    try {
        RunChecked $python @("-m", "pip", "install", "-r", "requirements.txt")
        RunChecked $python @("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py")
    } finally { Pop-Location }
}
RunChecked "git" @("-C", $active, "fetch", "--quiet", "origin", "main")
$head = (& git -C $active rev-parse HEAD).Trim()
$latest = (& git -C $active rev-parse refs/remotes/origin/main).Trim()
if ($LASTEXITCODE -ne 0 -or $head -ne $latest) {
    Fail "Local HEAD differs from the newest GitHub main. Do not launch an outdated version."
}
Write-Host "SUCCESS: UniTrack source is current with GitHub main: $($head.Substring(0, 10))" -ForegroundColor Green
Write-Host "ACTIVE VS CODE PROJECT: $active" -ForegroundColor Cyan
if ($createdFresh -and -not (Test-Path -LiteralPath (Join-Path $active "unitrack.db"))) {
    Write-Host "This is a fresh local database; real account records do not travel through GitHub." -ForegroundColor Yellow
}
if ($OpenVSCode) {
    if (Get-Command code -ErrorAction SilentlyContinue) {
        & code --reuse-window $active
    } else {
        Write-Host "VS Code command not on PATH. Open the active project folder manually." -ForegroundColor Yellow
    }
}
if (-not $SkipStart) {
    Write-Host "Starting UniTrack from the verified latest project..." -ForegroundColor Cyan
    Push-Location $active
    try { RunChecked $python @("run.py") } finally { Pop-Location }
}
