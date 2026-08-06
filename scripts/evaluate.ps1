param(
  [Parameter(Position = 0)]
  [ValidateSet("quick", "full", "paper")]
  [string]$ProfileName = "quick",
  [switch]$Detach,
  [string]$OutDir = "",
  [switch]$NoBuild,
  [switch]$SkipPlots
)

# Evaluation entry point.
#
# The profiles under eval/profiles hold the scale sets, repeat counts and completion criteria
# as data. This script resolves one of them, drives the measurement harness, then generates
# the figures, adjudicates the run and records provenance.
#
# Adjudication is done by scripts/verify-run.ps1, not by a reader: once a run finishes, the
# verdict field in status.json is the only thing that needs looking at.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$ProfilePath = Join-Path $Root "eval\profiles\$ProfileName.json"
if (-not (Test-Path $ProfilePath)) {
  throw "profile not found: $ProfilePath"
}
$evalProfile = Get-Content -Raw -Path $ProfilePath | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ss-fffZ")
  $OutDir = Join-Path $Root "eval\out\$stamp-$ProfileName"
} elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) {
  $OutDir = Join-Path $Root $OutDir
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$LatestRunPath = Join-Path $Root "eval\out\latest-run.txt"

function Get-Property {
  param($Object, [string]$Name)
  if ($null -eq $Object) { return $null }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) { return $null }
  return $property.Value
}

function Get-GitInfo {
  $commit = (git rev-parse HEAD)
  $treeHash = (git rev-parse "HEAD^{tree}")
  $dirty = @(git status --porcelain | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  return [ordered]@{
    commit = $commit
    treeHash = $treeHash
    cleanTree = ($dirty.Count -eq 0)
    dirtyFileCount = $dirty.Count
  }
}

# ------------------------------------------------------------------- Pre-gate
# Check before the detach branch. Behind it, the worker would already be running when the
# rejection happens, and the caller would find an empty result hours later.

$expect = Get-Property $evalProfile "expect"
$git = Get-GitInfo
if ((Get-Property $expect "requireCleanTree") -eq $true -and -not $git.cleanTree) {
  Write-Host "[evaluate] the $ProfileName profile runs only on a clean tree."
  Write-Host "[evaluate] $($git.dirtyFileCount) tracked file(s) modified. Commit or revert, then retry."
  exit 1
}

# The paper profile runs for about eleven hours and fills disk the whole way. reproduce.cmd only
# enforces enough room to bootstrap, so without this a run that cannot possibly finish still starts
# and dies somewhere in the middle. One complete cycle measured 16.6 GB.
$MinimumFreeGbForPaper = 25
if ($ProfileName -eq "paper") {
  $paths = @($Root)
  if ($env:LOCALAPPDATA) {
    $paths += $env:LOCALAPPDATA
  }
  $drives = @()
  foreach ($path in $paths) {
    try {
      $candidate = (Get-Item -LiteralPath $path -ErrorAction Stop).PSDrive
      if ($candidate -and $null -ne $candidate.Free) {
        $drives += $candidate
      }
    } catch {
      # A path we cannot read simply does not constrain the check.
    }
  }
  $tightest = $drives | Sort-Object -Property Name -Unique | Sort-Object -Property Free | Select-Object -First 1
  if ($tightest) {
    $freeGb = [Math]::Round($tightest.Free / 1GB, 1)
    if ($freeGb -lt $MinimumFreeGbForPaper) {
      Write-Host "[evaluate] only ${freeGb}GB free on $($tightest.Name):; the paper profile needs ${MinimumFreeGbForPaper}GB."
      Write-Host "[evaluate] Docker's virtual disk lives on the drive holding %LOCALAPPDATA% and never shrinks."
      exit 1
    }
    Write-Host "[evaluate] disk: ${freeGb}GB free on $($tightest.Name):"
  }
}

# ------------------------------------------------------------------ detach

if ($Detach) {
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $arguments = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $PSCommandPath,
    $ProfileName,
    "-OutDir", $OutDir
  )
  if ($NoBuild) { $arguments += "-NoBuild" }
  if ($SkipPlots) { $arguments += "-SkipPlots" }

  $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments `
    -WorkingDirectory $Root -WindowStyle Hidden -PassThru
  # Written without a BOM: this path file is read by tooling, not by a person.
  [System.IO.File]::WriteAllText($LatestRunPath, $OutDir, (New-Object System.Text.UTF8Encoding($false)))

  Write-Host "[evaluate] started in the background"
  Write-Host "  profile : $ProfileName"
  Write-Host "  pid     : $($process.Id)"
  Write-Host "  outDir  : $OutDir"
  Write-Host "  status  : $(Join-Path $OutDir 'status.json')"
  Write-Host ""
  Write-Host "When it finishes, read the verdict in status.json. No polling is needed."
  exit 0
}

# Clear the scale variables before applying the profile, so settings left in the shell by an
# earlier run cannot leak into this one.
foreach ($name in @("EVAL_LOG_SIZES", "EVAL_ANCHOR_INTERVALS", "EVAL_ANCHOR_COUNTS", "EVAL_STUDY_SIZES", "EVAL_REPEATS", "EVAL_MODE", "EVAL_OUT_DIR")) {
  Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
}
$appliedEnv = [ordered]@{}
$profileEnv = Get-Property $evalProfile "env"
if ($null -ne $profileEnv) {
  foreach ($property in $profileEnv.PSObject.Properties) {
    Set-Item -Path "env:$($property.Name)" -Value ([string]$property.Value)
    $appliedEnv[$property.Name] = [string]$property.Value
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Set-Content -Path $LatestRunPath -Value $OutDir -Encoding utf8

$startedAt = Get-Date
$resolvedEnv = [ordered]@{}
foreach ($name in @(
  "EVAL_LOG_SIZES", "EVAL_ANCHOR_INTERVALS", "EVAL_ANCHOR_COUNTS", "EVAL_STUDY_SIZES",
  "EVAL_INCLUDE_10M", "EVAL_REVOCATION_RANDOM_OFFSET", "EVAL_SKIP_DOCKER",
  "ANCHOR_INTERVAL_SEC", "ANCHOR_MAX_INTERVAL_SEC", "RECEIPT_TIMEOUT_SEC", "DICOM_MAX_BODY_BYTES"
)) {
  $value = (Get-Item -Path "env:$name" -ErrorAction SilentlyContinue).Value
  if ([string]::IsNullOrWhiteSpace($value)) {
    $resolvedEnv[$name] = "(unset - built-in default)"
  } else {
    $resolvedEnv[$name] = $value
  }
}

$configResolved = [ordered]@{
  profile = $ProfileName
  profileDescription = $evalProfile.description
  mode = $evalProfile.mode
  repeats = $evalProfile.repeats
  profileEnv = $appliedEnv
  resolvedEnv = $resolvedEnv
  expect = $expect
  source = $git
  startedAt = $startedAt.ToString("o")
}
$configResolved | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $OutDir "config.resolved.json") -Encoding utf8

Write-Host "[evaluate] profile=$ProfileName mode=$($evalProfile.mode) repeats=$($evalProfile.repeats)"
Write-Host "[evaluate] outDir=$OutDir"

# --------------------------------------------------------------- Measurement

$watchParameters = @{
  Mode = [string]$evalProfile.mode
  Repeats = [int]$evalProfile.repeats
  OutDir = $OutDir
}
if ($NoBuild) { $watchParameters["NoBuild"] = $true }
& (Join-Path $Root "eval\full-test-watch.ps1") @watchParameters
$watchExitCode = $LASTEXITCODE

# ------------------------------------------------------------------- Figures

if (-not $SkipPlots) {
  try {
    & (Join-Path $Root "eval\run-plots.ps1") -RunDir $OutDir
  } catch {
    Write-Host "[evaluate] figure generation failed: $($_.Exception.Message)"
  }
}

# -------------------------------------------------------------- Adjudication

& (Join-Path $PSScriptRoot "verify-run.ps1") -RunDir $OutDir -ProfilePath $ProfilePath
$verifyExitCode = $LASTEXITCODE

# --------------------------------------------------------------- provenance

$finishedAt = Get-Date
$status = Get-Content -Raw -Path (Join-Path $OutDir "status.json") | ConvertFrom-Json

$manifest = [ordered]@{
  profile = $ProfileName
  verdict = $status.verdict
  verdictReasons = @($status.verdictReasons)
  watchdogState = $status.state
  watchdogExitCode = $watchExitCode
  startedAt = $startedAt.ToString("o")
  finishedAt = $finishedAt.ToString("o")
  durationSeconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 1)
  source = $git
  profileSha256 = (Get-FileHash -Algorithm SHA256 -Path $ProfilePath).Hash.ToLower()
  packageLockSha256 = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $Root "package-lock.json")).Hash.ToLower()
  composeSha256 = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $Root "docker-compose.yml")).Hash.ToLower()
  checked = $status.checked
}
$deploymentPath = Join-Path $Root "data\deployments.local.json"
if (Test-Path $deploymentPath) {
  $deployments = Get-Content -Raw -Path $deploymentPath | ConvertFrom-Json
  $manifest["anchorContracts"] = [ordered]@{
    A = $deployments.anchors.A.address
    B = $deployments.anchors.B.address
  }
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $OutDir "run-manifest.json") -Encoding utf8

$hashLines = New-Object System.Collections.ArrayList
foreach ($relative in @("config.resolved.json", "environment.json", "status.json", "run-manifest.json")) {
  $path = Join-Path $OutDir $relative
  if (Test-Path $path) {
    [void]$hashLines.Add("$((Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower())  $relative")
  }
}
foreach ($subdirectory in @("raw", "summary", "figures")) {
  $directory = Join-Path $OutDir $subdirectory
  if (-not (Test-Path $directory)) { continue }
  foreach ($file in @(Get-ChildItem -Path $directory -File | Sort-Object Name)) {
    [void]$hashLines.Add("$((Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash.ToLower())  $subdirectory/$($file.Name)")
  }
}
Set-Content -Path (Join-Path $OutDir "SHA256SUMS") -Value $hashLines -Encoding utf8

$provenance = @(
  "# Run provenance - $ProfileName",
  "",
  "- Profile: ``eval/profiles/$ProfileName.json`` (sha256 ``$($manifest.profileSha256)``)",
  "- Description: $($evalProfile.description)",
  "- Verdict: **$($status.verdict)**",
  "- Source commit: ``$($git.commit)`` / tree ``$($git.treeHash)`` / clean=$($git.cleanTree)",
  "- Window: $($startedAt.ToString('o')) to $($finishedAt.ToString('o')) ($($manifest.durationSeconds)s)",
  "- Anchor contracts: A=$($manifest.anchorContracts.A), B=$($manifest.anchorContracts.B)",
  "",
  "## Results",
  "",
  "- Rows: $($status.checked.totalRows)",
  "- failed $($status.checked.failed) / waiting $($status.checked.waiting) / skipped $($status.checked.skipped) / undetected $($status.checked.undetected)",
  "- scaling rows not verified: $($status.checked.scalingUnverified)",
  "",
  "## Reproducing",
  "",
  '```powershell',
  ".\evaluate.cmd $ProfileName",
  '```',
  "",
  "Every resolved environment variable is in ``config.resolved.json``; file hashes are in ``SHA256SUMS``.",
  ""
)
if (@($status.verdictReasons).Count -gt 0) {
  $provenance += @("## Why the verdict failed", "")
  foreach ($reason in @($status.verdictReasons)) {
    $provenance += "- $reason"
  }
  $provenance += ""
}
Set-Content -Path (Join-Path $OutDir "PROVENANCE.md") -Value $provenance -Encoding utf8

Write-Host ""
Write-Host "[evaluate] verdict=$($status.verdict)  outDir=$OutDir"
Write-Host "[evaluate] the verdict in status.json is the only thing to check."

if ($status.verdict -ne "pass" -or $verifyExitCode -ne 0) {
  exit 1
}
