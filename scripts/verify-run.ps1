param(
  [Parameter(Mandatory = $true)][string]$RunDir,
  [Parameter(Mandatory = $true)][string]$ProfilePath
)

# Checks an evaluation run against the completion criteria of its profile and writes the result
# to the verdict field of status.json.
#
# The point is to have the script, not a reader, decide whether a run succeeded. Otherwise
# answering "are all rows there", "are all four S1 cases present", "is every scaling row
# verified" means opening the raw CSV and JSON by hand.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")

$RunPath = (Resolve-Path $RunDir).Path
$profile = Get-Content -Raw -Path $ProfilePath | ConvertFrom-Json
$expect = $profile.expect

$DefaultRawFiles = @(
  "scaling.json",
  "revocation_delay.json",
  "handshake_overhead.json",
  "verify_cost.json",
  "grace_window.json",
  "attack_injection.json"
)
$FigureFiles = @(
  "scaling.png",
  "revocation_delay.png",
  "handshake_overhead.png",
  "verify_cost.png",
  "grace_window.png",
  "attack_injection.png"
)

function Get-Property {
  param($Object, [string]$Name)
  if ($null -eq $Object) {
    return $null
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) {
    return $null
  }
  return $property.Value
}

$reasons = New-Object System.Collections.ArrayList
$rawDir = Join-Path $RunPath "raw"

$expectedFiles = $DefaultRawFiles
$rowsByFileExpectation = Get-Property $expect "rowsByFile"
if ($null -ne $rowsByFileExpectation) {
  $expectedFiles = @($rowsByFileExpectation.PSObject.Properties.Name)
}

$rowsByFile = [ordered]@{}
$totalRows = 0
$failed = 0
$waiting = 0
$skipped = 0
$undetected = 0
$scalingUnverified = 0
$attackLabels = @{}

foreach ($file in $expectedFiles) {
  $path = Join-Path $rawDir $file
  if (-not (Test-Path $path)) {
    [void]$reasons.Add("raw/$file is missing")
    continue
  }
  $parsed = Get-Content -Raw -Path $path | ConvertFrom-Json
  $rows = @($parsed)
  $rowsByFile[$file] = $rows.Count
  $totalRows += $rows.Count

  foreach ($row in $rows) {
    $status = [string](Get-Property $row "status")
    switch ($status) {
      "failed" { $failed += 1 }
      "failure" { $failed += 1 }
      "waiting" { $waiting += 1 }
      "skipped" { $skipped += 1 }
    }
    $detected = Get-Property $row "detected"
    if ($null -ne $detected -and $detected -eq $false -and $status -ne "skipped") {
      $undetected += 1
    }
    # scaling rows carry no status field; success is verified=true instead.
    $verified = Get-Property $row "verified"
    if ($file -eq "scaling.json" -and $verified -ne $true) {
      $scalingUnverified += 1
    }
    if ($file -eq "attack_injection.json" -and $status -ne "skipped") {
      $property = [string](Get-Property $row "property")
      $attackType = [string](Get-Property $row "attackType")
      if ($property -and $attackType) {
        if (-not $attackLabels.ContainsKey($property)) {
          $attackLabels[$property] = New-Object System.Collections.Generic.HashSet[string]
        }
        [void]$attackLabels[$property].Add($attackType)
      }
    }
  }
}

$expectedTotal = Get-Property $expect "totalRows"
if ($null -ne $expectedTotal -and $totalRows -ne [int]$expectedTotal) {
  [void]$reasons.Add("row count is $totalRows (expected $expectedTotal)")
}

if ($null -ne $rowsByFileExpectation) {
  foreach ($property in $rowsByFileExpectation.PSObject.Properties) {
    $actual = 0
    if ($rowsByFile.Contains($property.Name)) {
      $actual = $rowsByFile[$property.Name]
    }
    if ($actual -ne [int]$property.Value) {
      [void]$reasons.Add("$($property.Name) row count is $actual (expected $($property.Value))")
    }
  }
}

if ((Get-Property $expect "requireZeroFailures") -eq $true) {
  if ($failed -gt 0) { [void]$reasons.Add("$failed failed rows") }
  if ($waiting -gt 0) { [void]$reasons.Add("$waiting waiting rows") }
  if ($skipped -gt 0) { [void]$reasons.Add("$skipped skipped rows") }
  if ($undetected -gt 0) { [void]$reasons.Add("$undetected undetected rows") }
}

if ((Get-Property $expect "requireScalingVerified") -eq $true -and $scalingUnverified -gt 0) {
  [void]$reasons.Add("$scalingUnverified scaling rows without verified=true")
}

$labelExpectation = Get-Property $expect "attackLabels"
if ($null -ne $labelExpectation) {
  foreach ($property in $labelExpectation.PSObject.Properties) {
    $actual = 0
    if ($attackLabels.ContainsKey($property.Name)) {
      $actual = $attackLabels[$property.Name].Count
    }
    if ($actual -ne [int]$property.Value) {
      [void]$reasons.Add("$($property.Name) has $actual distinct scenarios (expected $($property.Value))")
    }
  }
}

if ((Get-Property $expect "requireFigures") -eq $true) {
  $missing = @($FigureFiles | Where-Object { -not (Test-Path (Join-Path $RunPath "figures\$_")) })
  if ($missing.Count -gt 0) {
    [void]$reasons.Add("missing figures: $($missing -join ', ')")
  }
}

# A run must not modify tracked files; every evaluation artefact belongs on an ignored path.
Push-Location $Root
$dirty = @(git status --porcelain | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
Pop-Location
if ((Get-Property $expect "requireCleanTree") -eq $true -and $dirty.Count -gt 0) {
  [void]$reasons.Add("$($dirty.Count) tracked files were modified by the run")
}

$verdict = "pass"
if ($reasons.Count -gt 0) {
  $verdict = "fail"
}

$statusPath = Join-Path $RunPath "status.json"
$status = [ordered]@{}
if (Test-Path $statusPath) {
  $existing = Get-Content -Raw -Path $statusPath | ConvertFrom-Json
  foreach ($property in $existing.PSObject.Properties) {
    $status[$property.Name] = $property.Value
  }
}
$status["verdict"] = $verdict
$status["verdictReasons"] = @($reasons)
$status["verifiedAt"] = (Get-Date).ToString("o")
$status["profile"] = $profile.name
$status["checked"] = [ordered]@{
  totalRows = $totalRows
  rowsByFile = $rowsByFile
  failed = $failed
  waiting = $waiting
  skipped = $skipped
  undetected = $undetected
  scalingUnverified = $scalingUnverified
  attackLabels = [ordered]@{}
  trackedFilesChanged = $dirty.Count
}
foreach ($key in ($attackLabels.Keys | Sort-Object)) {
  $status["checked"].attackLabels[$key] = $attackLabels[$key].Count
}

$temporary = "$statusPath.tmp"
$status | ConvertTo-Json -Depth 8 | Set-Content -Path $temporary -Encoding utf8
Move-Item -Force -Path $temporary -Destination $statusPath

Write-Host "[verify] verdict=$verdict rows=$totalRows failed=$failed waiting=$waiting skipped=$skipped undetected=$undetected"
foreach ($reason in $reasons) {
  Write-Host "  - $reason"
}
Write-Host "[verify] status: $statusPath"

if ($verdict -ne "pass") {
  exit 1
}
