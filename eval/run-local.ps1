param(
  [ValidateSet("quick", "full")]
  [string]$Mode = "quick",
  [string]$OutDir = "",
  [string[]]$Measures = @(),
  [int]$Repeats = 0,
  [switch]$SkipDocker,
  [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$fullDicomBodyLimitBytes = 512 * 1024 * 1024
if ($Mode -eq "full" -and [string]::IsNullOrWhiteSpace($env:DICOM_MAX_BODY_BYTES)) {
  $env:DICOM_MAX_BODY_BYTES = [string]$fullDicomBodyLimitBytes
  Write-Host "[eval] DICOM_MAX_BODY_BYTES defaulted to $env:DICOM_MAX_BODY_BYTES for full mode"
}

if (-not $NoBuild) {
  npm run build
}

$argsList = @("tsx", "eval/src/run-local.ts", "--mode", $Mode)
if (-not [string]::IsNullOrWhiteSpace($OutDir)) {
  $argsList += @("--out", $OutDir)
}
if ($Measures.Count -gt 0) {
  $measureList = ($Measures -join ",")
  $argsList += @("--measures", $measureList)
}
if ($Repeats -gt 0) {
  $argsList += @("--repeats", [string]$Repeats)
}
if ($SkipDocker) {
  $argsList += "--skip-docker"
}

Write-Host "[eval] npx $($argsList -join ' ')"
npx @argsList
