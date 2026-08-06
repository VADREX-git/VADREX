param(
  [switch]$RemoveVolumes
)

# Stops the local stack. Non-destructive by default: it only stops the containers.
#
# -RemoveVolumes also removes the Orthanc storage and node_modules volumes. The audit databases
# live in data/inst-*/ on the host and are not affected; use scripts/reset-local.ps1 to reset
# evaluation state.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

if ($RemoveVolumes) {
  Write-Host "[stop] docker compose down -v (removes Orthanc storage and node_modules volumes)"
  Write-Host "[stop] note: data/inst-*/audit.db on the host is left untouched."
  docker compose down -v
} else {
  Write-Host "[stop] docker compose stop"
  docker compose stop
}

Write-Host "[stop] done"
