param(
  [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")

Write-Host "[preflight] Root: $Root"
Set-Location $Root

Write-Host "[preflight] Node:"
node --version
npm --version

Write-Host "[preflight] Required local files"
# Checks only the artefacts a reproduction actually needs.
$required = @(
  "scripts\out\inst-a\cert.pem",
  "scripts\out\inst-a\key.pem",
  "scripts\out\inst-a\ca.cert.pem",
  "scripts\out\inst-a\ed25519.pub",
  "scripts\out\inst-b\ed25519.pub",
  "data\deployments.local.json"
)
foreach ($path in $required) {
  if (-not (Test-Path (Join-Path $Root $path))) {
    throw "Missing required file: $path"
  }
  Write-Host "  ok $path"
}

Write-Host "[preflight] Port 8545 listeners"
if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
  Write-Host "  (skipped: Windows-only diagnostic)"
} else {
$listeners = Get-NetTCPConnection -LocalPort 8545 -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,State,OwningProcess,@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
$listeners | Format-Table | Out-String | Write-Host

$hostHardhat = Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -like '*hardhat*node*--hostname*' } |
  Select-Object ProcessId,Name,CommandLine
if ($hostHardhat) {
  Write-Warning "A host Hardhat node appears to be running. Compose-based 8A evaluation expects Docker's chain on 8545."
  $hostHardhat | Format-List | Out-String | Write-Host
}
}

if (-not $SkipDocker) {
  Write-Host "[preflight] Docker compose services"
  docker compose ps
}

Write-Host "[preflight] Build check"
npm run build

Write-Host "[preflight] OK"

