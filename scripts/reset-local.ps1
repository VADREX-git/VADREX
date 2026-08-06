param(
  [switch]$Force,
  [int]$ReadyTimeoutSec = 600
)

# Destructive reset of evaluation state.
#
# `docker compose down -v` does not do this. The accumulated anchor state lives in the host
# files data/inst-*/audit.db and in the in-memory chain; -v only removes Orthanc storage.
# The order matters:
#
#   stop the gateways -> back up and remove the databases -> recreate the chain from block 0
#   -> redeploy the contracts -> restart the gateways against the new addresses
#
# A gateway reads its anchor contract address once at startup, so the containers must be
# recreated after a redeploy.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$RpcUrl = "http://127.0.0.1:8545"

function Invoke-Rpc {
  param([string]$Body)
  return Invoke-RestMethod -Uri $RpcUrl -Method Post -ContentType "application/json" -Body $Body -TimeoutSec 15
}

function Wait-ChainReady {
  param([int]$TimeoutSec)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-Rpc '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
      if ($response.result) {
        return
      }
    } catch {
      # The container may still be starting.
    }
    Start-Sleep -Seconds 3
  }
  throw "chain JSON-RPC did not become ready within $TimeoutSec seconds"
}

function Get-AnchorAddresses {
  $path = Join-Path $Root "data\deployments.local.json"
  if (-not (Test-Path $path)) {
    throw "deployment file not found: $path"
  }
  $deployments = Get-Content -Raw -Path $path | ConvertFrom-Json
  return @($deployments.anchors.A.address, $deployments.anchors.B.address)
}

if (-not $Force) {
  Write-Host "[reset] This backs up and removes the audit databases and rebuilds the chain from block 0."
  Write-Host "[reset] Pass -Force to proceed:  .\scripts\reset-local.ps1 -Force"
  exit 1
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$backupDir = Join-Path $Root "data\reset-backup-$stamp"

Write-Host "[reset] 1/6 stopping gateways"
docker compose stop gateway-a gateway-b

Write-Host "[reset] 2/6 backing up audit databases to $backupDir"
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
foreach ($institution in @("inst-a", "inst-b")) {
  $sourceDir = Join-Path $Root "data\$institution"
  if (-not (Test-Path $sourceDir)) {
    continue
  }
  foreach ($file in @(Get-ChildItem -Path $sourceDir -Filter "audit.db*" -File -ErrorAction SilentlyContinue)) {
    $target = Join-Path $backupDir "$institution`_$($file.Name)"
    Move-Item -LiteralPath $file.FullName -Destination $target -Force
  }
}
$deploymentPath = Join-Path $Root "data\deployments.local.json"
if (Test-Path $deploymentPath) {
  Copy-Item -LiteralPath $deploymentPath -Destination (Join-Path $backupDir "data_deployments.local.json") -Force
}

Write-Host "[reset] 3/6 recreating the chain from block 0"
docker compose up -d --force-recreate chain
Wait-ChainReady -TimeoutSec $ReadyTimeoutSec

Write-Host "[reset] 4/6 redeploying the Anchor contracts"
npm run contracts:deploy
if ($LASTEXITCODE -ne 0) {
  throw "contract deploy failed with exit $LASTEXITCODE"
}

Write-Host "[reset] 5/6 restarting gateways with empty databases and the new addresses"
docker compose up -d --force-recreate gateway-a gateway-b
npx tsx (Join-Path $PSScriptRoot "wait-healthy.ts") --timeout $ReadyTimeoutSec
if ($LASTEXITCODE -ne 0) {
  throw "services did not become healthy after reset"
}

Write-Host "[reset] 6/6 verifying the reset state"
$addresses = Get-AnchorAddresses
foreach ($address in $addresses) {
  $code = (Invoke-Rpc "{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"eth_getCode`",`"params`":[`"$address`",`"latest`"]}").result
  if (-not $code -or $code -eq "0x") {
    throw "no contract code at $address after redeploy"
  }
  Write-Host "  contract ok: $address"
}
foreach ($institution in @("inst-a", "inst-b")) {
  $dbPath = Join-Path $Root "data\$institution\audit.db"
  if (Test-Path $dbPath) {
    Write-Host "  fresh audit.db: $institution ($((Get-Item $dbPath).Length) bytes)"
  }
}

Write-Host "[reset] done. Backup: $backupDir"
