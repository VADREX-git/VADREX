param(
  [switch]$Reset,
  [switch]$SkipE2E,
  [int]$ReadyTimeoutSec = 600
)

# One-command bootstrap.
#
# From a fresh clone this installs dependencies, generates the CA and institution keys, starts
# the chain, deploys the anchor contracts, brings up Orthanc and both gateways, loads a
# synthetic study, and runs a compliant end-to-end scenario, recording a verdict in
# reproduce-status.json.
#
# The order is not arbitrary: a gateway reads its anchor contract address once at startup, so
# the chain and the contracts must be in place before the gateways come up.
#
# A second run reuses a healthy stack. Destructive reset happens only with -Reset.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$RpcUrl = "http://127.0.0.1:8545"
$StatusPath = Join-Path $Root "reproduce-status.json"
$RequiredPorts = @(7001, 7002, 8042, 8043, 8545)
# Floor for bootstrapping, not for a paper run. See Get-ConstrainedDrive for why two drives are
# checked, and evaluate.ps1 for the larger figure a paper run demands.
$MinimumFreeGb = 20

$script:Steps = @()
$script:CurrentNote = ""
$StartedAt = Get-Date

function Set-StepNote {
  param([string]$Text)
  $script:CurrentNote = $Text
}

function Invoke-Native {
  param([string]$Description, [scriptblock]$Command)
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "$Description failed with exit code $LASTEXITCODE"
  }
}

function Invoke-Rpc {
  param([string]$Body)
  return Invoke-RestMethod -Uri $RpcUrl -Method Post -ContentType "application/json" -Body $Body -TimeoutSec 15
}

function Write-StatusFile {
  param([string]$Verdict, [string]$FailedStep = "")
  $finishedAt = Get-Date
  $status = [ordered]@{
    verdict = $Verdict
    failedStep = $FailedStep
    startedAt = $StartedAt.ToString("o")
    finishedAt = $finishedAt.ToString("o")
    durationSeconds = [Math]::Round(($finishedAt - $StartedAt).TotalSeconds, 1)
    reset = [bool]$Reset
    skipE2E = [bool]$SkipE2E
    environment = [ordered]@{
      os = [string](Get-CimInstance Win32_OperatingSystem).Caption
      node = (node --version)
      npm = (npm --version)
      docker = (docker --version)
      compose = (docker compose version)
    }
    steps = $script:Steps
  }
  $temporary = "$StatusPath.tmp"
  $status | ConvertTo-Json -Depth 6 | Set-Content -Path $temporary -Encoding utf8
  Move-Item -Force -Path $temporary -Destination $StatusPath
}

function Invoke-Step {
  param([string]$Name, [scriptblock]$Body)
  $script:CurrentNote = ""
  Write-Host ""
  Write-Host "[reproduce] $Name"
  $started = Get-Date
  try {
    & $Body
    $elapsed = [Math]::Round(((Get-Date) - $started).TotalMilliseconds)
    $script:Steps += [ordered]@{ name = $Name; status = "ok"; durationMs = $elapsed; note = $script:CurrentNote }
    if ([string]::IsNullOrWhiteSpace($script:CurrentNote)) {
      Write-Host "  ok"
    } else {
      Write-Host "  ok - $script:CurrentNote"
    }
  } catch {
    $elapsed = [Math]::Round(((Get-Date) - $started).TotalMilliseconds)
    $message = $_.Exception.Message
    $script:Steps += [ordered]@{ name = $Name; status = "failed"; durationMs = $elapsed; note = $script:CurrentNote; error = $message }
    Write-Host "  FAILED: $message"
    Write-StatusFile -Verdict "fail" -FailedStep $Name
    Write-Host ""
    Write-Host "[reproduce] verdict=fail  ($Name)"
    Write-Host "[reproduce] status: $StatusPath"
    exit 1
  }
}

function Test-StackExists {
  $ids = @(docker compose ps -q | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  return $ids.Count -gt 0
}

function Get-AnchorAddresses {
  $path = Join-Path $Root "data\deployments.local.json"
  if (-not (Test-Path $path)) {
    return @()
  }
  try {
    $deployments = Get-Content -Raw -Path $path | ConvertFrom-Json
    return @($deployments.anchors.A.address, $deployments.anchors.B.address)
  } catch {
    return @()
  }
}

function Test-ContractsDeployed {
  $addresses = Get-AnchorAddresses
  if ($addresses.Count -lt 2) {
    return $false
  }
  foreach ($address in $addresses) {
    if ([string]::IsNullOrWhiteSpace($address)) {
      return $false
    }
    try {
      $code = (Invoke-Rpc "{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"eth_getCode`",`"params`":[`"$address`",`"latest`"]}").result
    } catch {
      return $false
    }
    if (-not $code -or $code -eq "0x") {
      return $false
    }
  }
  return $true
}

# ------------------------------------------------------------- 1. Prerequisites

# Returns whichever drive has the least room among the ones a run actually fills: the repository
# drive, and the drive holding Docker's virtual disk under %LOCALAPPDATA%. The virtual disk stays
# there no matter where the repository was cloned, so checking only the repository drive lets a
# clone on a roomy second drive pass while C: is nearly full - and that failure then surfaces hours
# later as a Docker engine error in the middle of a measurement.
function Get-ConstrainedDrive {
  $candidates = @($Root)
  if ($env:LOCALAPPDATA) {
    $candidates += $env:LOCALAPPDATA
  }
  $drives = @()
  foreach ($path in $candidates) {
    try {
      $drive = (Get-Item -LiteralPath $path -ErrorAction Stop).PSDrive
      if ($drive -and $null -ne $drive.Free) {
        $drives += $drive
      }
    } catch {
      # A path we cannot read simply does not constrain the check.
    }
  }
  if ($drives.Count -eq 0) {
    return $null
  }
  return ($drives | Sort-Object -Property Name -Unique | Sort-Object -Property Free | Select-Object -First 1)
}

Invoke-Step "prerequisites" {
  $nodeVersion = node --version
  $nodeMajor = [int]($nodeVersion -replace '^v(\d+)\..*$', '$1')
  if ($nodeMajor -lt 20) {
    throw "Node 20 or newer is required (found $nodeVersion). See https://nodejs.org."
  }
  npm --version | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "npm was not found"
  }
  # Do not redirect stderr of a native command: PowerShell 5.1 wraps each line in an
  # ErrorRecord, which turns a successful exit into a terminating error.
  docker info --format "{{.ServerVersion}}" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Cannot reach the Docker engine. Start Docker Desktop and try again."
  }
  docker compose version | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose v2 is required"
  }
  $drive = Get-ConstrainedDrive
  if (-not $drive) {
    throw "could not determine free disk space for $Root or $env:LOCALAPPDATA"
  }
  $freeGb = [Math]::Round($drive.Free / 1GB, 1)
  if ($freeGb -lt $MinimumFreeGb) {
    throw "Not enough free disk space on $($drive.Name): (${freeGb}GB free; ${MinimumFreeGb}GB required). Docker's virtual disk lives on the drive holding %LOCALAPPDATA%."
  }
  Set-StepNote "node $nodeVersion, npm $(npm --version), ${freeGb}GB free on $($drive.Name):"
}

Invoke-Step "ports" {
  if (Test-StackExists) {
    Set-StepNote "reusing the running stack; the ports belong to its own containers"
    return
  }
  $busy = @()
  foreach ($port in $RequiredPorts) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
      $busy += $port
    }
  }
  if ($busy.Count -gt 0) {
    throw "ports already in use by another process: $($busy -join ', '). Stop it and try again."
  }
  Set-StepNote "$($RequiredPorts -join ', ') available"
}

# --------------------------------------------------------- 2. Host preparation

# These three steps run only when their output is missing. -Reset means resetting runtime
# state (audit databases, chain, contracts) and deliberately leaves dependencies and
# certificates alone: regenerating certificates would leave Orthanc holding the old ones and
# break mTLS, so that is a separate and rare operation.

Invoke-Step "npm-install" {
  if (Test-Path (Join-Path $Root "node_modules")) {
    Set-StepNote "skipped: node_modules already present"
    return
  }
  Invoke-Native "npm ci" { npm ci }
}

Invoke-Step "build" {
  # Host-side scripts and the evaluation harness run under tsx but resolve the workspace
  # packages through their built dist directories, which a fresh clone does not have. Build
  # every time so that dist can never drift from the source it is generated from.
  Invoke-Native "npm run build" { npm run build }
}

Invoke-Step "certificates" {
  $caCert = Join-Path $Root "scripts\out\ca\ca.cert.pem"
  $certA = Join-Path $Root "scripts\out\inst-a\cert.pem"
  $certB = Join-Path $Root "scripts\out\inst-b\cert.pem"
  if ((Test-Path $caCert) -and (Test-Path $certA) -and (Test-Path $certB)) {
    Set-StepNote "skipped: reusing the existing CA and certificates"
    return
  }
  Invoke-Native "ca-setup" { powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "ca-setup.ps1") }
}

Invoke-Step "institution-keys" {
  $keyA = Join-Path $Root "scripts\out\inst-a\ed25519.key"
  $keyB = Join-Path $Root "scripts\out\inst-b\ed25519.key"
  if ((Test-Path $keyA) -and (Test-Path $keyB)) {
    Set-StepNote "skipped: reusing the existing Ed25519 and wallet keys"
    return
  }
  Invoke-Native "keygen" { npm run keygen }
}

# --------------------------------------------- 3. Chain, contracts, services

Invoke-Step "images" {
  # Build before deploying, never after. A changed image makes Compose recreate the chain
  # container, and because the Hardhat chain is in-memory it comes back at block 0 with the
  # freshly deployed contracts gone. Unchanged sources hit the cache and take seconds.
  Invoke-Native "docker compose build" { docker compose build }
}

Invoke-Step "chain" {
  Invoke-Native "docker compose up chain" { docker compose up -d chain }
  $deadline = (Get-Date).AddSeconds($ReadyTimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-Rpc '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
      if ($response.result) {
        Set-StepNote "JSON-RPC ready (block $([Convert]::ToInt64($response.result, 16)))"
        return
      }
    } catch {
      # Still starting up; retry.
    }
    # No point waiting out the timeout if the container has already exited; report with logs.
    if (@(docker compose ps --status exited --services) -contains "chain") {
      $tail = (docker compose logs --tail 20 --no-log-prefix chain) -join "`n"
      throw "the chain container exited:`n$tail"
    }
    Start-Sleep -Seconds 3
  }
  throw "chain JSON-RPC did not become ready within ${ReadyTimeoutSec}s"
}

if ($Reset) {
  Invoke-Step "reset-state" {
    Invoke-Native "reset-local" { powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "reset-local.ps1") -Force -ReadyTimeoutSec $ReadyTimeoutSec }
    Set-StepNote "audit databases backed up and removed, chain recreated, contracts redeployed"
  }
}

Invoke-Step "contracts" {
  if (Test-ContractsDeployed) {
    $addresses = Get-AnchorAddresses
    Set-StepNote "skipped: contracts already deployed (A=$($addresses[0]), B=$($addresses[1]))"
    return
  }
  Invoke-Native "contracts:deploy" { npm run contracts:deploy }
  if (-not (Test-ContractsDeployed)) {
    throw "no contract code on chain after deployment"
  }
}

Invoke-Step "state-consistency" {
  # The local anchor history lives in the host database and the anchors themselves live on
  # the chain, so the two drift apart silently: stopping and restarting the stack returns
  # the in-memory chain to block 0 while the databases survive. Catch it here rather than
  # much later, at the first anchor registration.
  Invoke-Native "check-state-consistency" { npx tsx (Join-Path $PSScriptRoot "check-state-consistency.ts") }
}

Invoke-Step "services" {
  Invoke-Native "docker compose up" { docker compose up -d }
  Invoke-Native "wait-healthy" { npx tsx (Join-Path $PSScriptRoot "wait-healthy.ts") --timeout $ReadyTimeoutSec }
  Set-StepNote "orthanc-a/b and gateway-a/b healthy, mTLS included"
}

# -------------------------------------------------------------- 4. Verification

Invoke-Step "sample-dicom" {
  # Scenarios default to the first study in Orthanc A, which may be a large one left behind
  # by an earlier measurement and would then exceed the gateway body limit. Pin the sample
  # this step just created so the bootstrap is deterministic.
  $output = npx tsx (Join-Path $PSScriptRoot "make-sample-dicom.ts")
  if ($LASTEXITCODE -ne 0) {
    throw "make-sample-dicom failed with exit code $LASTEXITCODE"
  }
  $output | Write-Host
  $match = $output | Select-String -Pattern '^studyInstanceUid:\s*(\S+)$'
  if (-not $match) {
    throw "could not find the sample studyInstanceUid in the output"
  }
  $script:SampleStudyUid = $match.Matches[0].Groups[1].Value
  Set-StepNote "synthetic study loaded, no external download; studyInstanceUid=$script:SampleStudyUid"
}

Invoke-Step "contract-smoke" {
  Invoke-Native "contracts:smoke" { npm run contracts:smoke }
}

if ($SkipE2E) {
  $script:Steps += [ordered]@{ name = "e2e-compliant"; status = "skipped"; durationMs = 0; note = "-SkipE2E" }
} else {
  Invoke-Step "e2e-compliant" {
    # An unconfirmed transfer from an earlier run leaves a peer hold that blocks every
    # subsequent approval.
    Invoke-Native "release-peer-hold" { npx tsx (Join-Path $PSScriptRoot "release-peer-hold.ts") }
    $env:SCENARIO_STUDY_UID = $script:SampleStudyUid
    Invoke-Native "e2e:compliant" { npm run e2e:compliant }
    Set-StepNote "compliant transfer and patient verification passed"
  }
}

# -------------------------------------------------------------------- 5. Result

Write-StatusFile -Verdict "pass"

Write-Host ""
Write-Host "[reproduce] verdict=pass"
Write-Host "[reproduce] status: $StatusPath"
Write-Host ""
Write-Host "Next:"
Write-Host "  .\evaluate.cmd quick      validate the measurement pipeline"
Write-Host "  .\scripts\stop-local.ps1  stop the stack"
