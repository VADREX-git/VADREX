param(
  [ValidateSet("quick", "full")]
  [string]$Mode = "full",
  [string]$OutDir = "",
  [ValidateSet("scaling", "revocation-delay", "handshake", "verify-cost", "grace", "attack")]
  [string[]]$Measures = @(),
  [int]$Repeats = 0,
  [switch]$SkipDocker,
  [switch]$NoBuild,
  [ValidateRange(10, 15)]
  [int]$SummaryIntervalMinutes = 12,
  [ValidateRange(10, 300)]
  [int]$WatchdogPollSeconds = 60,
  [ValidateRange(10, 240)]
  [int]$StallWarningMinutes = 45
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$startedAt = Get-Date
$outputFileByMeasure = [ordered]@{
  "scaling" = "scaling.json"
  "revocation-delay" = "revocation_delay.json"
  "handshake" = "handshake_overhead.json"
  "verify-cost" = "verify_cost.json"
  "grace" = "grace_window.json"
  "attack" = "attack_injection.json"
}
$requestedMeasures = if ($Measures.Count -gt 0) {
  @($Measures)
} else {
  @($outputFileByMeasure.Keys | ForEach-Object { [string]$_ })
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $stamp = $startedAt.ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ss-fffZ")
  $OutDir = Join-Path $Root "eval\out\$stamp-$Mode-watch"
} elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) {
  $OutDir = Join-Path $Root $OutDir
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$LogsDir = Join-Path $OutDir "logs"
$StatusPath = Join-Path $OutDir "status.json"
$StdoutPath = Join-Path $LogsDir "full-test.log"
$StderrPath = Join-Path $LogsDir "full-test-error.log"
$FailureContextPath = Join-Path $LogsDir "failure-context.log"
$RunnerExitCodePath = Join-Path $LogsDir "runner-exit-code.txt"

New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null
if (Test-Path $RunnerExitCodePath) {
  Remove-Item -LiteralPath $RunnerExitCodePath -Force
}

function ConvertTo-PowerShellLiteral([string]$Value) {
  return "'" + $Value.Replace("'", "''") + "'"
}

function Write-Status([System.Collections.IDictionary]$Status) {
  $temporaryPath = "$StatusPath.tmp"
  $Status | ConvertTo-Json -Depth 8 | Set-Content -Path $temporaryPath -Encoding utf8
  Move-Item -Force -Path $temporaryPath -Destination $StatusPath
}

function Get-LogTail([string]$Path, [int]$Lines = 200) {
  if (-not (Test-Path $Path)) {
    return @()
  }
  return @(Get-Content -Path $Path -Tail $Lines -ErrorAction SilentlyContinue)
}

function Get-CurrentPhase {
  $tail = Get-LogTail $StdoutPath
  $started = @($tail | Select-String -Pattern '^\[eval\] (.+) started$')
  $completed = @($tail | Select-String -Pattern '^\[eval\] (.+) completed in ')
  if ($tail | Select-String -Quiet -Pattern '^\[eval\] output: ') {
    return "finalizing"
  }
  if ($started.Count -gt 0) {
    $latestStarted = $started[-1].Matches[0].Groups[1].Value
    $latestCompleted = if ($completed.Count -gt 0) { $completed[-1].Matches[0].Groups[1].Value } else { "" }
    if ($latestStarted -ne $latestCompleted) {
      return $latestStarted
    }
  }
  return "startup"
}

function Get-ResultSummary {
  $summary = [ordered]@{
    files = 0
    rows = 0
    ok = 0
    failed = 0
    waiting = 0
    skipped = 0
    undetected = 0
    missingFiles = @()
  }
  $RawDir = Join-Path $OutDir "raw"
  if (-not (Test-Path $RawDir)) {
    $summary.missingFiles = @($requestedMeasures | ForEach-Object { $outputFileByMeasure[$_] })
    return $summary
  }

  foreach ($file in @(Get-ChildItem -Path $RawDir -Filter "*.json" -File -ErrorAction SilentlyContinue)) {
    try {
      $parsed = Get-Content -Raw -Path $file.FullName | ConvertFrom-Json
      $rows = if ($parsed -is [System.Array]) { $parsed } else { @($parsed) }
      $summary.files += 1
      foreach ($row in $rows) {
        $summary.rows += 1
        $status = if ($null -ne $row.PSObject.Properties["status"]) { [string]$row.status } else { "" }
        switch ($status) {
          "ok" { $summary.ok += 1 }
          "success" { $summary.ok += 1 }
          "failed" { $summary.failed += 1 }
          "failure" { $summary.failed += 1 }
          "waiting" { $summary.waiting += 1 }
          "skipped" { $summary.skipped += 1 }
        }
        if (
          $null -ne $row.PSObject.Properties["detected"] -and
          $row.detected -eq $false -and
          $status -ne "skipped"
        ) {
          $summary.undetected += 1
        }
      }
    } catch {
      # A measurement may be replacing its JSON file while the watchdog reads it.
    }
  }
  $summary.missingFiles = @(
    $requestedMeasures |
      ForEach-Object { $outputFileByMeasure[$_] } |
      Where-Object { -not (Test-Path (Join-Path $RawDir $_)) }
  )
  return $summary
}

function Get-DockerIssues {
  if ($SkipDocker) {
    return @()
  }
  $issues = @()
  foreach ($status in @("exited", "dead")) {
    try {
      $services = @(& docker compose ps --status $status --services 2>$null)
      foreach ($service in $services) {
        if (-not [string]::IsNullOrWhiteSpace($service)) {
          $issues += "$service ($status)"
        }
      }
    } catch {
      $issues += "docker compose status unavailable"
    }
  }
  return @($issues | Select-Object -Unique)
}

function Get-DiagnosticSignals {
  $patterns = 'NONCE_EXPIRED|Nonce too low|ECONNRESET|socket hang up|request body exceeds|HTTP 413|peer .+ held'
  $lines = @((Get-LogTail $StdoutPath) + (Get-LogTail $StderrPath))
  return @($lines | Select-String -Pattern $patterns | ForEach-Object { $_.Line } | Select-Object -Unique)
}

function Get-LastLogWriteUtc {
  $times = @($StdoutPath, $StderrPath) |
    Where-Object { Test-Path $_ } |
    ForEach-Object { (Get-Item $_).LastWriteTimeUtc }
  if ($times.Count -eq 0) {
    return $startedAt.ToUniversalTime()
  }
  return ($times | Sort-Object -Descending | Select-Object -First 1)
}

function Write-FailureContext([int]$ExitCode, $ResultSummary, [string[]]$DockerIssues, [string[]]$Signals) {
  $lines = @(
    "exitCode=$ExitCode",
    "failedRows=$($ResultSummary.failed)",
    "waitingRows=$($ResultSummary.waiting)",
    "skippedRows=$($ResultSummary.skipped)",
    "undetectedRows=$($ResultSummary.undetected)",
    "missingFiles=$($ResultSummary.missingFiles -join ', ')",
    "dockerIssues=$($DockerIssues -join ', ')",
    "diagnosticSignals=$($Signals -join ' | ')",
    "",
    "=== stdout tail ==="
  )
  $lines += Get-LogTail $StdoutPath 100
  $lines += ""
  $lines += "=== stderr tail ==="
  $lines += Get-LogTail $StderrPath 100
  $lines | Set-Content -Path $FailureContextPath -Encoding utf8
}

$runnerPath = Join-Path $PSScriptRoot "run-local.ps1"
$commandParts = @(
  "& $(ConvertTo-PowerShellLiteral $runnerPath)",
  "-Mode $(ConvertTo-PowerShellLiteral $Mode)",
  "-OutDir $(ConvertTo-PowerShellLiteral $OutDir)"
)
if ($Measures.Count -gt 0) {
  $measureLiterals = $Measures | ForEach-Object { ConvertTo-PowerShellLiteral $_ }
  $commandParts += "-Measures @($($measureLiterals -join ', '))"
}
if ($Repeats -gt 0) {
  $commandParts += "-Repeats $Repeats"
}
if ($SkipDocker) {
  $commandParts += "-SkipDocker"
}
if ($NoBuild) {
  $commandParts += "-NoBuild"
}
$runnerInvocation = $commandParts -join " "
$childCommand = @(
  '$ErrorActionPreference = "Stop"'
  '$runnerExitCode = 0'
  'try {'
  "  $runnerInvocation"
  '  if ($null -ne $LASTEXITCODE) { $runnerExitCode = $LASTEXITCODE }'
  '} catch {'
  '  Write-Error ($_ | Out-String)'
  '  $runnerExitCode = 1'
  '} finally {'
  "  [IO.File]::WriteAllText($(ConvertTo-PowerShellLiteral $RunnerExitCodePath), [string]`$runnerExitCode)"
  '}'
  'exit $runnerExitCode'
) -join [Environment]::NewLine
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))

$process = Start-Process -FilePath "powershell.exe" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encodedCommand) `
  -WorkingDirectory $Root `
  -WindowStyle Hidden `
  -RedirectStandardOutput $StdoutPath `
  -RedirectStandardError $StderrPath `
  -PassThru

$nextSummaryAt = (Get-Date).AddMinutes($SummaryIntervalMinutes)
$lastSignalCount = 0
$lastWarningKey = ""
$lastDockerIssues = @()
$pollCount = 0

Write-Host "[watch] started PID $($process.Id)"
Write-Host "[watch] output: $OutDir"
Write-Host "[watch] compact status: $StatusPath"
Write-Host "[watch] progress summary interval: $SummaryIntervalMinutes minutes"

Write-Status ([ordered]@{
  state = "starting"
  mode = $Mode
  phase = "startup"
  processId = $process.Id
  startedAt = $startedAt.ToString("o")
  updatedAt = (Get-Date).ToString("o")
  nextSummaryAt = $nextSummaryAt.ToString("o")
  summaryIntervalMinutes = $SummaryIntervalMinutes
  results = Get-ResultSummary
  paths = [ordered]@{
    stdout = $StdoutPath
    stderr = $StderrPath
    failureContext = $FailureContextPath
  }
})

while (-not $process.HasExited) {
  Start-Sleep -Seconds $WatchdogPollSeconds
  $process.Refresh()
  $pollCount += 1

  $now = Get-Date
  $phase = Get-CurrentPhase
  $results = Get-ResultSummary
  $signals = Get-DiagnosticSignals
  if ($pollCount % 5 -eq 0) {
    $lastDockerIssues = @(Get-DockerIssues)
  }
  $dockerIssues = $lastDockerIssues
  $lastLogWriteUtc = Get-LastLogWriteUtc
  $stalled = ($now.ToUniversalTime() - $lastLogWriteUtc).TotalMinutes -ge $StallWarningMinutes
  $emitSummary = $now -ge $nextSummaryAt
  if ($emitSummary) {
    $nextSummaryAt = $now.AddMinutes($SummaryIntervalMinutes)
  }

  $state = if ($dockerIssues.Count -gt 0 -or $stalled) { "running-with-warning" } else { "running" }
  Write-Status ([ordered]@{
    state = $state
    mode = $Mode
    phase = $phase
    processId = $process.Id
    startedAt = $startedAt.ToString("o")
    updatedAt = $now.ToString("o")
    lastLogWriteAt = $lastLogWriteUtc.ToString("o")
    nextSummaryAt = $nextSummaryAt.ToString("o")
    summaryIntervalMinutes = $SummaryIntervalMinutes
    stalled = $stalled
    dockerIssues = @($dockerIssues)
    diagnosticSignalCount = $signals.Count
    results = $results
    paths = [ordered]@{
      stdout = $StdoutPath
      stderr = $StderrPath
      failureContext = $FailureContextPath
    }
  })

  $newSignal = $signals.Count -gt $lastSignalCount
  $warningKey = "$($signals.Count)|$($dockerIssues -join ',')|$stalled"
  if (($newSignal -or $dockerIssues.Count -gt 0 -or $stalled) -and $warningKey -ne $lastWarningKey) {
    Write-Warning "[watch] phase=$phase signals=$($signals.Count) dockerIssues=$($dockerIssues.Count) stalled=$stalled"
    $lastWarningKey = $warningKey
  } elseif ($emitSummary) {
    Write-Host "[watch] phase=$phase rows=$($results.rows) failed=$($results.failed) waiting=$($results.waiting)"
  }
  if ($signals.Count -eq 0 -and $dockerIssues.Count -eq 0 -and -not $stalled) {
    $lastWarningKey = ""
  }
  $lastSignalCount = $signals.Count
}

$process.WaitForExit()
$process.Refresh()
$exitCode = if (Test-Path $RunnerExitCodePath) {
  [int](Get-Content -Raw -Path $RunnerExitCodePath).Trim()
} elseif ($null -ne $process.ExitCode) {
  [int]$process.ExitCode
} else {
  1
}
$finishedAt = Get-Date
$results = Get-ResultSummary
$signals = Get-DiagnosticSignals
$dockerIssues = Get-DockerIssues
$skippedIsIssue = $Mode -eq "full" -and -not $SkipDocker -and $results.skipped -gt 0
$hasResultIssues = `
  $results.failed -gt 0 -or `
  $results.waiting -gt 0 -or `
  $results.undetected -gt 0 -or `
  $results.missingFiles.Count -gt 0 -or `
  $skippedIsIssue
$finalState = if ($exitCode -ne 0) {
  "failed"
} elseif ($hasResultIssues) {
  "completed-with-issues"
} else {
  "completed"
}

if ($finalState -ne "completed") {
  Write-FailureContext $exitCode $results $dockerIssues $signals
}

Write-Status ([ordered]@{
  state = $finalState
  mode = $Mode
  phase = "finished"
  processId = $process.Id
  exitCode = $exitCode
  startedAt = $startedAt.ToString("o")
  finishedAt = $finishedAt.ToString("o")
  durationSeconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 3)
  summaryIntervalMinutes = $SummaryIntervalMinutes
  dockerIssues = @($dockerIssues)
  diagnosticSignalCount = $signals.Count
  results = $results
  paths = [ordered]@{
    stdout = $StdoutPath
    stderr = $StderrPath
    failureContext = $FailureContextPath
  }
})

Write-Host "[watch] state=$finalState exitCode=$exitCode rows=$($results.rows) failed=$($results.failed) waiting=$($results.waiting) skipped=$($results.skipped)"
Write-Host "[watch] status: $StatusPath"

if ($finalState -ne "completed") {
  exit 1
}
