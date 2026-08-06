param(
  [Parameter(Mandatory = $true)]
  [string]$RunDir,
  [switch]$Rebuild
)

# Renders the six figures from a run's results.
#
# The plotting runs in a pinned image (docker/Dockerfile.plot) so Python is not a host
# prerequisite; the exact versions are in eval/plot/requirements.txt.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$RunPath = (Resolve-Path $RunDir).Path
$ImageTag = "vadrex-plot:local"

# The image bakes in eval/plot/*.py, so skipping the build when the image exists would keep
# running an old copy and quietly produce stale figures. With no changes the cache makes this
# take seconds, so it is built every time.
Write-Host "[plot] building $ImageTag"
docker build -f (Join-Path $Root "docker\Dockerfile.plot") -t $ImageTag $Root
if ($LASTEXITCODE -ne 0) {
  throw "plot image build failed with exit code $LASTEXITCODE"
}

$Figures = Join-Path $RunPath "figures"
New-Item -ItemType Directory -Force -Path $Figures | Out-Null

$plots = @(
  @{ Script = "plot_scaling.py"; Input = "scaling.csv"; Output = "scaling.png" },
  @{ Script = "plot_revocation_delay.py"; Input = "revocation_delay.csv"; Output = "revocation_delay.png" },
  @{ Script = "plot_handshake_overhead.py"; Input = "handshake_overhead.csv"; Output = "handshake_overhead.png" },
  @{ Script = "plot_verify_cost.py"; Input = "verify_cost.csv"; Output = "verify_cost.png" },
  @{ Script = "plot_grace_window.py"; Input = "grace_window.csv"; Output = "grace_window.png" },
  @{ Script = "plot_attack_injection.py"; Input = "attack_injection.csv"; Output = "attack_injection.png" }
)

foreach ($plot in $plots) {
  Write-Host "[plot] $($plot.Script)"
  docker run --rm -v "${RunPath}:/run" $ImageTag "/plot/$($plot.Script)" `
    --input "/run/raw/$($plot.Input)" --output "/run/figures/$($plot.Output)"
  if ($LASTEXITCODE -ne 0) {
    throw "$($plot.Script) failed with exit code $LASTEXITCODE"
  }
}

Write-Host "[plot] figures written to $Figures"
