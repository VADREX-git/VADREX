param(
  [string]$ManifestPath = "",
  [string]$Ref = "HEAD"
)

# Computes sourceTreeHash, a content hash over the files that take part in a reproduction.
#
# A commit hash cannot serve as the link between results and source: it changes with the author
# and the timestamp, so anonymising the history or recreating an orphan commit would leave the
# published results pointing at a commit that no longer exists. This hash covers only the file
# contents named in eval/reference/source-manifest.txt, so the licence, the documentation and the
# author line can all change later without invalidating it.
#
# The per-file contribution is the blob hash git has already computed. Reading the working tree
# instead would make the value depend on line-ending translation and encoding.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
  $ManifestPath = Join-Path $PSScriptRoot "source-manifest.txt"
}
if (-not (Test-Path $ManifestPath)) {
  throw "manifest not found: $ManifestPath"
}

$entries = @(
  Get-Content -Path $ManifestPath -Encoding UTF8 |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" -and -not $_.StartsWith("#") }
)

# Only files git tracks are considered, which excludes build output and ignored files.
$blobByPath = @{}
foreach ($entry in $entries) {
  foreach ($line in @(git ls-tree -r $Ref -- $entry)) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }
    # "<mode> blob <sha1>`t<path>"
    $parts = $line -split "`t", 2
    $blobByPath[$parts[1]] = ($parts[0] -split '\s+')[2]
  }
}
if ($blobByPath.Count -eq 0) {
  throw "manifest matched no tracked files at $Ref"
}

$builder = New-Object System.Text.StringBuilder
foreach ($path in ($blobByPath.Keys | Sort-Object -CaseSensitive)) {
  [void]$builder.Append($blobByPath[$path]).Append("  ").Append($path).Append("`n")
}

$sha = [System.Security.Cryptography.SHA256]::Create()
try {
  $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($builder.ToString()))
} finally {
  $sha.Dispose()
}
$sourceTreeHash = ([BitConverter]::ToString($digest) -replace '-', '').ToLower()

Write-Host "ref:            $Ref"
Write-Host "files:          $($blobByPath.Count)"
Write-Host "sourceTreeHash: $sourceTreeHash"
