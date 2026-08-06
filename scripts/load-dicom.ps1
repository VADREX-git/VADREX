param(
  [string]$DicomPath = "",
  [string]$OrthancUrl = "https://localhost:8042"
)

# Loads DICOM into Orthanc A.
#
# The default is the synthetic generator in this repository. Downloading a sample from an
# upstream URL was dropped: reproduction would break whenever upstream changed. Pass -DicomPath
# to use your own file.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

if ([string]::IsNullOrWhiteSpace($DicomPath)) {
  npx tsx (Join-Path $PSScriptRoot "make-sample-dicom.ts")
  if ($LASTEXITCODE -ne 0) {
    throw "make-sample-dicom failed with exit code $LASTEXITCODE"
  }
  exit 0
}

npx tsx (Join-Path $PSScriptRoot "dicomweb-stow.ts") --file $DicomPath --url $OrthancUrl --institution a
if ($LASTEXITCODE -ne 0) {
  throw "dicomweb-stow failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Uploaded $DicomPath to $OrthancUrl via DICOMweb STOW-RS"
Write-Host "Check with:"
Write-Host "  npx tsx .\scripts\orthanc-get.ts --url $OrthancUrl/dicom-web/studies --institution a"
