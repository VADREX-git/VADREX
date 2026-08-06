param(
  # Pinned by digest. Different host OpenSSL versions produce different certificates and PKCS#12
  # files, which breaks reproduction, so this image is the default path.
  [string]$OpenSslImage = "alpine/openssl@sha256:0b22ba3ac61b6bcc56e34506f1b548281e46986d70e0e539c94a70452b283cff",
  # Use the host openssl instead of docker. Reproduction is not guaranteed in that case.
  [switch]$UseHostOpenSsl
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$out = Join-Path $PSScriptRoot "out"
$caDir = Join-Path $out "ca"
$opensslDir = Join-Path $out "openssl"

foreach ($path in @($caDir, $opensslDir)) {
  if (Test-Path $path) {
    Remove-Item -LiteralPath $path -Recurse -Force
  }
}

foreach ($institution in @("inst-a", "inst-b")) {
  $institutionDir = Join-Path $out $institution
  if (Test-Path $institutionDir) {
    foreach ($name in @("ca.cert.pem", "cert.csr.pem", "cert.pem", "client.p12", "key.pem", "tls.pem")) {
      $target = Join-Path $institutionDir $name
      if (Test-Path $target) {
        Remove-Item -LiteralPath $target -Force
      }
    }
  }
}

New-Item -ItemType Directory -Force -Path $caDir, $opensslDir, (Join-Path $out "inst-a"), (Join-Path $out "inst-b") | Out-Null

function Write-Utf8NoBom {
  param([string]$Path, [string]$Content)
  [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-OpenSsl {
  param([string[]]$Arguments)

  if ($UseHostOpenSsl) {
    $localOpenSsl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $localOpenSsl) {
      throw "-UseHostOpenSsl was given but openssl was not found on PATH"
    }
    & $localOpenSsl.Source @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "openssl failed with exit code $LASTEXITCODE"
    }
    return
  }

  $mountPath = $out
  docker run --rm -v "${mountPath}:/work" -w /work $OpenSslImage @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "dockerized openssl failed with exit code $LASTEXITCODE"
  }
}

$caConfig = @"
[ req ]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[ dn ]
CN = VADREX Local CA
O = VADREX Prototype

[ v3_ca ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
"@

Write-Utf8NoBom -Path (Join-Path $opensslDir "ca.cnf") -Content $caConfig

Invoke-OpenSsl @(
  "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650", "-nodes",
  "-keyout", "ca/ca.key.pem",
  "-out", "ca/ca.cert.pem",
  "-config", "openssl/ca.cnf"
)

function New-InstitutionCertificate {
  param(
    [string]$Name,
    [string]$CommonName,
    [string[]]$DnsNames
  )

  $instDir = "inst-$Name"
  $san = ($DnsNames | ForEach-Object { "DNS:$_" }) + @("IP:127.0.0.1")
  $config = @"
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[ dn ]
CN = $CommonName
O = VADREX Prototype

[ v3_req ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = $($san -join ",")
"@

  Write-Utf8NoBom -Path (Join-Path $opensslDir "$instDir.cnf") -Content $config

  Invoke-OpenSsl @(
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", "$instDir/key.pem",
    "-out", "$instDir/cert.csr.pem",
    "-config", "openssl/$instDir.cnf"
  )

  Invoke-OpenSsl @(
    "x509", "-req", "-sha256", "-days", "825",
    "-in", "$instDir/cert.csr.pem",
    "-CA", "ca/ca.cert.pem",
    "-CAkey", "ca/ca.key.pem",
    "-CAcreateserial",
    "-out", "$instDir/cert.pem",
    "-extensions", "v3_req",
    "-extfile", "openssl/$instDir.cnf"
  )

  $keyPath = Join-Path $out "$instDir/key.pem"
  $certPath = Join-Path $out "$instDir/cert.pem"
  $tlsPath = Join-Path $out "$instDir/tls.pem"
  Get-Content -LiteralPath $keyPath, $certPath -Raw | Set-Content -LiteralPath $tlsPath -Encoding ascii

  Invoke-OpenSsl @(
    "pkcs12", "-export",
    "-in", "$instDir/cert.pem",
    "-inkey", "$instDir/key.pem",
    "-out", "$instDir/client.p12",
    "-legacy",
    "-passout", "pass:vadrex"
  )
}

New-InstitutionCertificate -Name "a" -CommonName "orthanc-a" -DnsNames @("orthanc-a", "gateway-a", "localhost")
New-InstitutionCertificate -Name "b" -CommonName "orthanc-b" -DnsNames @("orthanc-b", "gateway-b", "localhost")

Copy-Item -LiteralPath (Join-Path $caDir "ca.cert.pem") -Destination (Join-Path $out "inst-a/ca.cert.pem")
Copy-Item -LiteralPath (Join-Path $caDir "ca.cert.pem") -Destination (Join-Path $out "inst-b/ca.cert.pem")

Write-Host "Generated CA and institution certificates under $out"
Write-Host "Orthanc TLS bundles: scripts/out/inst-a/tls.pem, scripts/out/inst-b/tls.pem"
Write-Host "Windows curl client certificates: scripts/out/inst-a/client.p12, scripts/out/inst-b/client.p12 (password: vadrex)"
