#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT_DIR="$SCRIPT_DIR/out"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for ca-setup.sh. On Windows PowerShell, run scripts/ca-setup.ps1 instead." >&2
  exit 1
fi

rm -rf "$OUT_DIR/ca" "$OUT_DIR/openssl"
for inst in a b; do
  if [ -d "$OUT_DIR/inst-$inst" ]; then
    rm -f \
      "$OUT_DIR/inst-$inst/ca.cert.pem" \
      "$OUT_DIR/inst-$inst/cert.csr.pem" \
      "$OUT_DIR/inst-$inst/cert.pem" \
      "$OUT_DIR/inst-$inst/client.p12" \
      "$OUT_DIR/inst-$inst/key.pem" \
      "$OUT_DIR/inst-$inst/tls.pem"
  fi
done
mkdir -p "$OUT_DIR/ca" "$OUT_DIR/inst-a" "$OUT_DIR/inst-b" "$OUT_DIR/openssl"

cat > "$OUT_DIR/openssl/ca.cnf" <<'EOF'
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
EOF

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$OUT_DIR/ca/ca.key.pem" \
  -out "$OUT_DIR/ca/ca.cert.pem" \
  -config "$OUT_DIR/openssl/ca.cnf"

make_cert() {
  inst="$1"
  cn="$2"
  dns="$3"
  cat > "$OUT_DIR/openssl/inst-$inst.cnf" <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[ dn ]
CN = $cn
O = VADREX Prototype

[ v3_req ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = $dns,IP:127.0.0.1
EOF

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$OUT_DIR/inst-$inst/key.pem" \
    -out "$OUT_DIR/inst-$inst/cert.csr.pem" \
    -config "$OUT_DIR/openssl/inst-$inst.cnf"

  openssl x509 -req -sha256 -days 825 \
    -in "$OUT_DIR/inst-$inst/cert.csr.pem" \
    -CA "$OUT_DIR/ca/ca.cert.pem" \
    -CAkey "$OUT_DIR/ca/ca.key.pem" \
    -CAcreateserial \
    -out "$OUT_DIR/inst-$inst/cert.pem" \
    -extensions v3_req \
    -extfile "$OUT_DIR/openssl/inst-$inst.cnf"

  cat "$OUT_DIR/inst-$inst/key.pem" "$OUT_DIR/inst-$inst/cert.pem" > "$OUT_DIR/inst-$inst/tls.pem"
  openssl pkcs12 -export \
    -in "$OUT_DIR/inst-$inst/cert.pem" \
    -inkey "$OUT_DIR/inst-$inst/key.pem" \
    -out "$OUT_DIR/inst-$inst/client.p12" \
    -legacy \
    -passout pass:vadrex
  cp "$OUT_DIR/ca/ca.cert.pem" "$OUT_DIR/inst-$inst/ca.cert.pem"
}

make_cert "a" "orthanc-a" "DNS:orthanc-a,DNS:gateway-a,DNS:localhost"
make_cert "b" "orthanc-b" "DNS:orthanc-b,DNS:gateway-b,DNS:localhost"

echo "Generated CA and institution certificates under $OUT_DIR"
