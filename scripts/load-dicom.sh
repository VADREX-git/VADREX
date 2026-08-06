#!/usr/bin/env sh
set -eu

# Sample source: pydicom test data CT_small.dcm.
# License: pydicom is distributed under the MIT license.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT_DIR="$SCRIPT_DIR/out"
SAMPLE_DIR="$OUT_DIR/samples"
DICOM_PATH="${1:-$SAMPLE_DIR/CT_small.dcm}"
ORTHANC_URL="${ORTHANC_URL:-https://localhost:8042}"
SAMPLE_URL="https://raw.githubusercontent.com/pydicom/pydicom/main/src/pydicom/data/test_files/CT_small.dcm"

mkdir -p "$SAMPLE_DIR"

if [ ! -f "$DICOM_PATH" ]; then
  curl -L "$SAMPLE_URL" -o "$DICOM_PATH"
fi

BODY="$SAMPLE_DIR/stow.multipart"
BOUNDARY="vadrex-boundary"
{
  printf -- "--%s\r\nContent-Type: application/dicom\r\n\r\n" "$BOUNDARY"
  cat "$DICOM_PATH"
  printf "\r\n--%s--\r\n" "$BOUNDARY"
} > "$BODY"

curl --fail --silent --show-error \
  --cacert "$OUT_DIR/ca/ca.cert.pem" \
  --cert "$OUT_DIR/inst-a/cert.pem" \
  --key "$OUT_DIR/inst-a/key.pem" \
  -H "Content-Type: multipart/related; type=\"application/dicom\"; boundary=$BOUNDARY" \
  --data-binary "@$BODY" \
  "$ORTHANC_URL/dicom-web/studies"

echo
echo "Uploaded $DICOM_PATH to $ORTHANC_URL via DICOMweb STOW-RS"
