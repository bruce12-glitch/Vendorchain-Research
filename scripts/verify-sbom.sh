#!/usr/bin/env bash
set -euo pipefail

# VendorChain SBOM Verifier
# Usage: ./scripts/verify-sbom.sh <sbom-file>

SBOM_FILE=${1:-}
PUB_KEY="keys/cosign.pub"
BUNDLE_FILE="${SBOM_FILE}.bundle"

if [ -z "$SBOM_FILE" ]; then
  echo "Error: Please provide the SBOM file path"
  echo "Usage: ./scripts/verify-sbom.sh outputs/sbom.json"
  exit 1
fi

if [ ! -f "$BUNDLE_FILE" ]; then
  echo "Error: Bundle file not found at $BUNDLE_FILE. Did you sign it first?"
  exit 1
fi

echo "Verifying SBOM: $SBOM_FILE"

if cosign verify-blob \
  --key "$PUB_KEY" \
  --bundle "$BUNDLE_FILE" \
  "$SBOM_FILE"; then
  echo "RESULT: Signature matches the configured public key"
  echo "Signature verification does not establish software safety or compliance."
else
  echo "RESULT: SBOM VERIFICATION FAILED"
  echo "This SBOM may have been tampered with. Blocking."
  exit 1
fi

