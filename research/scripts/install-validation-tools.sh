#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 1
mkdir -p "$ROOT/.runtime/bin"
# Official release checksums, pinned for reproducibility; not a latest-version claim.
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/open-policy-agent/opa/releases/download/v1.4.2/opa_linux_amd64_static \
  --output "$ROOT/.runtime/bin/opa"
echo "2c0ccdbbe0b8e2a5d12d9c42d92f1f34f494ffb32d1f3c4ddc36101be637d66f  $ROOT/.runtime/bin/opa" | sha256sum --check -
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64 \
  --output "$ROOT/.runtime/bin/cosign"
echo "caaad125acef1cb81d58dcdc454a1e429d09a750d1e9e2b3ed1aed8964454708  $ROOT/.runtime/bin/cosign" | sha256sum --check -
chmod 755 "$ROOT/.runtime/bin/opa" "$ROOT/.runtime/bin/cosign"
