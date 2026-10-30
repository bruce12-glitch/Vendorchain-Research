#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 1
mkdir -p "$ROOT/.runtime/bin"
archive="$ROOT/.runtime/syft-1.55.0.tar.gz"
curl --fail --location --retry 3 https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz --output "$archive"
echo "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d  $archive" | sha256sum --check -
tar -xzf "$archive" -C "$ROOT/.runtime/bin" syft
