#!/usr/bin/env bash
set -euo pipefail
PROJECT_PATH=${1:?Usage: generate-sbom.sh <project-directory> [output-directory]}
OUTPUT_DIR=${2:-outputs}
command -v syft >/dev/null
[[ -d "$PROJECT_PATH" ]] || { echo 'Project directory not found' >&2; exit 1; }
mkdir -p "$OUTPUT_DIR"
TEMP_FILE=$(mktemp "$OUTPUT_DIR/sbom.XXXXXXXX.json")
trap 'rm -f "$TEMP_FILE"' EXIT
syft "dir:$PROJECT_PATH" -o cyclonedx-json > "$TEMP_FILE"
python - "$TEMP_FILE" <<'PY'
import json,sys
with open(sys.argv[1]) as f:
    assert json.load(f).get('bomFormat')=='CycloneDX','Invalid Syft output'
PY
sha256sum "$TEMP_FILE" > "$TEMP_FILE.sha256"
printf '%s\n' "$TEMP_FILE"
trap - EXIT
