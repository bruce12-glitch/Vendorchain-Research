#!/usr/bin/env bash
# One fresh deployment, with sequential load levels. Dedicated Docker host only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
: "${VENDORCHAIN_TRIAL_DIR:?experiment.py must provide a trial output directory}"
export PYTHONPATH="$ROOT/research" PATH="$ROOT/.runtime/bin:$PATH"
export CONSENSUS="${1:-BFT}"
LEVELS="${2:-100,250,500,1000,2500,5000,10000}"
[[ "$CONSENSUS" == BFT || "$CONSENSUS" == etcdraft ]] || { echo 'Invalid consensus' >&2; exit 1; }
python - "$LEVELS" <<'PY'
import sys
levels=[int(n) for n in sys.argv[1].split(',')]
if len(levels)!=len(set(levels)) or any(not 1<=n<=10000 for n in levels):
    raise SystemExit('Unique load levels in [1, 10000] required')
PY
OUT="$VENDORCHAIN_TRIAL_DIR"
mkdir -p "$OUT" "$ROOT/.runtime"
# All trials share container names, ports and sample artifacts on this host.
# Acquire before claiming ownership; a competing runner must never tear us down.
command -v flock >/dev/null || { echo 'Install util-linux flock before running consensus trials' >&2; exit 1; }
exec 9>"/tmp/vendorchain-consensus-${UID}.lock"
flock -n 9 || { echo 'Another consensus trial owns this host' >&2; exit 1; }
STATE=$(mktemp -d "$ROOT/.runtime/consensus-state-XXXXXXXX")
API_PID= GATEWAY_PID= WATCH_PID= NETWORK_OWNED=0
cleanup() {
  for pid in "$WATCH_PID" "$API_PID" "$GATEWAY_PID"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  if [[ "$NETWORK_OWNED" == 1 ]]; then
    (cd "${VENDORCHAIN_NETWORK_DIR:-$ROOT/.runtime/fabric-samples}/test-network" && ./network.sh down -bft) > "$OUT/teardown.log" 2>&1 || true
  fi
  rm -rf -- "$STATE"
}
trap cleanup EXIT
# Bootstrap refuses any existing Fabric network before changing Docker state.
[[ -z $(docker ps -aq --filter label=service=hyperledger-fabric) ]] || { echo 'Dedicated Docker host required' >&2; exit 1; }
NETWORK_OWNED=1
bash research/scripts/bootstrap-bft.sh > "$OUT/bootstrap.log" 2>&1
cp .runtime/network-metadata.json .runtime/channel-config.json .runtime/container-images.txt "$OUT/"
source research/scripts/gateway-env.sh
NET="${VENDORCHAIN_NETWORK_DIR:-$ROOT/.runtime/fabric-samples}"
export PATH="$NET/bin:$PATH" FABRIC_CFG_PATH="$NET/config"
export CORE_PEER_TLS_ENABLED=true CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="$FABRIC_TLS_CERT" CORE_PEER_MSPCONFIGPATH="$(dirname "$(dirname "$FABRIC_ID_CERT")")"
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export GATEWAY_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export COSIGN_PASSWORD=''
python research/prepare_research.py --output "$STATE/deployment" > "$OUT/preparation.json"
node research/gateway/server.mjs register-evidence "$STATE/deployment/ledger-registration.json"
node research/gateway/server.mjs > "$OUT/gateway.log" 2>&1 & GATEWAY_PID=$!
python research/hardened_cli.py serve --config "$STATE/deployment/config.json" --allow-local-keys --workers "${UPLOAD_WORKERS:-8}" > "$OUT/api.log" 2>&1 & API_PID=$!
python research/watch_resources.py --pid "$API_PID" --state "$STATE/deployment/pipeline" --output "$OUT/resources.jsonl" & WATCH_PID=$!
python - <<'PY'
import os,time,urllib.request
from pathlib import Path
from table12_worker import identity_png
for _ in range(60):
    try:
        request=urllib.request.Request('http://127.0.0.1:8090/health',headers={'Authorization':'Bearer '+os.environ['API_TOKEN']})
        with urllib.request.urlopen(request,timeout=2) as response:assert response.status==200
        break
    except Exception:time.sleep(1)
else:raise SystemExit('hardened API did not start')
Path(os.environ['VENDORCHAIN_TRIAL_DIR'],'input.png').write_bytes(identity_png('consensus-load'))
PY
node research/load.mjs --file "$OUT/input.png" --concurrency "$LEVELS" --trials 1 --warmups 0 --unique-png --metadata "$OUT/network-metadata.json" --output "$OUT/load"
FIRST_LEVEL="${LEVELS%%,*}"
python research/verify_evidence_ledger.py --requests "$OUT/load/requests-c$FIRST_LEVEL-t0.json" --output "$OUT/ledger-proof"
# Colocated crash exercise, distinct from malicious Byzantine behavior.
docker stop orderer4.example.com > "$OUT/orderer-crash.log"
docker inspect --format '{{.State.Running}}' orderer4.example.com > "$OUT/orderer-running-before-crash-load.txt"
[[ $(cat "$OUT/orderer-running-before-crash-load.txt") == false ]] || { echo 'Fourth orderer did not stop' >&2; exit 1; }
node research/load.mjs --file "$OUT/input.png" --concurrency 3 --trials 1 --warmups 0 --unique-png --metadata "$OUT/network-metadata.json" --output "$OUT/one-crash"
docker inspect --format '{{.State.Running}}' orderer4.example.com > "$OUT/orderer-running-after-crash-load.txt"
python research/hardened_cli.py reconcile --config "$STATE/deployment/config.json" --allow-local-keys > "$OUT/reconciliation.json"
# Public synthetic evidence only; never copy private keys, tokens, or database credentials.
cp "$STATE/deployment/registry.json" "$STATE/deployment/signed-policy.json" "$STATE/deployment/cosign.pub" "$OUT/"
cp -r "$STATE/deployment/pipeline/evidence" "$STATE/deployment/pipeline/sbom" "$OUT/"
cp -r "$STATE/deployment/pipeline/blobs" "$OUT/encrypted-objects"
python research/summarize_consensus.py --directory "$OUT" --levels "$LEVELS" --consensus "$CONSENSUS"
