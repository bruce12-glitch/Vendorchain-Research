#!/usr/bin/env bash
# One fresh deployment, with sequential load levels. Dedicated Docker host only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
: "${VENDORCHAIN_TRIAL_DIR:?experiment.py must provide a trial output directory}"
export PYTHONPATH="$ROOT/research" PATH="$ROOT/.runtime/bin:$PATH"
export CONSENSUS="${1:-BFT}"
LEVELS="${2:-100,250,500,1000,2500,5000,10000}"
OUT="$VENDORCHAIN_TRIAL_DIR"
mkdir -p "$OUT"
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
node research/load.mjs --file "$OUT/input.png" --concurrency 3 --trials 1 --warmups 0 --unique-png --metadata "$OUT/network-metadata.json" --output "$OUT/one-crash"
python research/hardened_cli.py reconcile --config "$STATE/deployment/config.json" --allow-local-keys > "$OUT/reconciliation.json"
# Public synthetic evidence only; never copy private keys, tokens, or database credentials.
cp "$STATE/deployment/registry.json" "$STATE/deployment/signed-policy.json" "$STATE/deployment/cosign.pub" "$OUT/"
cp -r "$STATE/deployment/pipeline/evidence" "$STATE/deployment/pipeline/sbom" "$OUT/"
cp -r "$STATE/deployment/pipeline/blobs" "$OUT/encrypted-objects"
python - <<'PY'
import json,os
from pathlib import Path
out=Path(os.environ['VENDORCHAIN_TRIAL_DIR']);rows=[json.loads(x) for x in (out/'load/trials.jsonl').read_text().splitlines()]
metrics={};success=True
for r in rows:
    prefix='c'+str(r['concurrency'])
    success &= r['successful']==r['offered'] and r['policyAllowed']==r['successful'] and r['evidence']=='fabric-commit-confirmed'
    metrics[prefix+'_committed_tps']=r['successful']/r['durationSeconds']
    metrics[prefix+'_failed']=r['failed']
    if r['trialMeanMs'] is not None:metrics[prefix+'_latency_ms']=r['trialMeanMs']
crash=json.loads((out/'one-crash/trials.jsonl').read_text().strip())
success &= crash['successful']==3 and crash['policyAllowed']==3
reconciliation=json.loads((out/'reconciliation.json').read_text());success &= reconciliation['divergences']==0
network=json.loads((out/'network-metadata.json').read_text())
(out/'measurement.json').write_text(json.dumps({'successful':bool(success),'metrics':metrics,'evidence':'fabric-commit-confirmed',
 'consensus':network['consensus'],'channelConfigSHA256':network['channelConfigSha256'],'oneOrdererCrashPassed':crash['successful']==3,
 'custody':'research-local-keys','limitations':['colocated development certificates','crash test is not Byzantine attack simulation','private transient state erased after public evidence capture']},indent=2))
PY
