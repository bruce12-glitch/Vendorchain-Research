#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/research" PATH="$ROOT/.runtime/bin:$PATH"
source research/scripts/gateway-env.sh
# Short-lived random secrets; stored only in this process environment.
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export GATEWAY_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
STATE="$ROOT/.runtime/smoke-state"
python -m vendorchain init --state "$STATE"
export MASTER_KEK_HEX="$(cat "$STATE/master.hex")"
node research/gateway/server.mjs register-key "$STATE/worker-public.json"
node research/gateway/server.mjs > "$ROOT/.runtime/gateway.log" 2>&1 &
GATEWAY_PID=$!
python -m vendorchain serve --state "$STATE" --source "$ROOT/chaincode" --workers 2 > "$ROOT/.runtime/api.log" 2>&1 &
API_PID=$!
cleanup() {
  kill "$API_PID" "$GATEWAY_PID" 2>/dev/null || true
  docker start orderer4.example.com >/dev/null || true
}
trap cleanup EXIT
python - <<'PY'
import os,time,urllib.request
for _ in range(60):
    try:
        req=urllib.request.Request('http://127.0.0.1:8090/health',headers={'Authorization':'Bearer '+os.environ['API_TOKEN']})
        with urllib.request.urlopen(req,timeout=2) as r:assert r.status==200
        break
    except Exception:time.sleep(1)
else:raise SystemExit('API did not start')
from vendorchain.corpus import png
from pathlib import Path
Path('.runtime/smoke.png').write_bytes(png())
PY
node research/load.mjs --file .runtime/smoke.png --concurrency 3 --trials 1 --warmups 1 --metadata .runtime/network-metadata.json --output .runtime/bft-healthy
# A crash test is not an active Byzantine/malicious-orderer test.
docker stop orderer4.example.com
node research/load.mjs --file .runtime/smoke.png --concurrency 3 --trials 1 --warmups 0 --metadata .runtime/network-metadata.json --output .runtime/bft-one-crash
python - <<'PY'
import json
from pathlib import Path
for folder in ['bft-healthy','bft-one-crash']:
 rows=[json.loads(l) for l in Path('.runtime',folder,'trials.jsonl').read_text().splitlines()]
 assert rows and all(r['failed']==0 and r['evidence']=='fabric-commit-confirmed' for r in rows),rows
print('BFT healthy + one-orderer crash integration checks passed; publication sweep NOT executed')
PY
