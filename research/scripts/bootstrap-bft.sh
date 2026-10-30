#!/usr/bin/env bash
# Disposable Linux/WSL2 research network only. Does not touch an existing network.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NET="${VENDORCHAIN_NETWORK_DIR:-$ROOT/.runtime/fabric-samples}"
SAMPLES_COMMIT=5789681b4f4d24e58fa40f19a69f5496892374b6
FABRIC_VERSION=3.1.5
command -v docker >/dev/null
command -v go >/dev/null
command -v curl >/dev/null
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'This pinned bootstrap targets Linux amd64 / WSL2.' >&2; exit 1; }
# Refuse to interfere with any pre-existing Fabric test network.
if [[ -n $(docker ps -aq --filter label=service=hyperledger-fabric) ]]; then
  echo 'A Fabric sample network already exists; use an isolated Docker host.' >&2; exit 1
fi
mkdir -p "$ROOT/.runtime"
if [[ ! -d "$NET" ]]; then
  git clone --no-checkout https://github.com/hyperledger/fabric-samples.git "$NET"
  git -C "$NET" checkout --detach "$SAMPLES_COMMIT"
fi
[[ $(git -C "$NET" rev-parse HEAD) == "$SAMPLES_COMMIT" ]] || { echo 'Unexpected fabric-samples revision.' >&2; exit 1; }
ARCHIVE="$ROOT/.runtime/fabric-$FABRIC_VERSION.tar.gz"
curl --fail --location --retry 3 "https://github.com/hyperledger/fabric/releases/download/v$FABRIC_VERSION/hyperledger-fabric-linux-amd64-$FABRIC_VERSION.tar.gz" --output "$ARCHIVE"
echo "b9c31fd490991e76f8acb1835dee09fc19fee5428cb13e190ee6e0bdd2c37858  $ARCHIVE" | sha256sum --check -
tar -xzf "$ARCHIVE" -C "$NET"
for component in peer orderer ccenv baseos; do
  docker pull "hyperledger/fabric-$component:$FABRIC_VERSION"
  # The upstream prerequisites checker references :latest. Services below use the exact tag.
  docker tag "hyperledger/fabric-$component:$FABRIC_VERSION" "hyperledger/fabric-$component:latest"
done
python - "$NET" "$FABRIC_VERSION" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1]);version=sys.argv[2]
for path in (root/'test-network/compose').rglob('*.yaml'):
    text=path.read_text()
    for component in ['peer','orderer','ccenv','baseos']:
        text=text.replace('hyperledger/fabric-'+component+':latest','hyperledger/fabric-'+component+':'+version)
    if 'CORE_CHAINCODE_EXECUTETIMEOUT=300s' in text:
        text=text.replace('- CORE_CHAINCODE_EXECUTETIMEOUT=300s',
            '- CORE_CHAINCODE_EXECUTETIMEOUT=300s\n      - CORE_CHAINCODE_BUILDER=hyperledger/fabric-ccenv:'+version+
            '\n      - CORE_CHAINCODE_RUNTIME=hyperledger/fabric-baseos:'+version)
    path.write_text(text)
PY
cd "$NET/test-network"
./network.sh up createChannel -bft -c vendorchain
./network.sh deployCC -bft -c vendorchain -ccn vendorchain -ccp "$ROOT/chaincode" -ccl go -ccv 1.0 -ccs 1
# Capture the ACTUAL committed configuration, rather than trusting a topology label.
export PATH="$NET/bin:$PATH"
export FABRIC_CFG_PATH="$NET/config"
export CORE_PEER_TLS_ENABLED=true CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="$NET/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$NET/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
peer channel fetch config "$ROOT/.runtime/channel.block" -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com -c vendorchain --tls --cafile "$NET/test-network/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"
configtxlator proto_decode --input "$ROOT/.runtime/channel.block" --type common.Block --output "$ROOT/.runtime/channel-config.json"
python "$ROOT/research/scripts/verify-topology.py" "$ROOT/.runtime/channel-config.json" "$ROOT/.runtime/network-metadata.json"
docker inspect orderer.example.com orderer2.example.com orderer3.example.com orderer4.example.com peer0.org1.example.com peer0.org2.example.com --format '{{.Name}} {{.Image}}' > "$ROOT/.runtime/container-images.txt"
echo 'BFT network and chaincode deployed; see docs/experiments.md for the upload pipeline.'
