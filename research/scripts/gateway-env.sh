#!/usr/bin/env bash
# Source this file. It exports credential PATHS and never prints key contents.
VC_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VC_NET="${VENDORCHAIN_NETWORK_DIR:-$VC_ROOT/.runtime/fabric-samples}"
VC_ORG="$VC_NET/test-network/organizations/peerOrganizations/org1.example.com"
export FABRIC_PEER_ENDPOINT=localhost:7051
export FABRIC_PEER_HOST_ALIAS=peer0.org1.example.com
export FABRIC_TLS_CERT="$VC_ORG/peers/peer0.org1.example.com/tls/ca.crt"
export FABRIC_ID_CERT="$VC_ORG/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem"
VC_KEYS=("$VC_ORG/users/Admin@org1.example.com/msp/keystore/"*)
[[ ${#VC_KEYS[@]} -eq 1 && -f ${VC_KEYS[0]} ]] || { echo 'Expected exactly one enrollment key.' >&2; return 1; }
export FABRIC_ID_KEY="${VC_KEYS[0]}"
export FABRIC_MSP_ID=Org1MSP FABRIC_CHANNEL=vendorchain
export FABRIC_GATEWAY_URL=http://127.0.0.1:8091
unset VC_KEYS VC_ROOT VC_NET VC_ORG
