"""Prepare matched disposable local/Vault configurations for custody experiments.

An already initialized Vault Transit service and administrative research token
are required. This does not deploy Vault or establish hardware-backed custody.
"""
import argparse
import json
import os
from pathlib import Path
import time

from prepare_research import prepare
from prepare_vault_research import prepare_vault
from vendorchain.crypto import canonical, decode
from vendorchain.evidence import sha, sign_document
from vendorchain.kms import VaultSigner, VaultTransit
from make_custody_plan import make_plan


def prepare_custody(root, *, address_env='VAULT_ADDR', token_env='VAULT_TOKEN'):
    """Create fresh configurations; preserve one common Cosign file key."""
    # Fail before writing keys if service credentials have not been supplied.
    address, token = os.environ[address_env], os.environ[token_env]
    if not address or not token:
        raise ValueError('Vault address and token must be nonempty')
    root = Path(root).resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    local_path = prepare(root / 'localkeys')
    remote_path = prepare_vault(root / 'vaultkeys', address_env=address_env, token_env=token_env)
    local = json.loads(local_path.read_text())
    remote = json.loads(remote_path.read_text())
    common = dict(local['provenance'])
    for field in ('privateURI', 'publicFile'):
        common[field] = str((local_path.parent / common[field]).resolve())
    remote['provenance'] = common
    policy_path = remote_path.parent / remote['policyBundle']
    envelope = json.loads(policy_path.read_text())
    document = json.loads(decode(envelope['payload']))['document']
    document['provenanceTrust'] = {'mode': 'pinned-public-key', **{
        name: common[name] for name in ('publicSHA256', 'notBefore', 'notAfter')}}
    registry = json.loads((remote_path.parent / remote['registry']).read_text())
    spec = remote['signers']['policy']
    transit = VaultTransit(address, token, mount=spec.get('mount', 'transit'))
    signer = VaultSigner(transit, spec['key'], spec['version'], decode(registry[spec['keyID']]['publicKey']))
    now = int(time.time())
    expiry = min(common['notAfter'], *(key['notAfter'] for key in registry.values()))
    if expiry <= now:
        raise ValueError('prepared trust expires before the experiment can begin')
    bundle = sign_document(document, signer, spec['keyID'], 'vendorchain.policy.v1',
                           now=now, ttl=expiry-now)
    policy_path.write_bytes(canonical(bundle))
    remote_path.write_text(json.dumps(remote, indent=2) + '\n')
    registration_path = remote_path.parent / 'ledger-registration.json'
    registration = json.loads(registration_path.read_text())
    registration['policy']['digest'] = sha(canonical(bundle))
    registration['policy']['notAfter'] = expiry
    registration_path.write_bytes(canonical(registration))
    for name in ('cosign.key', 'cosign.pub'):
        (remote_path.parent / name).unlink()
    # Public-only validation catches policy or source drift before returning.
    make_plan(local_path, remote_path)
    return local_path, remote_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    local, vault = prepare_custody(args.output)
    print(json.dumps({'localConfig': str(local), 'vaultConfig': str(vault),
                      'custody': 'software Vault Transit; shared local Cosign file key; no HSM claim'}))


if __name__ == '__main__':
    main()
