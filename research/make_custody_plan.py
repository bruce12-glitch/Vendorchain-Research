"""Validate matched public configurations and plan a local/Vault custody comparison.

This inspects public manifests, signatures and artifact bytes only. It does not
load private keys, contact Vault, or establish hardware-backed key custody.
"""
import argparse
import json
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from vendorchain.crypto import canonical, decode
from vendorchain.evidence import SignedPolicy, sha, tree_hash
from vendorchain.sandbox import OCR_POLICY


ROLES = ('identity', 'decision', 'policy')


def _path(base, value):
    if not isinstance(value, str) or not value:
        raise ValueError('configuration paths must be nonempty strings')
    return (base / value).resolve()


def _public_configuration(config_path, remote):
    path = Path(config_path).resolve()
    raw = path.read_bytes()
    config = json.loads(raw)
    base = path.parent
    kind = 'vault-transit' if remote else 'research-file'
    if config.get('researchLocalKeys') is not (not remote):
        raise ValueError('researchLocalKeys must declare the actual custody mode')
    if 'postgresDsnEnv' in config:
        raise ValueError('custody comparison requires SQLite; remove postgresDsnEnv')
    if set(config['signers']) != set(ROLES):
        raise ValueError('exactly identity, decision and policy signers are required')
    specs = [config['kek'], *config['signers'].values()]
    for spec in specs:
        if spec.get('kind') != kind:
            raise ValueError('KEK and all three signers must use the declared custody mode')
        if remote:
            for field in ('key', 'addressEnv', 'tokenEnv'):
                if not isinstance(spec.get(field), str) or not spec[field]:
                    raise ValueError('Vault specifications require key/addressEnv/tokenEnv')
            if 'file' in spec:
                raise ValueError('Vault specifications must not contain local key files')
        else:
            _path(base, spec['file'])  # Validate the reference without reading private bytes.
    registry_path = _path(base, config['registry'])
    registry_raw = registry_path.read_bytes()
    registry = json.loads(registry_raw)
    now = int(time.time())
    key_ids = []
    for role in ROLES:
        spec = config['signers'][role]
        if remote and (type(spec.get('version')) is not int or spec['version'] < 1):
            raise ValueError('Vault signers require a positive integer key version')
        key_id = spec['keyID']
        key_ids.append(key_id)
        key = registry[key_id]
        if (key.get('keyID') != key_id or key.get('role') != role or key.get('revoked')
                or not key['notBefore'] <= now < key['notAfter']):
            raise ValueError('configured signer must have an active matching public registry entry')
        Ed25519PublicKey.from_public_bytes(decode(key['publicKey']))
    if len(set(key_ids)) != len(ROLES):
        raise ValueError('worker signer roles require distinct registered keys')
    bundle_path = _path(base, config['policyBundle'])
    policy, _, bundle_sha = SignedPolicy(bundle_path, registry).load()
    if json.loads(decode(json.loads(bundle_path.read_text())['payload']))['keyID'] != config['signers']['policy']['keyID']:
        raise ValueError('policy bundle must use the configured policy signer')
    if policy['identityTrust'] != registry[config['signers']['identity']['keyID']]:
        raise ValueError('signed identity trust must match its configured registry entry')
    retention = config['retentionSeconds']
    if type(retention) is not int or retention < 1:
        raise ValueError('retentionSeconds must be a positive integer')
    if policy['controls'] != {'ocrPolicy': OCR_POLICY, 'replayRetentionSeconds': retention}:
        raise ValueError('signed controls must match the worker OCR and replay configuration')
    provenance = config['provenance']
    expected_trust = {'mode': 'pinned-public-key', **{
        name: provenance[name] for name in ('publicSHA256', 'notBefore', 'notAfter')}}
    if policy['provenanceTrust'] != expected_trust:
        raise ValueError('signed provenance trust differs from configuration')
    public_path = _path(base, provenance['publicFile'])
    if sha(public_path.read_bytes()) != provenance['publicSHA256']:
        raise ValueError('Cosign public file differs from approved publicSHA256')
    if not provenance['notBefore'] <= now < provenance['notAfter']:
        raise ValueError('Cosign public trust must be currently valid')
    if '://' in provenance['privateURI']:
        raise ValueError('both arms require the common local Cosign file key')
    cosign_private_path = _path(base, provenance['privateURI'])
    artifact_sha = tree_hash(_path(base, config['source']))
    semantics = {name: config.get(name) for name in (
        'gstin', 'expectedPan', 'expectedTerms', 'retentionSeconds')}
    if not isinstance(semantics['gstin'], str) or not semantics['gstin']:
        raise ValueError('gstin must be a nonempty string')
    if (not isinstance(semantics['expectedTerms'], list) or not semantics['expectedTerms']
            or any(not isinstance(term, str) or not term for term in semantics['expectedTerms'])):
        raise ValueError('expectedTerms must be nonempty strings')
    # Only identity key material/validity changes inside the signed document.
    # Envelope key ID, timestamps and signature may also differ between arms.
    semantics['signedPolicy'] = {k: v for k, v in policy.items() if k != 'identityTrust'}
    return {
        'path': path, 'configSHA256': sha(raw), 'registrySHA256': sha(registry_raw),
        'signedPolicySHA256': bundle_sha, 'sourceArtifactSHA256': artifact_sha,
        'semantics': semantics, 'cosignPrivatePath': cosign_private_path,
        'cosignPublicSHA256': provenance['publicSHA256'],
    }


def make_plan(local_config, vault_config):
    """Return an experiment.py plan, rejecting unmatched or mixed-custody arms."""
    local = _public_configuration(local_config, False)
    vault = _public_configuration(vault_config, True)
    if local['sourceArtifactSHA256'] != vault['sourceArtifactSHA256']:
        raise ValueError('source artifact trees must be identical')
    if local['semantics'] != vault['semantics']:
        raise ValueError('identity expectations and signed policy semantics must match')
    if local['cosignPrivatePath'] != vault['cosignPrivatePath']:
        raise ValueError('both arms must reference the same local Cosign private file')
    worker = str(Path(__file__).resolve().with_name('table12_worker.py'))
    tasks = []
    configurations = {}
    for name, inspected in (('localkeys', local), ('vaultkeys', vault)):
        command = [sys.executable, worker, '--variant', 'full', '--config',
                   str(inspected['path']), '--local']
        if name == 'localkeys':
            command.append('--allow-local-keys')
        tasks.append({'name': name, 'command': command, 'timeoutSeconds': 300})
        configurations[name] = {key: inspected[key] for key in (
            'configSHA256', 'registrySHA256', 'signedPolicySHA256', 'sourceArtifactSHA256')}
    return {
        'kind': 'matched-local-vault-custody', 'tasks': tasks,
        'comparisons': [{'name': name, 'control': 'localkeys', 'treatment': 'vaultkeys', 'metric': metric}
                        for name, metric in [('vault_custody_cost', 'elapsed_ms'),
                          ('vault_encryption_stage_cost', 'encrypt_ms'),
                          ('vault_decryption_stage_cost', 'decrypt_ms'),
                          ('vault_identity_stage_cost', 'identity_attestation_ms'),
                          ('vault_decision_stage_cost', 'attest_ms')]],
        'provenance': {
            'configurations': configurations,
            'matchedSemanticsSHA256': sha(canonical(local['semantics'])),
            'commonCosignPublicSHA256': local['cosignPublicSHA256'],
            'ledger': 'local-non-consensus', 'operationalStore': 'SQLite',
            'scope': 'KEK and identity/decision/policy signer custody; shared local Cosign file key',
            'limitations': 'Software Vault Transit service; hardware HSM custody is not established. Configuration/key loading is outside elapsed_ms.',
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-config', required=True)
    parser.add_argument('--vault-config', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    plan = make_plan(args.local_config, args.vault_config)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(plan, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
