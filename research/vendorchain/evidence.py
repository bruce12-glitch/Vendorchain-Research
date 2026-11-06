"""Versioned H1-H4 evidence. Only digest receipts are sent to the ledger.

All signed JSON uses crypto.canonical. Equation 13 uses five ordered SHA-256
digests followed by an unsigned 64-bit big-endian Unix timestamp. This explicit
encoding prevents ambiguous concatenation; all evidence documents stay off-chain.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .crypto import canonical, encode, decode

HEX = re.compile(r'[a-f0-9]{64}')
ROOT_FIELDS = ('ciphertextHash','sbomHash','artifactHash','identityHash','snapshotHash')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sign_document(document, signer, key_id, domain, *, now=None, ttl=600):
    now = int(time.time()) if now is None else now
    body = {'domain':domain,'keyID':key_id,'issuedAt':now,'expiresAt':now+ttl,'document':document}
    raw = canonical(body)
    return {'payload':encode(raw),'signature':encode(signer.sign(raw))}


def verify_document(envelope, registry, domain, role, *, now=None):
    now = int(time.time()) if now is None else now
    raw = decode(envelope['payload'])
    if len(raw) > 2*1024*1024:
        raise ValueError('evidence document too large')
    body = json.loads(raw)
    if canonical(body) != raw or set(body) != {'domain','keyID','issuedAt','expiresAt','document'} or body['domain'] != domain:
        raise ValueError('non-canonical or wrong-domain evidence')
    key = registry[body['keyID']]
    if key.get('role') != role or key.get('revoked'):
        raise ValueError('wrong-role or revoked evidence key')
    issued, expiry = body['issuedAt'], body['expiresAt']
    if type(issued) is not int or type(expiry) is not int or not (
            key['notBefore'] <= issued <= now+30 and issued < expiry <= key['notAfter']
            and key['notBefore'] <= now < key['notAfter'] and now < expiry):
        raise ValueError('evidence/key outside validity interval')
    Ed25519PublicKey.from_public_bytes(decode(key['publicKey'])).verify(decode(envelope['signature']), raw)
    return body['document']


def evidence_root(hashes, issued_at):
    if any(not isinstance(hashes.get(k), str) or not HEX.fullmatch(hashes[k]) for k in ROOT_FIELDS):
        raise ValueError('evidence root requires five SHA-256 digests')
    if type(issued_at) is not int or not 0 <= issued_at < 2**63:
        raise ValueError('invalid evidence timestamp')
    return sha(b''.join(bytes.fromhex(hashes[k]) for k in ROOT_FIELDS)+issued_at.to_bytes(8,'big'))


def tree_hash(source):
    root = Path(source).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('artifact source must be a directory')
    rows = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('artifact tree may not contain symlinks')
        if path.is_file():
            h = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda:stream.read(65536), b''):
                    h.update(chunk)
            rows.append({'path':path.relative_to(root).as_posix(),'sha256':h.hexdigest()})
    if not rows:
        raise ValueError('artifact tree is empty')
    return sha(canonical(rows))


class SignedPolicy:
    def __init__(self, path, registry):
        self.path, self.registry = Path(path), registry

    def load(self):
        envelope = json.loads(self.path.read_text())
        policy = verify_document(envelope, self.registry, 'vendorchain.policy.v1', 'policy')
        source = decode(policy['source'])
        if sha(source) != policy['policySHA256']:
            raise ValueError('signed policy source hash mismatch')
        if policy['query'] != 'data.vendorchain.authorization.allow':
            raise ValueError('unexpected authorization query')
        return policy, source, sha(canonical(envelope))

    def evaluate(self, facts):
        # Read and verify exact bytes, then evaluate that private snapshot. An
        # administrator replacing the bundle cannot change an in-flight eval.
        policy, source, bundle_hash = self.load()
        version_text = subprocess.run(['opa','version'],capture_output=True, timeout=10, check=True).stdout.decode()
        match = re.search(r'^Version:\s*(\S+)', version_text, re.MULTILINE)
        if not match:
            raise ValueError('OPA version unavailable')
        actual = match[1]
        if actual != policy['opaVersion']:
            raise ValueError('OPA version differs from signed policy manifest')
        validate_facts(facts)
        if facts['policy'] != policy['parameters']:
            raise ValueError('policy parameters differ from signed bundle')
        with tempfile.TemporaryDirectory(prefix='vendorchain-policy-') as tmp:
            file = Path(tmp)/'policy.rego'
            file.write_bytes(source)
            compatibility = ['--v0-compatible'] if actual.split('.')[0] != '0' else []
            command = ['opa','eval',*compatibility,'--stdin-input','--format=json','--data',str(file),policy['query']]
            result = subprocess.run(command, input=canonical(facts), capture_output=True, timeout=10, check=True)
        expressions = json.loads(result.stdout).get('result', [])
        if len(expressions) != 1 or len(expressions[0].get('expressions', [])) != 1:
            raise ValueError('OPA returned no single authorization decision')
        value = expressions[0]['expressions'][0]['value']
        if type(value) is not bool:
            raise ValueError('OPA returned a non-boolean verdict')
        return value, bundle_hash, policy


def validate_facts(facts):
    """Prevent undefined fields from vacuously satisfying Rego's negations."""
    for section, names in {'sbom':('present',),'provenance':('signature_valid','certificate_approved','certificate_expired','artifact_digest_bound'),
                           'replay':('detected',)}.items():
        for name in names:
            if type(facts[section][name]) is not bool:
                raise ValueError('missing/non-boolean policy evidence')
    sbom = facts['sbom']
    components = sbom['components']
    if (type(sbom['component_count']) is not int or not isinstance(components,list)
            or sbom['component_count'] != len(components) or any(not isinstance(c.get('name'),str) for c in components)
            or type(facts['policy']['max_components']) is not int or facts['policy']['max_components'] < 1
            or not isinstance(facts['policy']['banned_packages'],list)
            or any(not isinstance(p,str) for p in facts['policy']['banned_packages'])
            or sbom['schema'] != 'cyclonedx' or facts['identity']['state'] not in ('verified','failed','flagged')):
        raise ValueError('inconsistent policy evidence')


def verify_receipt(payload, registry, now=None):
    now = int(time.time()) if now is None else now
    raw = decode(payload['receipt'])
    receipt = json.loads(raw)
    if canonical(receipt) != raw or receipt['version'] != 'vendorchain.receipt.v2':
        raise ValueError('invalid hardened receipt encoding/version')
    if (receipt['recordID'] != payload['recordID'] or receipt['nonce'] != payload['recordID']
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', receipt['recordID'])
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', receipt['vendorID'])
            or receipt['decision'] not in ('PASS','FAIL') or receipt['algorithm'] != 'sha256'
            or sha(raw) != payload['receiptHash'] or not HEX.fullmatch(receipt['policyHash'])
            or not HEX.fullmatch(receipt['documentHash'])
            or receipt['evidenceRoot'] != evidence_root(receipt, receipt['issuedAt'])):
        raise ValueError('hardened receipt context/root mismatch')
    key = registry[receipt['keyID']]
    if key.get('role') != 'decision' or key.get('revoked') or not (
            key['notBefore'] <= receipt['issuedAt'] <= now+30 and key['notBefore'] <= now < key['notAfter']
            and now < receipt['expiresAt'] <= key['notAfter']
            and 0 < receipt['expiresAt']-receipt['issuedAt'] <= 3600):
        raise ValueError('inactive decision key or receipt')
    public = Ed25519PublicKey.from_public_bytes(decode(key['publicKey']))
    public.verify(decode(payload['signature']), raw)
    public.verify(decode(payload['snapshotSignature']), bytes.fromhex(receipt['snapshotHash']))
    return receipt
