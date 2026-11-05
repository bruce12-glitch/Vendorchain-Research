"""Initialize, serve and reconcile a manuscript H1-H7 experiment deployment."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vendorchain.crypto import canonical, encode, decode
from vendorchain.evidence import SignedPolicy, sign_document, sha
from vendorchain.hardened import CosignProvenance, HardenedPipeline
from vendorchain.kms import VaultTransit, VaultSigner, VaultWrapper
from vendorchain.ledger import LocalLedger, FabricLedger
from vendorchain.pipeline import durable_write
from vendorchain.store import Store


def initialize(root, *, opa_version='1.4.2'):
    """Disposable research keys only. Explicitly labeled, never HSM evidence."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = int(time.time())
    registry, signers = {}, {}
    for role in ('identity','decision','policy'):
        key = Ed25519PrivateKey.generate()
        key_id = role+'-'+os.urandom(6).hex()
        durable_write(root/(role+'.private'),key.private_bytes_raw())
        registry[key_id] = {'keyID':key_id,'publicKey':encode(key.public_key().public_bytes_raw()),
                            'role':role,'notBefore':now-30,'notAfter':now+86400,'revoked':False}
        signers[role] = {'kind':'research-file','keyID':key_id,'file':role+'.private'}
        if role == 'policy':
            source = (Path(__file__).parent/'manuscript/listing-1.rego').read_bytes()
            document = {'policyVersion':'manuscript-listing-1.v1','opaVersion':opa_version,
                        'source':encode(source),'policySHA256':sha(source),'query':'data.vendorchain.authorization.allow',
                        'parameters':{'max_components':10000,'banned_packages':[]}}
            bundle = sign_document(document,key,key_id,'vendorchain.policy.v1',now=now,ttl=86400)
            durable_write(root/'signed-policy.json',canonical(bundle))
    durable_write(root/'registry.json',canonical(registry))
    durable_write(root/'master.hex',os.urandom(32).hex().encode())
    config = {'researchLocalKeys':True,'state':'pipeline','registry':'registry.json','signers':signers,
              'kek':{'kind':'research-file','file':'master.hex'},'policyBundle':'signed-policy.json',
              'retentionSeconds':86400,'gstin':'27AAPFU0939F1ZV','expectedPan':'AAPFU0939F',
              'expectedTerms':['VENDORCHAIN','27AAPFU0939F1ZV'],
              'source':'artifact','provenance':{'privateURI':'cosign.key','publicFile':'cosign.pub',
              'publicSHA256':'REPLACE_WITH_APPROVED_COSIGN_PUBLIC_FILE_SHA256','notBefore':now-30,'notAfter':now+86400}}
    durable_write(root/'config.json',canonical(config))
    registration = {'keys':list(registry.values()),'policy':{'digest':sha(canonical(bundle)),'notBefore':now-30,'notAfter':now+86400}}
    durable_write(root/'ledger-registration.json',canonical(registration))
    return root/'config.json'


def configured(config_path, *, local=False, allow_local_keys=False, root_override=None):
    config_path = Path(config_path).resolve()
    base, config = config_path.parent, json.loads(config_path.read_text())
    def path(value):
        p = Path(value)
        return p if p.is_absolute() else base/p
    if config.get('researchLocalKeys') and not allow_local_keys:
        raise ValueError('research file keys require explicit --allow-local-keys')
    registry = json.loads(path(config['registry']).read_text())
    def transit(spec):
        return VaultTransit(os.environ[spec.get('addressEnv','VAULT_ADDR')],os.environ[spec['tokenEnv']],mount=spec.get('mount','transit'))
    def signer(role):
        spec = config['signers'][role]
        if spec['kind'] == 'research-file' and allow_local_keys:
            return Ed25519PrivateKey.from_private_bytes(path(spec['file']).read_bytes())
        if spec['kind'] == 'vault-transit':
            return VaultSigner(transit(spec),spec['key'],spec['version'],decode(registry[spec['keyID']]['publicKey']))
        raise ValueError('unsupported signer/custody mode')
    spec = config['kek']
    if spec['kind'] == 'research-file' and allow_local_keys:
        from vendorchain.crypto import load_kek
        kek = load_kek(path(spec['file']).read_text())
    elif spec['kind'] == 'vault-transit':
        kek = VaultWrapper(transit(spec),spec['key'])
    else:
        raise ValueError('unsupported KEK custody mode')
    root = Path(root_override) if root_override is not None else path(config['state'])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    retention = config['retentionSeconds']
    if config.get('postgresDsnEnv'):
        from vendorchain.postgres import PostgresStore
        store = PostgresStore(root,os.environ[config['postgresDsnEnv']],retention_seconds=retention)
    else:
        store = Store(root,retention_seconds=retention)
    provenance = config['provenance']
    uri = provenance['privateURI']
    if '://' not in uri:
        uri = str(path(uri))
    cosign = CosignProvenance(uri,path(provenance['publicFile']),not_before=provenance['notBefore'],
                             not_after=provenance['notAfter'],public_hash=provenance['publicSHA256'])
    ledger = LocalLedger(root/'ledger.sqlite3',registry) if local else FabricLedger(os.environ['FABRIC_GATEWAY_URL'],os.environ['GATEWAY_TOKEN'])
    return HardenedPipeline(root,kek,signer('decision'),config['signers']['decision']['keyID'],registry,ledger,
                 identity_signer=signer('identity'),identity_key_id=config['signers']['identity']['keyID'],
                 signed_policy=SignedPolicy(path(config['policyBundle']),registry),provenance=cosign,
                 gstin=config['gstin'],expected_pan=config.get('expectedPan'),source=path(config['source']),
                 expected=config['expectedTerms'],retention_seconds=retention,store=store)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['init-research','serve','run','reconcile','migrate-postgres'])
    parser.add_argument('--config');parser.add_argument('--state');parser.add_argument('--file')
    parser.add_argument('--local',action='store_true');parser.add_argument('--allow-local-keys',action='store_true')
    parser.add_argument('--repair',action='store_true');parser.add_argument('--interval',type=float,default=0)
    parser.add_argument('--workers',type=int,default=8);parser.add_argument('--port',type=int,default=8090)
    args = parser.parse_args()
    if args.command == 'init-research':
        if not args.state:parser.error('--state required')
        print(json.dumps({'config':str(initialize(args.state)),'custody':'research-local-keys'}));return
    if not args.config:parser.error('--config required')
    if args.command == 'migrate-postgres':
        from vendorchain.postgres import PostgresStore
        c = json.loads(Path(args.config).read_text())
        PostgresStore(Path(args.config).resolve().parent/c['state'],os.environ[c['postgresDsnEnv']]).migrate()
        print(json.dumps({'migrationApplied':True}));return
    pipeline = configured(args.config,local=args.local,allow_local_keys=args.allow_local_keys)
    if args.command == 'serve':
        from vendorchain.server import serve
        asyncio.run(serve(pipeline,os.environ['API_TOKEN'],args.port,args.workers))
    elif args.command == 'run':
        if not args.file:parser.error('--file required')
        print(json.dumps(pipeline.run(bytearray(Path(args.file).read_bytes()),'research-vendor')))
    elif args.command == 'reconcile':
        from vendorchain.reconcile import reconcile
        while True:
            print(json.dumps(reconcile(pipeline,repair=args.repair)),flush=True)
            if not args.interval:break
            if args.interval < 1:parser.error('--interval must be at least one second')
            time.sleep(args.interval)


if __name__ == '__main__':main()
