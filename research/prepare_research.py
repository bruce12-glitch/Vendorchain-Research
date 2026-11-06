"""Create a complete disposable local-key experiment configuration."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from hardened_cli import initialize
from vendorchain.evidence import sha
from vendorchain.evidence import sign_document
from vendorchain.crypto import canonical, decode
from vendorchain.sandbox import OCR_POLICY
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import time


def prepare(root):
    root=Path(root).resolve();config=initialize(root)
    source=root/'artifact';source.mkdir()
    for file in (Path(__file__).resolve().parents[1]/'chaincode').glob('*.go'):
        shutil.copyfile(file,source/file.name)
    for name in ['go.mod','go.sum']:
        shutil.copyfile(Path(__file__).resolve().parents[1]/'chaincode'/name,source/name)
    subprocess.run(['cosign','generate-key-pair','--output-key-prefix',str(root/'cosign')],
                   env={**os.environ,'COSIGN_PASSWORD':''},capture_output=True,timeout=30,check=True)
    # Dev-only private material is readable only by this account, ignored by Git.
    (root/'cosign.key').chmod(0o600)
    value=json.loads(config.read_text());value['provenance']['publicSHA256']=sha((root/'cosign.pub').read_bytes())
    config.write_text(json.dumps(value,indent=2))
    registry=json.loads((root/'registry.json').read_text())
    old=json.loads((root/'signed-policy.json').read_text());document=json.loads(decode(old['payload']))['document']
    document['provenanceTrust']={'mode':'pinned-public-key',**{k:value['provenance'][k] for k in ('publicSHA256','notBefore','notAfter')}}
    document['identityTrust']=registry[value['signers']['identity']['keyID']]
    document['controls']={'ocrPolicy':OCR_POLICY,'replayRetentionSeconds':value['retentionSeconds']}
    key_id=value['signers']['policy']['keyID'];signer=Ed25519PrivateKey.from_private_bytes((root/'policy.private').read_bytes())
    now=int(time.time());bundle=sign_document(document,signer,key_id,'vendorchain.policy.v1',now=now,ttl=registry[key_id]['notAfter']-now)
    (root/'signed-policy.json').write_bytes(canonical(bundle))
    registration=json.loads((root/'ledger-registration.json').read_text());registration['policy']['digest']=sha(canonical(bundle))
    (root/'ledger-registration.json').write_bytes(canonical(registration))
    return config


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);a=p.parse_args()
    print(json.dumps({'config':str(prepare(a.output)),'custody':'research-local-keys; not HSM validation'}))
