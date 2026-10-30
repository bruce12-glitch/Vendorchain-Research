import json
import os
from pathlib import Path
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .crypto import encode,load_kek
from .ledger import FabricLedger,LocalLedger
from .pipeline import durable_write,Pipeline

def initialize(root):
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    private=Ed25519PrivateKey.generate()
    now=int(time.time())
    public={'keyID':'worker-'+os.urandom(6).hex(),'publicKey':encode(private.public_key().public_bytes_raw()),
            'notBefore':now-30,'notAfter':now+86400,'revoked':False}
    # All private files are ignored by Git; no secret values are printed.
    durable_write(root/'worker.private',private.private_bytes_raw())
    durable_write(root/'master.hex',os.urandom(32).hex().encode())
    durable_write(root/'worker-public.json',json.dumps(public,indent=2).encode())
    return public

def configured(root, *, local=False, source=None, no_ocr=False, no_sbom=False, expected=()):
    root=Path(root).resolve()
    public=json.loads((root/'worker-public.json').read_text())
    registry={public['keyID']:public}
    private=Ed25519PrivateKey.from_private_bytes((root/'worker.private').read_bytes())
    key=os.environ.get('MASTER_KEK_HEX')
    if key is None and local:
        key=(root/'master.hex').read_text()
    kek=load_kek(key)
    ledger=LocalLedger(root/'local-ledger.sqlite3',registry) if local else FabricLedger(os.environ['FABRIC_GATEWAY_URL'],os.environ['GATEWAY_TOKEN'])
    return Pipeline(root/'pipeline',kek,private,public['keyID'],registry,ledger,source=source,sbom=not no_sbom,ocr=not no_ocr,expected=expected)
