import hashlib
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .crypto import canonical, encode, decode

def sign(receipt, private_key):
    raw = canonical(receipt)
    return {'recordID':receipt['recordID'], 'receipt':encode(raw),
            'signature':encode(private_key.sign(raw)), 'receiptHash':hashlib.sha256(raw).hexdigest()}

def verify(payload, registry, now=None):
    import json
    now = int(time.time()) if now is None else now
    raw = decode(payload['receipt'])
    receipt = json.loads(raw)
    key = registry[receipt['keyID']]
    if key.get('revoked') or not key['notBefore'] <= now < key['notAfter']:
        raise ValueError('inactive worker key')
    if (receipt['issuedAt'] < key['notBefore'] or receipt['issuedAt'] > now+30
        or receipt['expiresAt'] <= now or receipt['expiresAt'] > key['notAfter']
        or not 0 < receipt['expiresAt']-receipt['issuedAt'] <= 3600):
        raise ValueError('invalid receipt validity interval')
    if receipt['version'] != 'vendorchain.receipt.v1' or receipt['recordID'] != payload['recordID'] or receipt['nonce'] != payload['recordID']:
        raise ValueError('receipt context mismatch')
    if hashlib.sha256(raw).hexdigest() != payload['receiptHash']:
        raise ValueError('receipt hash mismatch')
    Ed25519PublicKey.from_public_bytes(decode(key['publicKey'])).verify(decode(payload['signature']), raw)
    return receipt
