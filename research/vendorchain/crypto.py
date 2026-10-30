"""Context-bound envelope encryption; GCM plaintext is used only after finalization."""
import base64
import json
import os
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def load_kek(hex_key):
    if not isinstance(hex_key, str) or not re.fullmatch('[a-fA-F0-9]{64}', hex_key):
        raise ValueError('MASTER_KEK_HEX must encode exactly 32 random bytes as 64 hex characters')
    return bytes.fromhex(hex_key)

def encode(b):
    return base64.b64encode(b).decode()

def decode(s):
    return base64.b64decode(s, validate=True)

def encrypt(data, kek, context):
    aad = canonical({'domain':'vendorchain.envelope.v1', **context})
    dek = bytearray(os.urandom(32))
    try:
        nonce = os.urandom(12)
        enc = Cipher(algorithms.AES(bytes(dek)), modes.GCM(nonce)).encryptor()
        enc.authenticate_additional_data(aad)
        ciphertext = b''.join(enc.update(data[i:i+65536]) for i in range(0, len(data), 65536)) + enc.finalize()
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(kek).encrypt(wrap_nonce, bytes(dek), aad)
        return ciphertext, {'version':1, 'nonce':encode(nonce), 'tag':encode(enc.tag),
                            'wrapNonce':encode(wrap_nonce), 'wrappedKey':encode(wrapped)}
    finally:
        dek[:] = b'\x00'*len(dek)

def decrypt(ciphertext, metadata, kek, context):
    if metadata.get('version') != 1:
        raise ValueError('unsupported envelope version')
    aad = canonical({'domain':'vendorchain.envelope.v1', **context})
    dek = bytearray(AESGCM(kek).decrypt(decode(metadata['wrapNonce']), decode(metadata['wrappedKey']), aad))
    plaintext = bytearray()
    try:
        dec = Cipher(algorithms.AES(bytes(dek)), modes.GCM(decode(metadata['nonce']), decode(metadata['tag']))).decryptor()
        dec.authenticate_additional_data(aad)
        for i in range(0, len(ciphertext), 65536):
            plaintext.extend(dec.update(ciphertext[i:i+65536]))
        plaintext.extend(dec.finalize())  # Authenticate before returning any bytes.
        return plaintext
    except BaseException:
        plaintext[:] = b'\x00'*len(plaintext)
        raise
    finally:
        dek[:] = b'\x00'*len(dek)
