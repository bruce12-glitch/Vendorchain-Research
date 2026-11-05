"""Vault Transit adapter. KEKs and signing keys stay in the remote service.

Vault custody is not itself evidence of hardware-backed HSM custody. Rotation and
minimum decrypt/sign versions are enforced by Vault policy on every operation.
"""
import json
import re
import urllib.request
from urllib.parse import urlparse
from .crypto import canonical, encode, decode


class VaultTransit:
    def __init__(self, address, token, *, mount='transit', opener=None):
        u = urlparse(address)
        if u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
            raise ValueError('Vault address must be an origin')
        if u.scheme != 'https' and not (u.scheme == 'http' and u.hostname in ('localhost','127.0.0.1','::1')):
            raise ValueError('Vault requires TLS outside loopback')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', mount) or not token:
            raise ValueError('Vault mount and token required')
        self.address, self.token, self.mount = address.rstrip('/'), token, mount
        self.opener = opener or urllib.request.urlopen

    def call(self, path, body=None):
        req = urllib.request.Request(self.address+'/v1/'+self.mount+'/'+path,
                None if body is None else canonical(body),
                {'X-Vault-Token':self.token,'Content-Type':'application/json'})
        with self.opener(req, timeout=15) as response:
            data = response.read(1024*1024+1)
        if len(data) > 1024*1024:
            raise ValueError('oversized Vault response')
        value = json.loads(data)
        if value.get('errors'):
            raise ValueError('Vault operation rejected')
        return value.get('data', {})

    def key(self, name):
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
            raise ValueError('invalid Transit key name')
        value = self.call('keys/'+name)
        if value.get('exportable') is not False or value.get('allow_plaintext_backup') is not False:
            raise ValueError('Transit keys must be non-exportable with plaintext backup disabled')
        return value


class VaultWrapper:
    def __init__(self, transit, name):
        self.transit, self.name = transit, name
        key = transit.key(name)
        if key.get('type') != 'aes256-gcm96' or not key.get('derived'):
            raise ValueError('KEK requires derived aes256-gcm96 Transit key')

    def wrap(self, dek, aad):
        value = self.transit.call('encrypt/'+self.name, {'plaintext':encode(dek),'context':encode(aad)})
        ciphertext = value['ciphertext']
        match = re.fullmatch(r'vault:v([1-9][0-9]*):[^:]+', ciphertext)
        if not match:
            raise ValueError('invalid wrapped DEK')
        return {'provider':'vault-transit','key':self.name,'keyVersion':int(match[1]),'ciphertext':ciphertext}

    def unwrap(self, wrapped, aad):
        if wrapped.get('provider') != 'vault-transit' or wrapped.get('key') != self.name:
            raise ValueError('wrapped DEK provider/key mismatch')
        match = re.fullmatch(r'vault:v([1-9][0-9]*):[^:]+', wrapped['ciphertext'])
        if not match or int(match[1]) != wrapped['keyVersion']:
            raise ValueError('wrapped DEK version mismatch')
        # Do not cache DEKs or bypass Vault min_decryption_version/revocation.
        value = self.transit.call('decrypt/'+self.name, {'ciphertext':wrapped['ciphertext'],'context':encode(aad)})
        dek = decode(value['plaintext'])
        if len(dek) != 32:
            raise ValueError('invalid DEK length')
        return dek


class VaultSigner:
    def __init__(self, transit, name, version, public_key):
        self.transit, self.name, self.version = transit, name, version
        key = transit.key(name)
        if key.get('type') != 'ed25519' or key.get('derived') or version < 1:
            raise ValueError('signer requires a pinned non-derived Ed25519 version')
        if decode(key['keys'][str(version)]['public_key']) != public_key:
            raise ValueError('Transit public key differs from pinned registry')

    def sign(self, data):
        value = self.transit.call('sign/'+self.name, {'input':encode(data),'key_version':self.version,'prehashed':False})
        prefix = 'vault:v'+str(self.version)+':'
        if not value['signature'].startswith(prefix):
            raise ValueError('Transit signed with an unexpected key version')
        sig = decode(value['signature'][len(prefix):])
        if len(sig) != 64:
            raise ValueError('invalid Ed25519 signature')
        return sig
