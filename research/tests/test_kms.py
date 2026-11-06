import os
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from vendorchain.crypto import canonical, decode, encrypt, decrypt
from vendorchain.kms import VaultTransit, VaultSigner, VaultWrapper


class KmsConfigurationTests(unittest.TestCase):
    def test_transport_validation(self):
        for address in ['http://public.example.com','ftp://localhost','https://token@example.com','https://example.com/path','https://']:
            with self.assertRaises(ValueError):VaultTransit(address,'token')

    def test_redirect_does_not_forward_vault_token_to_another_origin(self):
        redirected=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/v1/'):
                    self.send_response(302)
                    self.send_header('Location',f'http://localhost:{self.server.server_port}/redirected')
                    self.end_headers()
                else:
                    redirected.append(self.headers.get('X-Vault-Token'))
                    self.send_response(200);self.end_headers();self.wfile.write(b'{"data":{}}')
            def log_message(self,*_):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            transit=VaultTransit(f'http://127.0.0.1:{server.server_port}','test-only-token')
            with self.assertRaisesRegex(ValueError,'unconfigured origin'):transit.key('test')
            self.assertEqual(redirected,[])
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_exportable_keys_rejected(self):
        class Transit:
            def key(self,_):return {'type':'aes256-gcm96','derived':False}
        with self.assertRaises(ValueError):VaultWrapper(Transit(),'test')


@unittest.skipUnless(os.environ.get('VENDORCHAIN_TEST_VAULT_ADDR'),'requires a real disposable Vault Transit service')
class LiveVaultTests(unittest.TestCase):
    def setUp(self):
        self.vault=VaultTransit(os.environ['VENDORCHAIN_TEST_VAULT_ADDR'],os.environ['VENDORCHAIN_TEST_VAULT_TOKEN'])
        self.prefix='test-'+os.urandom(8).hex()

    def test_remote_wrap_rotation_revocation_and_context_binding(self):
        name=self.prefix+'-kek'
        self.vault.call('keys/'+name,{'type':'aes256-gcm96','derived':True,'exportable':False,'allow_plaintext_backup':False})
        wrapper=VaultWrapper(self.vault,name)
        ciphertext,metadata=encrypt(b'authenticated document',wrapper,{'recordID':'a'})
        self.assertEqual(metadata['wrapped']['keyVersion'],1)
        self.assertEqual(decrypt(ciphertext,metadata,wrapper,{'recordID':'a'}),b'authenticated document')
        with self.assertRaises(urllib.error.HTTPError):decrypt(ciphertext,metadata,wrapper,{'recordID':'b'})
        self.vault.call('keys/'+name+'/rotate',{})
        c2,m2=encrypt(b'rotated',wrapper,{'recordID':'a'})
        self.assertEqual(m2['wrapped']['keyVersion'],2)
        self.vault.call('keys/'+name+'/config',{'min_decryption_version':2,'min_encryption_version':2})
        with self.assertRaises(urllib.error.HTTPError):decrypt(ciphertext,metadata,wrapper,{'recordID':'a'})
        self.assertEqual(decrypt(c2,m2,wrapper,{'recordID':'a'}),b'rotated')

    def test_remote_ed25519_signer_version_pin(self):
        name=self.prefix+'-signer'
        self.vault.call('keys/'+name,{'type':'ed25519','exportable':False,'allow_plaintext_backup':False})
        public=decode(self.vault.key(name)['keys']['1']['public_key'])
        signer=VaultSigner(self.vault,name,1,public)
        data=canonical({'domain':'test-only','recordID':'one'})
        Ed25519PublicKey.from_public_bytes(public).verify(signer.sign(data),data)
        self.vault.call('keys/'+name+'/rotate',{})
        self.vault.call('keys/'+name+'/config',{'min_encryption_version':2})
        with self.assertRaises(urllib.error.HTTPError):signer.sign(data)

    @unittest.skipUnless(all(shutil.which(x) for x in ('syft','cosign','opa','tesseract')),'requires real provenance, policy and OCR tools')
    @patch.dict(os.environ, {'COSIGN_PASSWORD':''})
    def test_hardened_pipeline_with_remote_kek_and_worker_keys(self):
        from prepare_vault_research import prepare_vault
        from hardened_cli import configured
        from table12_worker import identity_png
        with tempfile.TemporaryDirectory() as tmp:
            config_path=prepare_vault(Path(tmp)/'deployment',address_env='VENDORCHAIN_TEST_VAULT_ADDR',token_env='VENDORCHAIN_TEST_VAULT_TOKEN')
            root=config_path.parent
            self.assertTrue(all(not (root/p).exists() for p in ['master.hex','identity.private','decision.private','policy.private']))
            pipeline=configured(config_path,local=True)
            result=pipeline.run(bytearray(identity_png('remote-vault-integration')),'remote-vendor')
            self.assertEqual(result['decision'],'PASS')
            self.assertEqual(json.loads(pipeline.store.get(result['recordID'])['envelope'])['version'],2)
