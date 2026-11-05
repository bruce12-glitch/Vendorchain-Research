import os
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
import urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from vendorchain.crypto import canonical, decode, encode, encrypt, decrypt
from vendorchain.kms import VaultTransit, VaultSigner, VaultWrapper


class KmsConfigurationTests(unittest.TestCase):
    def test_transport_validation(self):
        for address in ['http://public.example.com','ftp://localhost','https://token@example.com','https://example.com/path']:
            with self.assertRaises(ValueError):VaultTransit(address,'token')

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
    def test_hardened_pipeline_with_remote_kek_and_worker_keys(self):
        from prepare_research import prepare
        from hardened_cli import configured
        from vendorchain.evidence import sign_document
        from table12_worker import identity_png
        with tempfile.TemporaryDirectory() as tmp:
            config_path=prepare(Path(tmp)/'deployment');c=json.loads(config_path.read_text());registry={};now=int(time.time())
            signers={}
            for role in ('identity','decision','policy'):
                name=self.prefix+'-'+role
                self.vault.call('keys/'+name,{'type':'ed25519','exportable':False,'allow_plaintext_backup':False})
                pub=self.vault.key(name)['keys']['1']['public_key']
                registry[name]={'keyID':name,'role':role,'publicKey':pub,'notBefore':now-30,'notAfter':now+86400,'revoked':False}
                spec={'kind':'vault-transit','keyID':name,'key':name,'version':1,
                      'addressEnv':'VENDORCHAIN_TEST_VAULT_ADDR','tokenEnv':'VENDORCHAIN_TEST_VAULT_TOKEN'}
                c['signers'][role]=spec;signers[role]=VaultSigner(self.vault,name,1,decode(pub))
            kek=self.prefix+'-pipeline-kek'
            self.vault.call('keys/'+kek,{'type':'aes256-gcm96','derived':True,'exportable':False,'allow_plaintext_backup':False})
            c['kek']={'kind':'vault-transit','key':kek,'addressEnv':'VENDORCHAIN_TEST_VAULT_ADDR','tokenEnv':'VENDORCHAIN_TEST_VAULT_TOKEN'}
            c['researchLocalKeys']=False
            root=config_path.parent
            old=json.loads((root/'signed-policy.json').read_text());doc=json.loads(decode(old['payload']))['document']
            bundle=sign_document(doc,signers['policy'],c['signers']['policy']['keyID'],'vendorchain.policy.v1',now=now)
            (root/'signed-policy.json').write_bytes(canonical(bundle));(root/'registry.json').write_bytes(canonical(registry));config_path.write_text(json.dumps(c))
            # Remove the original file KEK/worker keys before exercising the path.
            for name in ['master.hex','identity.private','decision.private','policy.private']:(root/name).unlink()
            pipeline=configured(config_path,local=True)
            result=pipeline.run(bytearray(identity_png('remote-vault-integration')),'remote-vendor')
            self.assertEqual(result['decision'],'PASS')
            self.assertEqual(json.loads(pipeline.store.get(result['recordID'])['envelope'])['version'],2)
