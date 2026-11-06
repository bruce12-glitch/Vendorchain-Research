import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vendorchain.crypto import canonical, encode, decode, encrypt, decrypt
from vendorchain.corpus import png
from vendorchain.evidence import sign_document, verify_document, evidence_root, sha, tree_hash, verify_receipt, SignedPolicy, validate_facts
from vendorchain.hardened import HardenedPipeline
from vendorchain.ledger import LocalLedger
from vendorchain.pipeline import durable_write
from vendorchain.reconcile import reconcile
from vendorchain.store import Store, Conflict
from vendorchain.sbom_schema import validate_sbom


def keys():
    private = {role:Ed25519PrivateKey.generate() for role in ('identity','decision','policy')}
    now = int(time.time())
    registry = {role:{'keyID':role,'role':role,'publicKey':encode(key.public_key().public_bytes_raw()),
                        'notBefore':now-60,'notAfter':now+86400,'revoked':False} for role,key in private.items()}
    return private, registry


class EvidenceTests(unittest.TestCase):
    def setUp(self):self.keys,self.registry = keys()

    def test_identity_context_tamper_role_and_revocation(self):
        value = sign_document({'submissionID':'a'},self.keys['identity'],'identity','vendorchain.identity.v1')
        self.assertEqual(verify_document(value,self.registry,'vendorchain.identity.v1','identity')['submissionID'],'a')
        for domain,role in [('another','identity'),('vendorchain.identity.v1','decision')]:
            with self.assertRaises(ValueError):verify_document(value,self.registry,domain,role)
        changed = copy.deepcopy(value)
        body = json.loads(decode(changed['payload']));body['document']['submissionID']='b'
        changed['payload']=encode(canonical(body))
        with self.assertRaises(InvalidSignature):verify_document(changed,self.registry,'vendorchain.identity.v1','identity')
        self.registry['identity']['revoked']=True
        with self.assertRaises(ValueError):verify_document(value,self.registry,'vendorchain.identity.v1','identity')

    def test_expired_evidence_is_rejected(self):
        value=sign_document({},self.keys['identity'],'identity','vendorchain.identity.v1',now=int(time.time())-100,ttl=1)
        with self.assertRaises(ValueError):verify_document(value,self.registry,'vendorchain.identity.v1','identity')

    def test_root_covers_every_component_and_timestamp(self):
        hashes={k:sha(k.encode()) for k in ('ciphertextHash','sbomHash','artifactHash','identityHash','snapshotHash')}
        root=evidence_root(hashes,42)
        for key in hashes:
            self.assertNotEqual(root,evidence_root({**hashes,key:'0'*64},42))
        self.assertNotEqual(root,evidence_root(hashes,43))

    def test_source_digest_covers_paths_contents_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'a').write_text('one');first=tree_hash(root)
            (root/'a').rename(root/'b');self.assertNotEqual(first,tree_hash(root))
            (root/'a').symlink_to(root/'b')
            with self.assertRaises(ValueError):tree_hash(root)

    def test_signed_policy_rejects_replacement_and_wrong_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'policy.json';source=b'package vendorchain.authorization\ndefault allow = false\n'
            doc={'source':encode(source),'policySHA256':sha(source),'query':'data.vendorchain.authorization.allow'}
            signed=sign_document(doc,self.keys['policy'],'policy','vendorchain.policy.v1')
            path.write_text(json.dumps(signed));policy=SignedPolicy(path,self.registry)
            self.assertEqual(policy.load()[1],source)
            body=json.loads(decode(signed['payload']));body['document']['source']=encode(b'malicious replacement')
            signed['payload']=encode(canonical(body));path.write_text(json.dumps(signed))
            with self.assertRaises(InvalidSignature):policy.load()

    def test_full_offline_cyclonedx_schema(self):
        bom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'type':'library','name':'example','licenses':[{'license':{'id':'MIT'}}]}]}
        validate_sbom(bom)
        with self.assertRaises(Exception):validate_sbom({**bom,'unexpected':True})
        with self.assertRaises(Exception):validate_sbom({**bom,'components':[{'type':'library','name':'example','licenses':[{'license':{'id':'NONEXISTENT-LICENSE'}}]}]})

    def test_missing_replay_predicate_cannot_vacuously_allow(self):
        with self.assertRaises(KeyError):validate_facts({'sbom':{'present':True},'provenance':{}})

    def test_ocr_similarity_matches_manuscript_threshold(self):
        from vendorchain.sandbox import ocr_score
        self.assertEqual(ocr_score('27AAPFU0939F1ZV','GSTIN 27AAPFU0939F 1ZV'),1.0)
        self.assertGreaterEqual(ocr_score('27AAPFU0939F1ZV','GSTIN 27AAPFUO939F1ZV'),0.90)
        self.assertLess(ocr_score('27AAPFU0939F1ZV','INVOICE DIFFERENT IDENTIFIER'),0.90)

    def test_parser_does_not_inherit_deployment_credentials(self):
        from vendorchain.sandbox import parser_environment
        with patch.dict(os.environ,{'MASTER_KEK_HEX':'test-only','VAULT_TOKEN':'test-only',
                  'API_TOKEN':'test-only','GATEWAY_TOKEN':'test-only','CUSTOM_IDENTITY_SIGNER_TOKEN':'test-only'}):
            environment=parser_environment()
            self.assertFalse(set(environment)&{'MASTER_KEK_HEX','VAULT_TOKEN','API_TOKEN','GATEWAY_TOKEN','CUSTOM_IDENTITY_SIGNER_TOKEN'})
            self.assertIn('PATH',environment)


class ReplayTests(unittest.TestCase):
    def test_atomic_digest_admission_under_race(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(tmp,retention_seconds=60)
            def attempt(index):
                try:
                    store.ingest(str(index),'vendor','a'*64,'b'*64,{}, {},'unused')
                    return 'accepted'
                except Conflict as exc:return str(exc)
            with ThreadPoolExecutor(max_workers=12) as pool:results=list(pool.map(attempt,range(30)))
            self.assertEqual(results.count('accepted'),1)
            self.assertEqual(results.count('CONTENT_REPLAY'),29)
            self.assertTrue(store.verify_audit())

    def test_retention_expiry_allows_a_new_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(tmp,retention_seconds=5)
            with patch('vendorchain.store.time.time',return_value=100):store.ingest('one','v','a'*64,'b'*64,{}, {},'unused')
            with patch('vendorchain.store.time.time',return_value=106):store.ingest('two','v','a'*64,'b'*64,{}, {},'unused')
            self.assertIsNotNone(store.get('two'))


class TestProvenance:
    def trust_configuration(self):return {'unit-test':'provenance-trust-double'}
    def build(self, source, path, metrics):
        value={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'type':'library','name':'fixture'}]}
        durable_write(path,canonical(value));return value,tree_hash(source)
    def approved(self):return True
    def verify(self,path,**_):validate_sbom(json.loads(path.read_text()))


class TestPolicy:
    def __init__(self,registry):
        from vendorchain.sandbox import OCR_POLICY
        self.digest='c'*64;self.identity=copy.deepcopy(registry['identity'])
        self.controls=copy.deepcopy({'ocrPolicy':OCR_POLICY,'replayRetentionSeconds':86400})
    def document(self):
        from vendorchain.sandbox import OCR_POLICY
        return {'parameters':{'max_components':100,'banned_packages':[]},'policyVersion':'test','opaVersion':'unit-double',
                'provenanceTrust':{'unit-test':'provenance-trust-double'},'identityTrust':self.identity,
                'controls':self.controls}
    def load(self):return self.document(),b'',self.digest
    def evaluate(self,facts):
        validate_facts(facts)
        return facts['identity']['state']=='verified',self.digest,self.document()


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.keys,self.registry=keys();source=root/'artifact';source.mkdir();(source/'code').write_text('fixture')
        self.policy=TestPolicy(self.registry)
        with patch('vendorchain.pipeline.shutil.which',side_effect=lambda name:name):
            self.p=HardenedPipeline(root/'state',b'k'*32,self.keys['decision'],'decision',self.registry,
                    LocalLedger(root/'ledger.sqlite3',self.registry),identity_signer=self.keys['identity'],identity_key_id='identity',
                    signed_policy=self.policy,provenance=TestProvenance(),source=source,
                    gstin='27AAPFU0939F1ZV',expected=('VENDORCHAIN','27AAPFU0939F1ZV'))
        self.ocr=patch('vendorchain.hardened.isolated',return_value={'ocr':{'expectedCount':2,'expectedMatches':True},
                         'ocrMs':1.0,'cpuSeconds':.01,'peakRssKiB':1000})
        self.ocr.start();self.addCleanup(self.ocr.stop)

    def prepare(self):
        self.p.ingest(bytearray(png()),'vendor','request');return self.p.process('request')

    def test_hardened_commit_and_hash_only_receipt(self):
        payload=self.prepare();receipt=verify_receipt(payload,self.registry)
        self.assertNotIn('gstin',receipt);self.assertNotIn('input',receipt)
        self.assertEqual(receipt['decision'],'PASS')
        ack=self.p.deliver('request');self.assertTrue(ack['successful'])
        self.assertEqual(reconcile(self.p)['divergences'],0)
        self.assertEqual(self.p.store.get('request')['state'],'COMMITTED')

    def test_new_id_replay_wipes_buffer_and_leaves_no_blob(self):
        self.prepare();data=bytearray(png())
        with self.assertRaisesRegex(Conflict,'CONTENT_REPLAY'):self.p.ingest(data,'other-vendor','second')
        self.assertEqual(data,bytearray(len(data)))
        self.assertFalse((self.p.root/'blobs/second.enc').exists())

    def test_identity_mutation_is_blocked_at_delivery(self):
        self.prepare();path=self.p.root/'evidence/request.json';value=json.loads(path.read_text())
        body=json.loads(decode(value['identity']['payload']));body['document']['state']='failed'
        value['identity']['payload']=encode(canonical(body));path.write_text(json.dumps(value))
        with self.assertRaises(InvalidSignature):self.p.deliver('request')
        self.assertEqual(self.p.store.get('request')['state'],'PREPARED')

    def test_policy_replacement_between_evaluation_and_commit_is_blocked(self):
        self.prepare();self.policy.digest='d'*64
        with self.assertRaises(Conflict):self.p.deliver('request')

    def test_lost_acknowledgement_is_reconciled_without_duplicate_commit(self):
        payload=self.prepare();ack=self.p.ledger.submit(payload)
        self.assertEqual(self.p.store.get('request')['state'],'PREPARED')
        result=reconcile(self.p,repair=True)
        self.assertEqual(result['repaired'],1)
        self.assertEqual(self.p.store.pending('request')['tx_id'],ack['transactionID'])

    def test_revocation_blocks_uncommitted_receipt(self):
        self.prepare();self.registry['decision']['revoked']=True
        with self.assertRaises(ValueError):self.p.deliver('request')

    def test_artifact_mutation_is_blocked(self):
        self.prepare();(Path(self.p.source)/'code').write_text('tampered')
        with self.assertRaises(Conflict):self.p.deliver('request')

    def test_unsigned_provenance_trust_change_is_blocked(self):
        self.prepare();self.p.provenance.trust_configuration=lambda:{'changed':'unapproved key'}
        with self.assertRaisesRegex(Conflict,'provenance trust'):self.p.deliver('request')

    def test_unsigned_identity_registry_change_is_blocked(self):
        self.prepare();self.registry['identity']['publicKey']=encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
        with self.assertRaisesRegex(Conflict,'identity trust'):self.p.deliver('request')

    def test_unsigned_replay_window_change_is_blocked(self):
        self.prepare();self.p.store.retention_seconds=1
        with self.assertRaisesRegex(Conflict,'worker controls'):self.p.deliver('request')

    def test_unsigned_replay_window_change_is_blocked_before_admission(self):
        self.prepare();self.p.store.retention_seconds=1
        data=bytearray(png())
        with self.assertRaisesRegex(Conflict,'worker controls'):
            self.p.ingest(data,'vendor','second')
        self.assertEqual(data,bytearray(len(data)))
        self.assertIsNone(self.p.store.get('second'))
        self.assertFalse((self.p.root/'blobs/second.enc').exists())

    def test_expired_policy_blocks_admission_and_wipes_buffer(self):
        data=bytearray(png())
        with patch.object(self.policy,'load',side_effect=ValueError('expired policy')):
            with self.assertRaisesRegex(ValueError,'expired policy'):
                self.p.ingest(data,'vendor','request')
        self.assertEqual(data,bytearray(len(data)))
        self.assertIsNone(self.p.store.get('request'))
        self.assertFalse((self.p.root/'blobs/request.enc').exists())

    def test_sbom_replacement_cannot_bind_a_different_inventory_to_the_verdict(self):
        original=self.p.provenance.build
        def replace(source,path,metrics):
            bom,artifact=original(source,path,metrics)
            replacement=copy.deepcopy(bom);replacement['components'][0]['name']='another-inventory'
            path.write_bytes(canonical(replacement))
            return bom,artifact
        self.p.provenance.build=replace
        self.p.ingest(bytearray(png()),'vendor','request')
        with self.assertRaisesRegex(Conflict,'SBOM changed after provenance'):
            self.p.process('request')
        self.assertFalse((self.p.root/'evidence/request.json').exists())
        self.assertIsNone(self.p.store.pending('request'))

    def test_envelope_mutation_is_cryptographically_bound_even_if_sql_trigger_is_removed(self):
        self.prepare()
        with self.p.store.connection(True) as con:
            con.execute('DROP TRIGGER immutable_submission')
            envelope=json.loads(self.p.store.get('request')['envelope']);envelope['nonce']=encode(b'changednonce')
            con.execute('UPDATE submissions SET envelope=? WHERE id=?',(json.dumps(envelope),'request'))
        with self.assertRaisesRegex(Conflict,'envelope/context changed'):self.p.deliver('request')


@unittest.skipUnless(os.environ.get('VENDORCHAIN_TEST_POSTGRES_DSN'),'requires real PostgreSQL')
class PostgresTests(unittest.TestCase):
    def test_outbox_replay_and_audit_on_postgres(self):
        from vendorchain.postgres import PostgresStore
        import psycopg
        with tempfile.TemporaryDirectory() as tmp:
            dsn=os.environ['VENDORCHAIN_TEST_POSTGRES_DSN']
            store=PostgresStore(tmp,dsn,retention_seconds=60);store.migrate()
            # This integration database must be disposable and dedicated to CI.
            with psycopg.connect(dsn) as con:con.execute('TRUNCATE outbox,submissions,events,digest_replays RESTART IDENTITY CASCADE')
            store.ingest('pg-one','v','a'*64,'b'*64,{}, {},'unused')
            with self.assertRaises(Conflict):store.ingest('pg-two','v','a'*64,'b'*64,{}, {},'unused')
            row=store.claim('pg-one');store.prepare(row,{'receiptHash':'c'*64})
            store.finish('pg-one',row['version']+1,'pg-tx','c'*64)
            self.assertEqual(store.get('pg-one')['state'],'COMMITTED')
            self.assertTrue(store.verify_audit())
