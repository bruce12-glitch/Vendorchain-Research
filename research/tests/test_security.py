import copy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vendorchain.crypto import encrypt,decrypt,load_kek,encode
from vendorchain.corpus import png,jpeg,pdf,polyglot,nested_polyglot,rate
from vendorchain.ingress import validate,Rejected
from vendorchain.sandbox import isolated
from vendorchain.trust import verify
from vendorchain.ledger import LocalLedger
from vendorchain.pipeline import Pipeline
from vendorchain.store import Conflict

class GateTests(unittest.TestCase):
    def test_unusual_valid_images(self):
        for mode in ['RGB','L','P','1']:
            self.assertEqual(validate(png(7,mode))['format'],'PNG')
        self.assertEqual(validate(jpeg(7))['format'],'JPEG')
    def test_literal_script_names_in_metadata_are_not_code(self):
        self.assertEqual(validate(pdf())['format'],'PDF')
    def test_independently_valid_polyglots_are_rejected(self):
        for image in [png(),jpeg(),pdf()]:
            with self.assertRaises(Rejected):validate(polyglot(image))
    def test_polyglot_inside_valid_metadata_and_final_eof(self):
        for kind,data in [('PNG',png()),('JPEG',jpeg()),('PDF',pdf())]:
            with self.assertRaises(Rejected):validate(nested_polyglot(data,kind))
    def test_pdf_active_content(self):
        for kind in ['JavaScript','Launch','EmbeddedFile']:
            with self.assertRaises(Rejected):validate(pdf(action=kind))
    def test_xxe_metadata(self):
        with self.assertRaises(Rejected):validate(pdf(xxe=True))
    def test_encoded_xml_dtd_rejected_but_passive_metadata_accepted(self):
        from pypdf import PdfWriter
        from pypdf.generic import DecodedStreamObject,NameObject
        for encoding in ['utf-8','utf-16','utf-16-be']:
            for dtd in [False,True]:
                writer=PdfWriter();writer.add_blank_page(612,792)
                source='<?xml version="1.0" encoding="'+('UTF-16' if '16' in encoding else 'UTF-8')+'"?>'
                if dtd:source+='<!DOCTYPE x [<!ENTITY e SYSTEM "file:///NONEXISTENT_VENDORCHAIN_TEST_ONLY">]>'
                source+='<x>'+('&e;' if dtd else 'passive metadata')+'</x>'
                stream=DecodedStreamObject();stream.set_data(source.encode(encoding))
                stream[NameObject('/Type')]=NameObject('/Metadata');stream[NameObject('/Subtype')]=NameObject('/XML')
                writer._root_object[NameObject('/Metadata')]=writer._add_object(stream)
                out=io.BytesIO();writer.write(out)
                if dtd:
                    with self.assertRaises(Rejected):validate(out.getvalue())
                else:self.assertEqual(validate(out.getvalue())['format'],'PDF')
    def test_pdf_decompression_limit(self):
        with self.assertRaises(Rejected):validate(pdf(expansion=True))
    def test_empty_and_oversized(self):
        for b in [b'',b'x'*(5*1024*1024+1)]:
            with self.assertRaises(Rejected):validate(b)
    def test_signature_spoof(self):
        with self.assertRaises(Rejected):validate(b'MZ inert .pdf')
    def test_truncated_image(self):
        with self.assertRaises(Rejected):validate(png()[:40])
    def test_parser_subprocess(self):
        self.assertTrue(isolated(png())['ok'])
        with self.assertRaises(Rejected):isolated(b'MZ')
    def test_real_ocr_subprocess(self):
        result=isolated(png(),ocr=True,expected=('VENDORCHAIN',))
        self.assertTrue(result['ocr']['expectedMatches'])
        self.assertNotIn('text',result['ocr'])
    def test_zero_bypass_does_not_mean_zero_population_risk(self):
        self.assertGreater(rate(0,50)['ci95'][1],0)

class CryptoTests(unittest.TestCase):
    def test_key_encoding(self):
        self.assertEqual(len(load_kek('ab'*32)),32)
        for key in ['a'*32,'z'*64,'',' '+('a'*64)]:
            with self.assertRaises(ValueError):load_kek(key)
    def test_roundtrip_and_random_nonces(self):
        a={'recordID':'1','vendorID':'v'};key=b'k'*32
        c,m=encrypt(png(),key,a)
        self.assertEqual(bytes(decrypt(c,m,key,a)),png())
        self.assertNotEqual(m['nonce'],encrypt(png(),key,a)[1]['nonce'])
    def test_vendor_or_document_swap(self):
        a={'recordID':'1','vendorID':'v'};key=b'k'*32;c,m=encrypt(b'private',key,a)
        for other in [{'recordID':'2','vendorID':'v'},{'recordID':'1','vendorID':'other'}]:
            with self.assertRaises(Exception):decrypt(c,m,key,other)
    def test_tamper_authentication(self):
        c,m=encrypt(b'private',b'k'*32,{'id':'1'})
        with self.assertRaises(Exception):decrypt(bytes([c[0]^1])+c[1:],m,b'k'*32,{'id':'1'})

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.private=Ed25519PrivateKey.generate();now=int(time.time())
        self.registry={'test':{'publicKey':encode(self.private.public_key().public_bytes_raw()),'notBefore':now-10,'notAfter':now+7200,'revoked':False}}
        self.ledger=LocalLedger(self.root/'local.sqlite',self.registry)
        self.pipeline=Pipeline(self.root/'state',b'k'*32,self.private,'test',self.registry,self.ledger,sbom=False,ocr=False)
    def tearDown(self):self.temp.cleanup()
    def prepared(self,rid='r1'):
        self.pipeline.ingest(png(),'vendor1',rid);return self.pipeline.process(rid)
    def test_complete_pipeline(self):
        r=self.pipeline.run(png(),'vendor1','r1')
        self.assertEqual(r['evidence'],'local-non-consensus')
        self.assertEqual(self.pipeline.store.get('r1')['state'],'COMMITTED')
        self.assertTrue(self.pipeline.store.verify_audit())
    def test_unsigned_or_tampered_receipt(self):
        p=self.prepared();p['signature']=encode(b'0'*64)
        with self.assertRaises(Exception):verify(p,self.registry)
    def test_revoked_worker_cannot_commit(self):
        self.prepared();self.registry['test']['revoked']=True
        with self.assertRaises(ValueError):self.pipeline.deliver('r1')
        self.assertEqual(self.pipeline.store.get('r1')['state'],'PREPARED')
    def test_expired_receipt(self):
        p=self.prepared()
        with self.assertRaises(ValueError):verify(p,self.registry,now=int(time.time())+601)
    def test_unknown_key(self):
        p=self.prepared()
        with self.assertRaises(KeyError):verify(p,{})
    def test_ciphertext_swap_at_commit(self):
        self.prepared();row=self.pipeline.store.get('r1');Path(row['blob_path']).write_bytes(b'changed')
        with self.assertRaises(Conflict):self.pipeline.deliver('r1')
    def test_idempotent_completed_request(self):
        a=self.pipeline.run(png(),'v','r1');b=self.pipeline.run(png(),'v','r1')
        self.assertEqual(a['ack']['transactionID'],b['ack']['transactionID'])
    def test_idempotency_context_mismatch(self):
        self.pipeline.ingest(png(),'v','r1')
        with self.assertRaises(Conflict):self.pipeline.ingest(png(1),'v','r1')
        with self.assertRaises(Conflict):self.pipeline.ingest(png(),'other','r1')
    def test_one_atomic_worker_claim(self):
        self.pipeline.ingest(png(),'v','r1')
        def claim(_):
            try:self.pipeline.store.claim('r1');return True
            except Conflict:return False
        with ThreadPoolExecutor(max_workers=12) as pool:results=list(pool.map(claim,range(24)))
        self.assertEqual(sum(results),1)
    def test_stale_worker_cannot_prepare(self):
        self.pipeline.ingest(png(),'v','r1');row=self.pipeline.store.claim('r1')
        with self.pipeline.store.connection(True) as con:
            con.execute('UPDATE submissions SET version=version+1 WHERE id=?',('r1',))
        with self.assertRaises(Conflict):self.pipeline.store.prepare(row,{'receiptHash':'x'})
    def test_stale_failure_cannot_cancel_new_worker(self):
        self.pipeline.ingest(png(),'v','r1');row=self.pipeline.store.claim('r1')
        with self.pipeline.store.connection(True) as con:
            con.execute("UPDATE submissions SET version=version+1 WHERE id='r1'")
        self.pipeline.store.fail_processing('r1',row['version'])
        self.assertEqual(self.pipeline.store.get('r1')['state'],'PROCESSING')
    def test_database_binding_immutable(self):
        self.pipeline.ingest(png(),'v','r1')
        with self.assertRaises(sqlite3.IntegrityError):
            with self.pipeline.store.connection(True) as con:con.execute("UPDATE submissions SET vendor_id='other'")
    def test_audit_update_delete_blocked(self):
        self.pipeline.ingest(png(),'v','r1')
        for query in ["UPDATE events SET event='tamper'", "DELETE FROM events"]:
            with self.assertRaises(sqlite3.IntegrityError):
                with self.pipeline.store.connection(True) as con:con.execute(query)
    def test_ledger_outage_keeps_durable_pending_entry(self):
        self.prepared()
        original=self.ledger.submit
        self.ledger.submit=lambda _: (_ for _ in ()).throw(ConnectionError('outage'))
        with self.assertRaises(ConnectionError):self.pipeline.deliver('r1')
        self.assertEqual(self.pipeline.store.pending('r1')['status'],'PENDING')
        self.ledger.submit=original;self.pipeline.deliver('r1')
    def test_lost_commit_ack_reconciles_exactly_once(self):
        self.prepared();original=self.ledger.submit
        def lost(payload):original(payload);raise ConnectionError('lost ack')
        self.ledger.submit=lost
        with self.assertRaises(ConnectionError):self.pipeline.deliver('r1')
        self.ledger.submit=original;self.pipeline.deliver('r1')
        with sqlite3.connect(self.ledger.path) as con:self.assertEqual(con.execute('SELECT count(*) FROM records').fetchone()[0],1)
    def test_local_finalize_failure_is_recoverable(self):
        self.prepared();original=self.pipeline.store.finish
        self.pipeline.store.finish=lambda *args: (_ for _ in ()).throw(OSError('disk full'))
        with self.assertRaises(OSError):self.pipeline.deliver('r1')
        self.assertEqual(self.pipeline.store.get('r1')['state'],'PREPARED')
        self.pipeline.store.finish=original;self.pipeline.deliver('r1')
    def test_false_ack_never_finalizes(self):
        self.prepared();self.ledger.submit=lambda _: {'successful':True,'receiptHash':'wrong','transactionID':'tx','kind':self.ledger.kind}
        with self.assertRaises(ValueError):self.pipeline.deliver('r1')
        self.assertEqual(self.pipeline.store.get('r1')['state'],'PREPARED')

if __name__=='__main__':unittest.main()
