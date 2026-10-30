"""Executable ingestion -> worker -> durable outbox -> commit acknowledgement."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
from .crypto import canonical, encrypt, decrypt, decode
from .ingress import POLICY
from .sandbox import isolated
from .store import Store, Conflict
from .trust import sign, verify
from cryptography.exceptions import InvalidSignature

IDENTIFIER = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
def digest(data):
    return hashlib.sha256(data).hexdigest()

@contextmanager
def timed(metrics, name):
    start = time.perf_counter_ns()
    try:
        yield
    finally:
        metrics[name] = (time.perf_counter_ns()-start)/1e6

def durable_write(path, data):
    # Unique request paths; refuse overwrites and symlink traversal at the leaf.
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0), 0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        directory = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        path.unlink(missing_ok=True)
        raise

class Pipeline:
    def __init__(self, root, kek, private_key, key_id, registry, ledger, *, source=None, sbom=True, ocr=True, expected=()):
        self.root = Path(root).resolve()
        self.store = Store(self.root)
        self.kek, self.private_key, self.key_id = kek, private_key, key_id
        self.registry, self.ledger = registry, ledger
        self.source, self.sbom, self.ocr, self.expected = source, sbom, ocr, tuple(expected)
        if ledger.kind != 'local-non-consensus' and (not sbom or not ocr or not source):
            raise ValueError('Fabric mode requires real OCR and Syft; ablations are local only')
        if sbom and (not source or not shutil.which('syft')):
            raise ValueError('Syft and a host-controlled source directory are required')
        (self.root/'blobs').mkdir(exist_ok=True, mode=0o700)
        (self.root/'sbom').mkdir(exist_ok=True, mode=0o700)

    def ingest(self, data, vendor, rid=None, metrics=None):
        metrics = {} if metrics is None else metrics
        rid = rid or uuid.uuid4().hex
        if not IDENTIFIER.fullmatch(vendor) or not IDENTIFIER.fullmatch(rid):
            raise ValueError('invalid vendor or request identifier')
        old = self.store.get(rid)
        if old:
            if old['document_hash'] != digest(data) or old['vendor_id'] != vendor:
                raise Conflict('idempotency key reused for another document or vendor')
            return rid
        with timed(metrics,'gate_ms'):
            isolated(data)
        context = {'vendorID':vendor,'recordID':rid,'documentType':'COMPLIANCE_DOCUMENT'}
        with timed(metrics,'encrypt_ms'):
            ciphertext, envelope = encrypt(data,self.kek,context)
        path = self.root/'blobs'/(rid+'.enc')
        with timed(metrics,'persist_ms'):
            durable_write(path,ciphertext)
            try:
                self.store.ingest(rid,vendor,digest(data),digest(ciphertext),envelope,context,path)
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        return rid

    def process(self, rid, metrics=None):
        metrics = {} if metrics is None else metrics
        row = self.store.claim(rid)
        plaintext = None
        try:
            with timed(metrics,'decrypt_ms'):
                ciphertext = Path(row['blob_path']).read_bytes()
                if digest(ciphertext) != row['cipher_hash']:
                    raise ValueError('ciphertext changed after ingestion')
                plaintext = decrypt(ciphertext,json.loads(row['envelope']),self.kek,json.loads(row['context']))
                if digest(plaintext) != row['document_hash']:
                    raise ValueError('document digest mismatch')
            with timed(metrics,'worker_ms'):
                worker = isolated(bytes(plaintext),ocr=self.ocr,expected=self.expected)
                metrics.update(worker_gate_ms=worker['gateMs'],ocr_ms=worker['ocrMs'],
                               worker_cpu_seconds=worker['cpuSeconds'],worker_peak_rss_kib=worker['peakRssKiB'])
            sbom = b'NOT_RUN:local-ablation'
            with timed(metrics,'syft_ms'):
                if self.sbom:
                    result = subprocess.run(['syft','dir:'+str(Path(self.source).resolve()),'-o','cyclonedx-json'],
                                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=True)
                    sbom = result.stdout
                    parsed = json.loads(sbom)
                    if parsed.get('bomFormat') != 'CycloneDX':
                        raise ValueError('Syft did not produce a CycloneDX SBOM')
                    durable_write(self.root/'sbom'/(rid+'.json'),sbom)
            if not self.sbom:
                metrics['syft_ms'] = None
            now = int(time.time())
            receipt = {'version':'vendorchain.receipt.v1','recordID':rid,'vendorID':row['vendor_id'],
                       'documentHash':row['document_hash'],'ciphertextHash':row['cipher_hash'],
                       'sbomHash':digest(sbom),'policyHash':digest(canonical({'ingress':POLICY,'ocr':self.ocr,'sbom':self.sbom,'expected':list(self.expected)})),
                       'decision':'PASS' if not self.ocr or worker['ocr']['expectedMatches'] else 'FAIL',
                       'keyID':self.key_id,'issuedAt':now,'expiresAt':now+600,'nonce':rid}
            with timed(metrics,'attest_ms'):
                payload = sign(receipt,self.private_key)
                verify(payload,self.registry)
            with timed(metrics,'outbox_prepare_ms'):
                self.store.prepare(row,payload)
            return payload
        except BaseException:
            self.store.fail_processing(rid,row['version'])
            raise
        finally:
            if plaintext is not None:
                plaintext[:] = b'\x00'*len(plaintext)
            # Python/crypto libraries may make copies: this is best-effort hygiene,
            # not a claim that all heap copies or swap have been erased.

    def historical_commit(self, rid, row, payload):
        raw=decode(payload['receipt']);receipt=json.loads(raw)
        if (payload['recordID']!=rid or receipt['recordID']!=rid or receipt['nonce']!=rid
            or digest(raw)!=payload['receiptHash'] or receipt['vendorID']!=row['vendor_id']
            or receipt['documentHash']!=row['document_hash'] or receipt['ciphertextHash']!=row['cipher_hash']):
            raise Conflict('historical receipt binding mismatch')
        ack=self.ledger.lookup(payload)
        if (not ack or ack.get('successful') is not True or not ack.get('transactionID')
            or ack.get('receiptHash')!=payload['receiptHash'] or ack.get('kind')!=self.ledger.kind):
            raise ValueError('historical commitment not confirmed by ledger')
        return ack

    def deliver(self, rid, metrics=None):
        metrics = {} if metrics is None else metrics
        pending = self.store.pending(rid)
        if not pending:
            raise ValueError('no prepared outbox entry')
        payload = json.loads(pending['payload'])
        with timed(metrics,'commit_revalidate_ms'):
            if pending['status']=='CONFIRMED':
                row=self.store.get(rid)
                if row['state']!='COMMITTED':raise Conflict('inconsistent cached commitment')
                ack=self.historical_commit(rid,row,payload)
                if ack['transactionID']!=pending['tx_id']:raise Conflict('cached transaction differs from ledger')
                return ack
            try:
                receipt = verify(payload,self.registry)
            except (ValueError,KeyError,InvalidSignature):
                # Expiry/revocation blocks new writes, not recovery of a past commit.
                row=self.store.get(rid)
                if row['state']!='PREPARED' or row['version']!=pending['snapshot']:
                    raise Conflict('stale recovery snapshot')
                ack=self.historical_commit(rid,row,payload)
                self.store.finish(rid,pending['snapshot'],ack['transactionID'],ack['receiptHash'])
                return ack
            row = self.store.get(rid)
            if row['state']!='PREPARED' or row['version']!=pending['snapshot']:
                raise Conflict('stale outbox snapshot')
            data = Path(row['blob_path']).read_bytes()
            if digest(data)!=row['cipher_hash'] or digest(data)!=receipt['ciphertextHash'] or row['document_hash']!=receipt['documentHash'] or row['vendor_id']!=receipt['vendorID']:
                raise Conflict('commit-time document binding changed')
            if self.sbom and digest((self.root/'sbom'/(rid+'.json')).read_bytes()) != receipt['sbomHash']:
                raise Conflict('commit-time SBOM changed')
        with timed(metrics,'ledger_commit_ms'):
            ack = self.ledger.submit(payload)
            if ack.get('successful') is not True or ack.get('receiptHash')!=payload['receiptHash'] or ack.get('kind')!=self.ledger.kind:
                raise ValueError('invalid ledger acknowledgement')
        with timed(metrics,'db_finalize_ms'):
            self.store.finish(rid,pending['snapshot'],ack['transactionID'],ack['receiptHash'])
        return ack

    def run(self, data, vendor, rid=None):
        metrics = {}
        start = time.perf_counter_ns()
        rid = self.ingest(data,vendor,rid,metrics)
        state = self.store.get(rid)['state']
        if state == 'INGESTED':
            self.process(rid,metrics)
        result = self.deliver(rid,metrics)
        metrics['ingestion_to_commit_ms'] = (time.perf_counter_ns()-start)/1e6
        return {'recordID':rid,'ack':result,'stages':metrics,'evidence':self.ledger.kind}
