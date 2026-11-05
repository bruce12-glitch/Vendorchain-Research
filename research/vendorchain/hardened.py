"""Executable H1-H7 path. Production dependencies are required, never simulated.

Identity and policy signing custody must be separate from the decision worker.
A compromised authorized signer can still assert false evidence; see Section 8.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from .crypto import canonical, decode, encode, decrypt
from .evidence import sha, tree_hash, sign_document, verify_document, verify_receipt, evidence_root
from .gstin import valid_gstin
from .pipeline import Pipeline, timed, durable_write
from .sandbox import isolated
from .store import Store, Conflict


class CosignProvenance:
    def __init__(self, private_uri, public_file, *, not_before, not_after, public_hash):
        self.private_uri, self.public_file = private_uri, Path(public_file)
        self.not_before, self.not_after, self.public_hash = not_before, not_after, public_hash

    def approved(self):
        return self.not_before <= int(time.time()) < self.not_after and sha(self.public_file.read_bytes()) == self.public_hash

    def build(self, source, path, metrics):
        with timed(metrics, 'syft_ms'):
            before = tree_hash(source)
            result = subprocess.run(['syft','dir:'+str(Path(source).resolve()),'-o','cyclonedx-json@1.5'],
                         capture_output=True, timeout=120, check=True,
                         env={**os.environ,'SYFT_CHECK_FOR_APP_UPDATE':'false'})
            data = result.stdout
            parsed = json.loads(data)
            from .sbom_schema import validate_sbom
            validate_sbom(parsed)
            if before != tree_hash(source):
                raise Conflict('artifact source changed during Syft scan')
            durable_write(path, data)
        signature = path.with_suffix('.sig')
        with timed(metrics, 'cosign_sign_ms'):
            subprocess.run(['cosign','sign-blob','--yes','--tlog-upload=false','--key',self.private_uri,
                            '--output-signature',str(signature),str(path)], capture_output=True,timeout=60,check=True)
        with timed(metrics, 'cosign_verify_ms'):
            self.verify(path,expected_hash=sha(data))
        return parsed, before

    def verify(self, path, *, expected_hash=None):
        public = self.public_file.read_bytes()
        if not self.not_before <= int(time.time()) < self.not_after or sha(public) != self.public_hash:
            raise ValueError('unapproved/expired provenance verification key')
        data = path.read_bytes()
        if expected_hash is not None and sha(data) != expected_hash:
            raise Conflict('SBOM changed before signature verification')
        with tempfile.TemporaryDirectory(prefix='vendorchain-cosign-') as tmp:
            root = Path(tmp)
            (root/'public.pem').write_bytes(public);(root/'sbom.json').write_bytes(data)
            (root/'sbom.sig').write_bytes(path.with_suffix('.sig').read_bytes())
            subprocess.run(['cosign','verify-blob','--insecure-ignore-tlog=true','--key',str(root/'public.pem'),
                            '--signature',str(root/'sbom.sig'),str(root/'sbom.json')],capture_output=True,timeout=60,check=True)


class HardenedPipeline(Pipeline):
    def __init__(self, *args, identity_signer, identity_key_id, signed_policy, provenance,
                 gstin, expected_pan=None, retention_seconds=86400, **kwargs):
        if not kwargs.get('ocr', True) or not kwargs.get('sbom', True):
            raise ValueError('hardened pipeline requires OCR and provenance')
        if not kwargs.get('expected') or gstin not in kwargs['expected']:
            raise ValueError('trusted OCR expectations must include the submitted GSTIN')
        kwargs['opa'] = True
        super().__init__(*args, **kwargs)
        self.store = kwargs.get('store') or Store(self.root, retention_seconds=retention_seconds)
        if getattr(self.store, 'retention_seconds', None) != retention_seconds:
            raise ValueError('store replay-retention policy mismatch')
        if self.registry[self.key_id].get('role') != 'decision' or self.registry[identity_key_id].get('role') != 'identity' or self.key_id == identity_key_id:
            raise ValueError('separate identity and decision roles required')
        self.identity_signer, self.identity_key_id = identity_signer, identity_key_id
        self.signed_policy, self.provenance = signed_policy, provenance
        self.gstin, self.expected_pan = gstin, expected_pan
        (self.root/'evidence').mkdir(mode=0o700, exist_ok=True)

    def policy_hash(self):
        return self.signed_policy.load()[2]

    def verify_payload(self, payload):
        return verify_receipt(payload, self.registry)

    def process(self, rid, metrics=None):
        metrics = {} if metrics is None else metrics
        row = self.store.claim(rid)
        plaintext = None
        try:
            with timed(metrics,'decrypt_ms'):
                cipher = Path(row['blob_path']).read_bytes()
                if sha(cipher) != row['cipher_hash']:
                    raise Conflict('ciphertext changed')
                plaintext = decrypt(cipher,json.loads(row['envelope']),self.kek,json.loads(row['context']))
                if sha(plaintext) != row['document_hash']:
                    raise Conflict('plaintext changed')
            with timed(metrics,'worker_ms'):
                worker = isolated(bytes(plaintext),ocr=True,expected=self.expected)
                metrics['ocr_ms'] = worker['ocrMs']
                metrics['worker_cpu_seconds'] = worker['cpuSeconds']
                metrics['worker_peak_rss_kib'] = worker['peakRssKiB']
            now = int(time.time())
            with timed(metrics,'identity_attestation_ms'):
                check = valid_gstin(self.gstin, self.expected_pan)
                ocr = worker['ocr']['expectedCount'] > 0 and worker['ocr']['expectedMatches'] is True
                identity = {'version':1,'submissionID':rid,'vendorID':row['vendor_id'],'gstin':self.gstin,
                            'state':'verified' if check and ocr else 'failed','checksum':check,'ocr':ocr,
                            'workerID':self.identity_key_id,'timestamp':now,'documentHash':row['document_hash'],
                            'ocrPolicy':worker['ocr'].get('policy'),'ocrScores':worker['ocr'].get('scores')}
                attestation = sign_document(identity,self.identity_signer,self.identity_key_id,'vendorchain.identity.v1',now=now)
                verified = verify_document(attestation,self.registry,'vendorchain.identity.v1','identity')
            sbom_path = self.root/'sbom'/(rid+'.json')
            sbom, artifact_hash = self.provenance.build(self.source,sbom_path,metrics)
            parameters = self.signed_policy.load()[0]['parameters']
            facts = {'identity':{'state':verified['state']},'sbom':{'present':True,'component_count':len(sbom.get('components',[])),
                     'components':sbom.get('components',[]),'schema':'cyclonedx'},
                     'provenance':{'signature_valid':True,'certificate_approved':self.provenance.approved(),
                     'certificate_expired':False,'artifact_digest_bound':True},
                     'policy':parameters,'replay':{'detected':False}}
            with timed(metrics,'opa_ms'):
                decision, policy_hash, policy = self.signed_policy.evaluate(facts)
            snapshot = {'version':1,'input':facts,'policyHash':policy_hash,'policyVersion':policy['policyVersion'],
                        'opaVersion':policy['opaVersion'],'verdict':'PASS' if decision else 'FAIL','timestamp':now,
                        'submissionID':rid,'vendorID':row['vendor_id'],'identityHash':sha(canonical(attestation)),
                        'envelopeHash':sha(canonical({'envelope':json.loads(row['envelope']),'context':json.loads(row['context'])}))}
            receipt = {'version':'vendorchain.receipt.v2','recordID':rid,'vendorID':row['vendor_id'],
                       'documentHash':row['document_hash'],'ciphertextHash':row['cipher_hash'],
                       'sbomHash':sha(sbom_path.read_bytes()),'artifactHash':artifact_hash,
                       'identityHash':sha(canonical(attestation)),'snapshotHash':sha(canonical(snapshot)),
                       'policyHash':policy_hash,'decision':snapshot['verdict'],'keyID':self.key_id,
                       'issuedAt':now,'expiresAt':now+600,'nonce':rid,'algorithm':'sha256'}
            receipt['evidenceRoot'] = evidence_root(receipt,now)
            with timed(metrics,'attest_ms'):
                raw = canonical(receipt)
                payload = {'recordID':rid,'receipt':encode(raw),'receiptHash':sha(raw),
                           'signature':encode(self.private_key.sign(raw)),
                           'snapshotSignature':encode(self.private_key.sign(bytes.fromhex(receipt['snapshotHash'])))}
                self.verify_payload(payload)
            evidence = {'identity':attestation,'snapshot':snapshot,'receipt':payload,
                        'envelope':json.loads(row['envelope']),'context':json.loads(row['context'])}
            durable_write(self.root/'evidence'/(rid+'.json'),canonical(evidence))
            with timed(metrics,'outbox_prepare_ms'):
                self.store.prepare(row,payload)
            return payload
        except BaseException:
            self.store.fail_processing(rid,row['version'])
            raise
        finally:
            if plaintext is not None:
                plaintext[:] = b'\0'*len(plaintext)

    def validate_pending(self, rid, receipt, metrics):
        evidence = json.loads((self.root/'evidence'/(rid+'.json')).read_text())
        with timed(metrics,'identity_revalidate_ms'):
            identity = verify_document(evidence['identity'],self.registry,'vendorchain.identity.v1','identity')
            if (sha(canonical(evidence['identity'])) != receipt['identityHash'] or identity['submissionID'] != rid
                    or identity['vendorID'] != receipt['vendorID'] or identity['documentHash'] != receipt['documentHash']):
                raise Conflict('identity attestation changed')
        with timed(metrics,'snapshot_revalidate_ms'):
            snapshot = evidence['snapshot']
            if sha(canonical(snapshot)) != receipt['snapshotHash'] or snapshot['identityHash'] != receipt['identityHash']:
                raise Conflict('decision snapshot changed')
            row = self.store.get(rid)
            binding = {'envelope':json.loads(row['envelope']),'context':json.loads(row['context'])}
            retained = {'envelope':evidence['envelope'],'context':evidence['context']}
            if binding != retained or sha(canonical(binding)) != snapshot['envelopeHash']:
                raise Conflict('encrypted object envelope/context changed')
            decision, bundle_hash, _ = self.signed_policy.evaluate(snapshot['input'])
            if (bundle_hash != receipt['policyHash'] or snapshot['policyHash'] != bundle_hash
                    or ('PASS' if decision else 'FAIL') != receipt['decision']):
                raise Conflict('commit-time policy decision mismatch')
        with timed(metrics,'provenance_revalidate_ms'):
            self.provenance.verify(self.root/'sbom'/(rid+'.json'),expected_hash=receipt['sbomHash'])
            if tree_hash(self.source) != receipt['artifactHash']:
                raise Conflict('commit-time artifact changed')
