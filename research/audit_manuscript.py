"""Observed checks against manuscript claims; failed requirements stay explicit."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import time
import zipfile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vendorchain.crypto import encrypt,decrypt,encode
from vendorchain.corpus import png
from vendorchain.ingress import Rejected
from vendorchain.ledger import LocalLedger
from vendorchain.pipeline import Pipeline

root=Path(__file__).resolve().parent.parent
out=root/'research/results/manuscript-audit';out.mkdir(parents=True,exist_ok=True)
observations=[]
def record(check,requirement_met,**facts):
    row={'check':check,'requirementMet':requirement_met,**facts}
    observations.append(row);print(json.dumps(row,sort_keys=True))

suites={}
for path in sorted((root/'research/tests').glob('test_*.py')):
    for node in ast.parse(path.read_text()).body:
        if isinstance(node,ast.ClassDef):
            cases=[m.name for m in node.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name.startswith('test_')]
            if cases:suites[str(path.relative_to(root))+':'+node.name]=cases
record('original_12_suites_44_tests',False,pythonTestClasses=len(suites),pythonTests=sum(map(len,suites.values())),
       originalHistoricalSuiteRecovered=False,luhnImplementationPresent=False,opaImplementationPresent=False)
with zipfile.ZipFile(root/'research/fixtures/generated-corpus.zip') as archive:
    entries=json.loads(archive.read('manifest.json'))['entries']
    spoof=[e for e in entries if e['family']=='exe-extension-spoof']
    pe=sum(archive.read(e['path']).startswith(b'MZ') for e in spoof)
    elf=sum(archive.read(e['path']).startswith(b'\x7fELF') for e in spoof)
    record('original_15_PE_ELF_fixtures',False,generatedPrefixFixtures=len(spoof),PEPrefix=pe,ELFPrefix=elf,
           originalHistoricalFixturesRecovered=False,loadableExecutablesValidated=False)

# The exact expected cryptographic exception is recorded, not any exception.
kek=bytes(range(32));context={'vendorID':'audit-vendor','recordID':'audit-record','documentType':'COMPLIANCE_DOCUMENT'}
cipher,metadata=encrypt(b'INERT synthetic private document',kek,context)
for field,value in [('vendorID','other-vendor'),('recordID','other-submission')]:
    try:
        decrypt(cipher,metadata,kek,{**context,field:value})
    except InvalidTag:
        record('cross_context_GCM_'+field,True,exception='cryptography.exceptions.InvalidTag',sameCiphertext=True,sameWrappedDEK=True)
    else:raise AssertionError('cross-context decryption unexpectedly succeeded')

with tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp);private=Ed25519PrivateKey.generate();now=int(time.time())
    registry={'audit':{'publicKey':encode(private.public_key().public_bytes_raw()),'notBefore':now-30,'notAfter':now+7200,'revoked':False}}
    ledger=LocalLedger(path/'ledger.sqlite',registry)
    pipeline=Pipeline(path/'state',kek,private,'audit',registry,ledger,ocr=False,sbom=False)
    for family,prefix in [('PE',b'MZ'),('ELF',b'\x7fELF')]:
        receive=bytearray(prefix+b'INERT audit specimen')
        before=len(list((path/'state/blobs').glob('*.enc')))
        try:pipeline.ingest(receive,'audit-vendor','reject-'+family)
        except Rejected as exc:reason=str(exc)
        else:raise AssertionError('executable prefix accepted')
        after=len(list((path/'state/blobs').glob('*.enc')))
        zeroed=all(x==0 for x in receive)
        record('executable_rejection_'+family,reason=='EXECUTABLE_SPOOF' and zeroed and before==after,
               observedReason=reason,expectedReason='EXECUTABLE_SPOOF',ownedReceiveBufferZeroed=zeroed,
               encryptedObjectsBefore=before,encryptedObjectsAfter=after,
               objectBackend='local encrypted files, not S3/MinIO',rejectionOccurredBeforeObjectPersistence=before==after)
    first=pipeline.run(png(),'audit-vendor','content-first')
    second=pipeline.run(png(),'audit-vendor','content-second')
    record('H7_content_digest_replay_window',False,sameContentDigest=True,differentSubmissionIDs=True,
           firstCommitted=first['ack']['successful'],secondCommitted=second['ack']['successful'],
           note='Request-ID idempotency exists; content-digest/retention-window replay rejection does not.')

record('Section_6_3_five_warmups',False,retainedIndependentDeployments=50,
       observedWarmupsPerDeployment=1,requiredWarmups=5,
       observedExecution='parallel independent runners',requiredExecution='sequential trials with no competing load')
record('Table_9_historical_timers',False,originalTerminalOutputsRecovered=False,
       claimedHeaderGateMs=1.2,claimedEnvelope5MBMs=4.8,claimedLuhnMs=.04,claimedIngestionToCommitMs=342,
       note='Claims are not observations from this audit. Current BFT measurements use another implementation/testbed/load.')
(out/'observations.json').write_text(json.dumps({'observations':observations,'suiteInventory':suites},indent=2))
