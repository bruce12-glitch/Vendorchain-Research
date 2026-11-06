"""One cumulative Table 12 trial. Disabled-control variants exist only here.

Use experiment.py to run this in a fresh process. Early variants intentionally
persist plaintext, so use a disposable directory and synthetic/public input only.
"""
import argparse
import io
import json
import os
from pathlib import Path
import resource
import tempfile
import time
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
from hardened_cli import configured
from vendorchain.crypto import canonical, encrypt, decrypt
from vendorchain.evidence import sha, sign_document, verify_document
from vendorchain.gstin import valid_gstin
from vendorchain.pipeline import timed, durable_write
from vendorchain.sandbox import isolated

VARIANTS=['baseline','gate','encryption','identity','provenance','policy','full']
COMPARATORS=['full_without_client_revalidation','full_crypto_x10']


def identity_png(nonce):
    image=Image.new('RGB',(1100,300),'white');draw=ImageDraw.Draw(image)
    draw.multiline_text((24,24),'VENDORCHAIN\n27AAPFU0939F1ZV',font=ImageFont.truetype('DejaVuSansMono.ttf',44),fill='black',spacing=15)
    meta=PngImagePlugin.PngInfo();meta.add_text('TrialNonce',str(nonce))
    output=io.BytesIO();image.save(output,format='PNG',pnginfo=meta);return output.getvalue()


def run(variant, config, *, input_file=None, local=False, allow_local_keys=False):
    directory=Path(os.environ['VENDORCHAIN_TRIAL_DIR']);directory.mkdir(parents=True,exist_ok=True)
    metrics={};success=True;verdict=None;reason=None
    config_hash=sha(Path(config).read_bytes())
    data=Path(input_file).read_bytes() if input_file else identity_png(os.urandom(8).hex())
    if not input_file:(directory/'input.png').write_bytes(data)
    plaintext=None
    with tempfile.TemporaryDirectory(prefix='vendorchain-trial-') as tmp:
        p=configured(config,local=local,allow_local_keys=allow_local_keys,root_override=Path(tmp)/'pipeline')
        if sha(Path(config).read_bytes()) != config_hash:
            raise ValueError('experiment configuration changed during initialization')
        root=p.root;cpu=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
        initial_disk=sum(x.stat().st_size for x in root.rglob('*') if x.is_file())
        started=time.perf_counter_ns()
        try:
            if variant in ['full',*COMPARATORS]:
                if variant=='full_without_client_revalidation':
                    if not local:raise ValueError('disabled checks are confined to the local experimental worker')
                    p.validate_pending=lambda *_:None
                if variant=='full_crypto_x10':
                    with timed(metrics,'extra_crypto_ms'):
                        for _ in range(10):
                            c,m=encrypt(data,p.kek,{'benchmark':'extra-loop'})
                            plain=decrypt(c,m,p.kek,{'benchmark':'extra-loop'});plain[:]=b'\0'*len(plain)
                result=p.run(bytearray(data),'ablation-vendor')
                metrics.update(result['stages']);verdict=result['decision'];success=verdict=='PASS'
            else:
                stage=VARIANTS.index(variant)
                if stage==0:
                    with timed(metrics,'plaintext_persist_ms'):durable_write(root/'baseline.bin',data)
                else:
                    with timed(metrics,'gate_ms'):isolated(data)
                    if stage==1:
                        with timed(metrics,'plaintext_persist_ms'):durable_write(root/'baseline.bin',data)
                    if stage>=2:
                        context={'recordID':'ablation','vendorID':'ablation-vendor','documentType':'COMPLIANCE_DOCUMENT'}
                        with timed(metrics,'encrypt_ms'):cipher,envelope=encrypt(data,p.kek,context)
                        with timed(metrics,'persist_ms'):durable_write(root/'document.enc',cipher)
                    if stage>=3:
                        with timed(metrics,'decrypt_ms'):plaintext=decrypt(cipher,envelope,p.kek,context)
                        with timed(metrics,'worker_ms'):worker=isolated(bytes(plaintext),ocr=True,expected=p.expected)
                        metrics['ocr_ms']=worker['ocrMs']
                        with timed(metrics,'identity_attestation_ms'):
                            ok=valid_gstin(p.gstin,p.expected_pan) and worker['ocr']['expectedCount']>0 and worker['ocr']['expectedMatches']
                            attestation=sign_document({'state':'verified' if ok else 'failed','gstin':p.gstin,'documentHash':sha(data)},
                                    p.identity_signer,p.identity_key_id,'vendorchain.identity.v1')
                            state=verify_document(attestation,p.registry,'vendorchain.identity.v1','identity')['state']
                            durable_write(root/'identity.json',canonical(attestation))
                        success=bool(ok);verdict='PASS' if ok else 'FAIL'
                    if stage>=4:
                        bom,_=p.provenance.build(p.source,root/'sbom/ablation.json',metrics)
                    if stage>=5:
                        facts={'identity':{'state':state},'sbom':{'present':True,'component_count':len(bom.get('components',[])),
                               'components':bom.get('components',[]),'schema':'cyclonedx'},'replay':{'detected':False},
                               'policy':p.signed_policy.load()[0]['parameters'],
                               'provenance':{'signature_valid':True,'certificate_approved':p.provenance.approved(),
                               'certificate_expired':False,'artifact_digest_bound':True}}
                        with timed(metrics,'opa_ms'):allowed,_,_=p.signed_policy.evaluate(facts)
                        success=allowed;verdict='PASS' if allowed else 'FAIL'
        except Exception as exc:
            success=False;reason=type(exc).__name__
        finally:
            if plaintext is not None:plaintext[:]=b'\0'*len(plaintext)
        metrics['elapsed_ms']=(time.perf_counter_ns()-started)/1e6
        own=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
        metrics.update(parent_cpu_seconds=own.ru_utime+own.ru_stime-cpu.ru_utime-cpu.ru_stime,
                       child_cpu_seconds=child.ru_utime+child.ru_stime-children.ru_utime-children.ru_stime,
                       parent_peak_rss_kib=own.ru_maxrss,largest_child_peak_rss_kib=child.ru_maxrss,
                       disk_growth_bytes=sum(x.stat().st_size for x in root.rglob('*') if x.is_file())-initial_disk)
        row={'successful':bool(success),'variant':variant,'metrics':{k:v for k,v in metrics.items() if type(v) in (int,float)},
             'evidence':p.ledger.kind if variant in ['full',*COMPARATORS] else 'offchain-stage-ablation',
             'decision':verdict,'error':reason,'inputSHA256':sha(data),'inputBytes':len(data),
             'inputKind':'external-file' if input_file else 'generated-synthetic-png',
             'configSHA256':config_hash,'signedPolicySHA256':p.policy_hash(),
             'operationalStore':type(p.store).__name__,
             'custody':'research-local-keys' if allow_local_keys else 'configured-remote-service',
             'limitations':['synthetic PNG unless --file provided','RSS is separate process high-water marks, not aggregate concurrent process-tree RSS',
                            'full adds H2/H3/H4 and operational outbox as well as ledger; it is the hardened version of Table 12']}
        (directory/'measurement.json').write_text(json.dumps(row,indent=2))
    return row


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--variant',choices=VARIANTS+COMPARATORS,required=True)
    parser.add_argument('--config',required=True);parser.add_argument('--file');parser.add_argument('--local',action='store_true')
    parser.add_argument('--allow-local-keys',action='store_true');a=parser.parse_args()
    result=run(a.variant,a.config,input_file=a.file,local=a.local,allow_local_keys=a.allow_local_keys)
    print(json.dumps({'successful':result['successful'],'variant':a.variant,'error':result['error']}))
