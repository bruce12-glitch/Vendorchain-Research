"""Fresh-process local stage experiments. Syft is explicitly null when unavailable."""
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import subprocess
import sys
import tempfile
import time
from .corpus import png
from .crypto import encrypt,decrypt
from .ingress import validate
from .pipeline import timed
from .sandbox import isolated
from .settings import initialize,configured
from .stats import summarize

VARIANTS=['structural_inline','isolated_pipeline','hardened','hardened_crypto_x10']
def disk_bytes(root):
    return sum(p.stat().st_size for p in Path(root).rglob('*') if p.is_file())

def trial(variant,source=None):
    data=png(11);metrics={};start=time.perf_counter_ns()
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);initialize(root)
        before=disk_bytes(root)
        cpu=time.process_time()
        if variant in ('structural_inline','isolated_pipeline'):
            with timed(metrics,'gate_ms'):
                info=validate(data) if variant=='structural_inline' else isolated(data)['info']
            context={'recordID':'trial','vendorID':'ablation'}
            with timed(metrics,'encrypt_ms'):cipher,meta=encrypt(data,b'k'*32,context)
            with timed(metrics,'decrypt_ms'):plain=decrypt(cipher,meta,b'k'*32,context)
            try:
                with timed(metrics,'worker_ms'):
                    worker=isolated(bytes(plain),ocr=True)
                    metrics.update(ocr_ms=worker['ocrMs'],worker_peak_rss_kib=worker['peakRssKiB'],worker_cpu_seconds=worker['cpuSeconds'])
            finally:plain[:]=b'\x00'*len(plain)
            if source:
                with timed(metrics,'syft_ms'):
                    sbom=subprocess.run(['syft','dir:'+str(Path(source).resolve()),'-o','cyclonedx-json'],capture_output=True,timeout=60,check=True).stdout
                    if json.loads(sbom).get('bomFormat')!='CycloneDX':raise ValueError('invalid SBOM')
            else:metrics['syft_ms']=None
        else:
            pipeline=configured(root,local=True,source=source,no_sbom=not bool(source))
            if variant=='hardened_crypto_x10':
                with timed(metrics,'extra_crypto_ms'):
                    for _ in range(10):
                        c,m=encrypt(data,pipeline.kek,{'benchmark':'extra-loop'})
                        p=decrypt(c,m,pipeline.kek,{'benchmark':'extra-loop'});p[:]=b'\x00'*len(p)
            metrics.update(pipeline.run(data,'ablation','trial')['stages'])
        elapsed=(time.perf_counter_ns()-start)/1e6
        own=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
        return {'variant':variant,'elapsed_ms':elapsed,'stages':metrics,'parent_cpu_seconds':time.process_time()-cpu,
                'children_cpu_seconds':child.ru_utime+child.ru_stime,'peak_rss_kib':max(own.ru_maxrss,child.ru_maxrss),
                'disk_growth_bytes':disk_bytes(root)-before,'input_bytes':len(data),'evidence':'local-non-consensus',
                'syftExecuted':bool(source),'pid':os.getpid()}

def campaign(output,trials=50,warmups=5,source=None):
    if trials<1 or warmups<0:raise ValueError('invalid trial counts')
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    if (out/'raw.jsonl').exists():
        raise FileExistsError('use a new output directory for each campaign')
    raw=[];rng=random.Random(20261030)
    for iteration in range(warmups+trials):
        order=VARIANTS.copy();rng.shuffle(order)
        for variant in order:
            command=[sys.executable,'-m','vendorchain.ablation',variant]
            if source:command+=['--source',str(Path(source).resolve())]
            result=subprocess.run(command,capture_output=True,timeout=180,check=True,cwd=Path(__file__).resolve().parents[1])
            row={**json.loads(result.stdout),'trial':iteration-warmups,'warmup':iteration<warmups}
            raw.append(row)
            with (out/'raw.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
    summary={v:{'elapsed_ms':summarize([r['elapsed_ms'] for r in raw if r['variant']==v and not r['warmup']]),
                'peak_rss_kib':summarize([r['peak_rss_kib'] for r in raw if r['variant']==v and not r['warmup']]),
                'disk_growth_bytes':summarize([r['disk_growth_bytes'] for r in raw if r['variant']==v and not r['warmup']])} for v in VARIANTS}
    result={'kind':'local-stage-ablation','trialsPerVariant':trials,'warmupsDiscardedPerVariant':warmups,
            'syftExecuted':bool(source),'variants':summary,'fabricBenchmarkExecuted':False,
            'limitations':['same synthetic image; no historical corporate documents','local SQLite ledger double; no Raft/BFT measurement','fresh process per trial, shared host caches; randomized variant order']}
    (out/'summary.json').write_text(json.dumps(result,indent=2))
    return result

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('variant',choices=VARIANTS);parser.add_argument('--source')
    args=parser.parse_args();print(json.dumps(trial(args.variant,args.source)))
