"""Controlled local oversized-header sweep, with a separate real API process.

Clients declare 1 GiB, sending no document body. This tests early size rejection,
not aggregate memory bounds for accepted bodies, slow clients or a Fabric load.
"""
import argparse
import asyncio
from collections import Counter
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from vendorchain.settings import initialize

ROOT=Path(__file__).resolve().parent.parent

async def burst(port,token,level):
    active=peak=0
    async def request(index):
        nonlocal active,peak
        writer=None;started=time.perf_counter_ns()
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',port),30)
            active+=1;peak=max(peak,active)
            writer.write(f'POST /v1/uploads HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: 1073741824\r\nX-Request-ID: oversized-{index}\r\n\r\n'.encode())
            await writer.drain()
            header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),30)
            status=int(header.split(b' ',2)[1])
            return {'request':index,'status':status,'latencyMs':(time.perf_counter_ns()-started)/1e6}
        except Exception as exc:
            return {'request':index,'status':0,'error':type(exc).__name__}
        finally:
            if writer is not None:
                active-=1;writer.close()
                try:await writer.wait_closed()
                except OSError:pass
    rows=await asyncio.gather(*(request(i) for i in range(level)))
    return rows,peak

def campaign(output,levels):
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    reports=[]
    with tempfile.TemporaryDirectory() as tmp:
        state=Path(tmp)/'state';initialize(state)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        token=secrets.token_hex(32)
        env={**os.environ,'PYTHONPATH':str(ROOT/'research'),'API_TOKEN':token}
        with (out/'api.log').open('w') as log:
            proc=subprocess.Popen([sys.executable,'-m','vendorchain','serve','--state',str(state),'--local',
                                   '--no-sbom','--no-ocr','--port',str(port)],env=env,cwd=ROOT,stdout=log,stderr=log)
            def health():
                req=urllib.request.Request(f'http://127.0.0.1:{port}/health',headers={'Authorization':'Bearer '+token})
                with urllib.request.urlopen(req,timeout=5) as response:return json.load(response)
            try:
                for _ in range(100):
                    try:health();break
                    except OSError:
                        if proc.poll() is not None:raise RuntimeError('API failed to start')
                        time.sleep(.05)
                else:raise RuntimeError('API start timeout')
                for level in levels:
                    before=health()['processPeakRssKiB']
                    rows,peak=asyncio.run(burst(port,token,level))
                    counts=Counter(r['status'] for r in rows);observed=health()
                    (out/f'requests-c{level}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
                    reports.append({'offeredConcurrency':level,'trials':1,'peakClientOpenConnections':peak,
                                    'statuses':dict(counts),'serverLifetimePeakRssBeforeKiB':before,
                                    'serverLifetimePeakRssAfterKiB':observed['processPeakRssKiB'],
                                    'rssMeasurement':'API process getrusage(RUSAGE_SELF).ru_maxrss; Linux KiB; excludes children',
                                    'healthAfter':observed,'encryptedObjectCount':len(list((state/'pipeline/blobs').glob('*')))})
                    if observed['bufferedBytes'] or observed['peakBufferedBytes'] or counts.get(200):
                        raise AssertionError('oversized request entered the upload pipeline')
            finally:
                proc.terminate()
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
    result={'kind':'local-oversized-declared-length-smoke','conditions':reports,
            'bodyBytesSentPerRequest':0,'declaredLengthBytes':1073741824,
            'consensusTested':False,'statisticalProtocolMet':False,
            'limitations':['N=1 per level','offered concurrency is not guaranteed simultaneous arrival',
                           'no body/slow-client/accepted-upload memory claim',
                           'RSS is lifetime peak for one reused API process; not an aggregate system bound']}
    (out/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    parser.add_argument('--concurrency',default='100,1000,10000');args=parser.parse_args()
    levels=[int(x) for x in args.concurrency.split(',')]
    if any(x<1 or x>10000 for x in levels):parser.error('concurrency must be 1..10000')
    campaign(args.output,levels)
