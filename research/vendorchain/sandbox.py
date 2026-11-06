"""Bounded subprocess boundary for parsing, rendering and OCR; no plaintext files."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import time
from .ingress import MAX_BYTES, Rejected

TIMEOUT = 45
OCR_POLICY = {'version':'normalized-substring-levenshtein.v1','threshold':0.90,
              'maxExpectedTerms':16,'maxExpectedCharacters':64,'maxOCRCharacters':20000}


def ocr_score(expected, text):
    term = ''.join(re.findall(r'[a-z0-9]', expected.casefold()))
    normalized = ''.join(re.findall(r'[a-z0-9]', text.casefold()))
    if not term or len(term)>OCR_POLICY['maxExpectedCharacters'] or len(normalized)>OCR_POLICY['maxOCRCharacters']:
        raise Rejected('ocr_comparison_limit')
    if term in normalized:return 1.0
    # Approximate substring matching: free text prefix/suffix, unit edit cost.
    previous=list(range(len(term)+1));best=len(term)
    for char in normalized:
        current=[0]
        for index,wanted in enumerate(term,1):
            current.append(min(previous[index]+1,current[index-1]+1,previous[index-1]+(char!=wanted)))
        best=min(best,current[-1]);previous=current
    return max(0.0,1.0-best/len(term))

def isolated(data, *, ocr=False, expected=()):
    if not 0 < len(data) <= MAX_BYTES:
        raise Rejected('file_size_limit')
    request = json.dumps({'data': base64.b64encode(data).decode(), 'ocr': ocr, 'expected': list(expected)})
    try:
        proc = subprocess.run([sys.executable, '-m', 'vendorchain.sandbox'], input=request.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT,
                              cwd=Path(__file__).resolve().parents[1],
                              env=parser_environment())
    except subprocess.TimeoutExpired as exc:
        raise Rejected('worker_wall_timeout') from exc
    if proc.returncode:
        raise Rejected('worker_resource_or_process_failure')
    try:
        result = json.loads(proc.stdout)
    except (ValueError, UnicodeError) as exc:
        raise Rejected('invalid_worker_response') from exc
    if not result.get('ok'):
        raise Rejected(result.get('reason', 'worker_rejected'))
    return result


def parser_environment():
    # Do not inherit KEKs, API/gateway/Vault tokens or arbitrary signer secrets.
    result={'PATH':os.environ.get('PATH',os.defpath),
            'PYTHONPATH':str(Path(__file__).resolve().parents[1]),'LANG':'C.UTF-8',
            'OMP_THREAD_LIMIT':'1','OPENBLAS_NUM_THREADS':'1'}
    for name in ('TESSDATA_PREFIX','LD_LIBRARY_PATH','PYTHONUSERBASE'):
        if name in os.environ:result[name]=os.environ[name]
    return result

def run_ocr(data, info, expected):
    if len(expected)>OCR_POLICY['maxExpectedTerms']:
        raise Rejected('ocr_expected_term_limit')
    texts = []
    pages = info['pages']
    for page in range(1, pages+1):
        image = data
        if info['format'] == 'PDF':
            image = subprocess.run(['pdftoppm', '-f', str(page), '-l', str(page), '-singlefile',
                                    '-scale-to', '3000', '-png', '-'], input=data,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True).stdout
        proc = subprocess.run(['tesseract', 'stdin', 'stdout', '--psm', '6'], input=image,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
        texts.append(proc.stdout.decode('utf-8', errors='replace'))
    text = '\n'.join(texts)
    scores = [ocr_score(term,text) for term in expected]
    # OCR text and expected credentials never leave this short-lived process.
    return {'engine':'tesseract', 'textHash': hashlib.sha256(text.encode()).hexdigest(),
            'expectedMatches': bool(scores) and all(score>=OCR_POLICY['threshold'] for score in scores),
            'expectedCount': len(expected),'scores':scores,'policy':OCR_POLICY}

def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    started = time.perf_counter()
    try:
        from .ingress import validate
        req = json.loads(sys.stdin.buffer.read(2*MAX_BYTES))
        data = base64.b64decode(req['data'], validate=True)
        info = validate(data)
        gate_ms = (time.perf_counter()-started)*1000
        start = time.perf_counter()
        ocr = run_ocr(data, info, req['expected']) if req['ocr'] else None
        own = resource.getrusage(resource.RUSAGE_SELF)
        child = resource.getrusage(resource.RUSAGE_CHILDREN)
        result = {'ok':True, 'info':info, 'ocr':ocr, 'gateMs':gate_ms,
                  'ocrMs':(time.perf_counter()-start)*1000 if req['ocr'] else 0,
                  'cpuSeconds':own.ru_utime+own.ru_stime+child.ru_utime+child.ru_stime,
                  'peakRssKiB':max(own.ru_maxrss, child.ru_maxrss)}
    except Exception as exc:
        result = {'ok':False, 'reason':str(exc) if isinstance(exc, Rejected) else type(exc).__name__}
    sys.stdout.write(json.dumps(result))

if __name__ == '__main__':
    main()
