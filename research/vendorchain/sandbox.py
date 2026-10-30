"""Bounded subprocess boundary for parsing, rendering and OCR; no plaintext files."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time
from .ingress import MAX_BYTES, Rejected

TIMEOUT = 45

def isolated(data, *, ocr=False, expected=()):
    if not 0 < len(data) <= MAX_BYTES:
        raise Rejected('file_size_limit')
    request = json.dumps({'data': base64.b64encode(data).decode(), 'ocr': ocr, 'expected': list(expected)})
    try:
        proc = subprocess.run([sys.executable, '-m', 'vendorchain.sandbox'], input=request.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT,
                              cwd=Path(__file__).resolve().parents[1],
                              env={**os.environ, 'OMP_THREAD_LIMIT':'1', 'OPENBLAS_NUM_THREADS':'1'})
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

def run_ocr(data, info, expected):
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
    # OCR text and expected credentials never leave this short-lived process.
    return {'engine':'tesseract', 'textHash': hashlib.sha256(text.encode()).hexdigest(),
            'expectedMatches': all(term.casefold() in text.casefold() for term in expected),
            'expectedCount': len(expected)}

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
