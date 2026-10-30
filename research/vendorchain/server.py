"""Bounded loopback research HTTP server; deploy behind a proper authenticated ingress."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import resource
import time
from .crypto import canonical
from .ingress import MAX_BYTES, Rejected
from .store import Conflict

async def serve(pipeline, token, port=8090, workers=8, max_pending=10000):
    if len(token) < 32:
        raise ValueError('API token must be at least 32 characters')
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=workers))
    waiting = active = buffered = 0
    peak_buffered = 0
    async def handle(reader, writer):
        nonlocal waiting, active, buffered, peak_buffered
        code, result = 500, {'error':'internal failure'}
        acquired = False
        reserved = 0
        start = time.perf_counter_ns()
        try:
            header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),timeout=10)
            if len(header) > 8192:
                raise ValueError('header limit')
            lines = header.decode('ascii').split('\r\n')
            method, target, protocol = lines[0].split(' ')
            headers = {}
            for line in lines[1:]:
                if line:
                    k,v = line.split(':',1); k=k.lower()
                    if k in headers:
                        raise ValueError('duplicate header')
                    headers[k]=v.strip()
            if not hmac.compare_digest(hashlib.sha256(headers.get('authorization','').encode()).digest(), hashlib.sha256(('Bearer '+token).encode()).digest()):
                code,result=401,{'error':'unauthorized'}
            elif method=='GET' and target=='/health':
                code,result=200,{'evidence':pipeline.ledger.kind,'workers':workers,'active':active,'pending':waiting,
                                 'bufferedBytes':buffered,'peakBufferedBytes':peak_buffered,'bufferLimitBytes':64*1024*1024}
                result['processPeakRssKiB'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            elif method!='POST' or target!='/v1/uploads':
                code,result=404,{'error':'not found'}
            elif 'transfer-encoding' in headers:
                raise ValueError('Content-Length required')
            elif waiting >= max_pending:
                code,result=503,{'error':'ingress capacity reached'}
            else:
                length = int(headers.get('content-length','0'))
                if not 0 < length <= MAX_BYTES:
                    raise ValueError('file size outside policy')
                if buffered + length > 64*1024*1024:
                    code,result=503,{'error':'upload memory budget reached'}
                    return
                waiting += 1; acquired=True
                buffered += length; reserved = length
                peak_buffered = max(peak_buffered, buffered)
                # Keep the one owned receive buffer mutable through ingestion.
                body = bytearray(length)
                async def read_body():
                    position = 0
                    while position < length:
                        chunk = await reader.read(min(65536, length-position))
                        if not chunk:
                            raise asyncio.IncompleteReadError(b'', length-position)
                        body[position:position+len(chunk)] = chunk
                        position += len(chunk)
                await asyncio.wait_for(read_body(),timeout=60)
                vendor = headers.get('x-vendor-id','research-vendor')
                rid = headers.get('x-request-id')
                active += 1
                try:
                    queued_at = time.perf_counter_ns()
                    def execute():
                        queue_ms = (time.perf_counter_ns()-queued_at)/1e6
                        completed = pipeline.run(body,vendor,rid)
                        completed.setdefault('stages',{})['queue_dispatch_ms'] = queue_ms
                        return completed
                    result = await asyncio.to_thread(execute)
                    result['server_ingestion_to_commit_ms']=(time.perf_counter_ns()-start)/1e6
                    code=200
                finally:
                    active -= 1
        except Rejected as exc:
            code,result=422,{'error':str(exc)}
        except Conflict as exc:
            code,result=409,{'error':str(exc)}
        except (ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            code,result=400,{'error':'invalid request'}
        except (TimeoutError, asyncio.TimeoutError):
            code,result=408,{'error':'request timeout'}
        except Exception:
            code,result=503,{'error':'processing or commit unconfirmed; inspect/reconcile outbox'}
        finally:
            if 'body' in locals() and isinstance(body, bytearray):
                body[:] = b'\x00' * len(body)
            if acquired:
                waiting-=1
                buffered-=reserved
            body=canonical(result)
            writer.write(f'HTTP/1.1 {code} Result\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()+body)
            try:
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
    server = await asyncio.start_server(handle,'127.0.0.1',port,limit=8192,backlog=16384)
    async with server:
        await server.serve_forever()
