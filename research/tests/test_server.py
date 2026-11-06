import asyncio
import json
import socket
import unittest
from types import SimpleNamespace
from vendorchain.server import serve

class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        sock=socket.socket();sock.bind(('127.0.0.1',0));self.port=sock.getsockname()[1];sock.close()
        self.token='test-token-'+'x'*32
        self.calls=[]
        def run(body,vendor,rid):
            self.calls.append((bytes(body),vendor,rid))
            return {'ack':{'successful':True,'transactionID':'local-test'},'evidence':'local-non-consensus','stages':{}}
        pipeline=SimpleNamespace(ledger=SimpleNamespace(kind='local-non-consensus'),run=run)
        self.task=asyncio.create_task(serve(pipeline,self.token,self.port,workers=1))
        for _ in range(50):
            try:
                r,w=await asyncio.open_connection('127.0.0.1',self.port);w.close();await w.wait_closed();break
            except OSError:await asyncio.sleep(.01)
    async def asyncTearDown(self):
        self.task.cancel()
        try:await self.task
        except asyncio.CancelledError:pass
    async def request(self,header,body=b''):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.port)
        writer.write(header+body);await writer.drain()
        response=await reader.read();writer.close();await writer.wait_closed()
        return response
    async def test_authenticated_upload_returns_commit(self):
        h=f'POST /v1/uploads HTTP/1.1\r\nAuthorization: Bearer {self.token}\r\nContent-Length: 3\r\nX-Vendor-ID: vendor\r\nX-Request-ID: r1\r\n\r\n'.encode()
        result=await self.request(h,b'abc');self.assertTrue(result.startswith(b'HTTP/1.1 200'))
        self.assertEqual(self.calls,[(b'abc','vendor','r1')])
        self.assertIn(b'queue_dispatch_ms',result)
    async def test_oversized_length_rejected_before_body_or_pipeline(self):
        header=f'POST /v1/uploads HTTP/1.1\r\nAuthorization: Bearer {self.token}\r\nContent-Length: 1073741824\r\n\r\n'.encode()
        self.assertTrue((await self.request(header)).startswith(b'HTTP/1.1 400'))
        self.assertEqual(self.calls,[])
    async def test_health_exposes_owned_buffer_limit(self):
        header=f'GET /health HTTP/1.1\r\nAuthorization: Bearer {self.token}\r\n\r\n'.encode()
        result=await self.request(header)
        payload=json.loads(result.split(b'\r\n\r\n',1)[1])
        self.assertEqual(payload['bufferedBytes'],0)
        self.assertEqual(payload['bufferLimitBytes'],64*1024*1024)
    async def test_unauthorized_request_cannot_execute_pipeline(self):
        result=await self.request(b'POST /v1/uploads HTTP/1.1\r\nContent-Length: 3\r\n\r\n',b'abc')
        self.assertTrue(result.startswith(b'HTTP/1.1 401'));self.assertEqual(self.calls,[])
    async def test_ambiguous_content_length_rejected(self):
        h=f'POST /v1/uploads HTTP/1.1\r\nAuthorization: Bearer {self.token}\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n'.encode()
        self.assertTrue((await self.request(h)).startswith(b'HTTP/1.1 400'));self.assertEqual(self.calls,[])
    async def test_chunked_upload_cannot_bypass_size_limit(self):
        h=f'POST /v1/uploads HTTP/1.1\r\nAuthorization: Bearer {self.token}\r\nTransfer-Encoding: chunked\r\n\r\n'.encode()
        self.assertTrue((await self.request(h)).startswith(b'HTTP/1.1 400'));self.assertEqual(self.calls,[])
