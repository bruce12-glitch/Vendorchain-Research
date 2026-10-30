import hashlib
import json
import sqlite3
import urllib.request
from urllib.parse import urlparse
from .crypto import canonical
from .trust import verify

class LocalLedger:
    """Durable test double. Never represents Raft, BFT, or production throughput."""
    kind = 'local-non-consensus'
    def __init__(self, path, registry):
        self.path, self.registry = path, registry
        with sqlite3.connect(path) as con:
            con.execute('CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, hash TEXT NOT NULL, tx TEXT NOT NULL)')
    def lookup(self, payload):
        with sqlite3.connect(self.path,timeout=60) as con:
            row=con.execute('SELECT hash,tx FROM records WHERE id=?',(payload['recordID'],)).fetchone()
        if row is None:return None
        if row[0]!=payload['receiptHash']:raise ValueError('conflicting historical receipt')
        return {'successful':True,'transactionID':row[1],'receiptHash':row[0],'kind':self.kind}
    def submit(self, payload):
        verify(payload,self.registry)
        with sqlite3.connect(self.path, timeout=60) as con:
            tx = 'local-'+hashlib.sha256(canonical(payload)).hexdigest()
            con.execute('INSERT OR IGNORE INTO records VALUES(?,?,?)', (payload['recordID'],payload['receiptHash'],tx))
            row = con.execute('SELECT hash,tx FROM records WHERE id=?',(payload['recordID'],)).fetchone()
            if row[0] != payload['receiptHash']:
                raise ValueError('ledger replay has different receipt')
        return {'successful':True,'transactionID':row[1],'receiptHash':row[0],'kind':self.kind}

class FabricLedger:
    kind = 'fabric-commit-confirmed'
    def __init__(self, url, token):
        parsed = urlparse(url)
        if parsed.scheme not in ('http','https') or (parsed.scheme=='http' and parsed.hostname not in ('127.0.0.1','localhost','::1')):
            raise ValueError('gateway requires TLS outside loopback')
        self.url, self.token = url.rstrip('/'), token
    def submit(self, payload):
        return self._request(payload,'/records')
    def lookup(self, payload):
        return self._request(payload,'/records/query')
    def _request(self, payload, path):
        request = urllib.request.Request(self.url+path, canonical(payload),
                    {'Content-Type':'application/json','Authorization':'Bearer '+self.token})
        with urllib.request.urlopen(request,timeout=150) as response:
            result = json.load(response)
        if result.get('successful') is not True or result.get('kind') != self.kind or result.get('receiptHash') != payload['receiptHash'] or not result.get('transactionID'):
            raise ValueError('gateway did not confirm matching ledger commitment')
        return result
