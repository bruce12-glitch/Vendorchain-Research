"""SQLite reference outbox. External ledger and SQL are not one atomic transaction."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from .crypto import canonical

class Conflict(ValueError):
    pass

class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / 'pipeline.sqlite3'
        with self.connection() as con:
            con.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS submissions(
              id TEXT PRIMARY KEY, vendor_id TEXT NOT NULL, document_hash TEXT NOT NULL,
              cipher_hash TEXT NOT NULL, envelope TEXT NOT NULL, context TEXT NOT NULL,
              blob_path TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL,
              lease_until REAL NOT NULL DEFAULT 0, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox(
              id TEXT PRIMARY KEY REFERENCES submissions(id), payload TEXT NOT NULL,
              snapshot INTEGER NOT NULL, status TEXT NOT NULL, tx_id TEXT);
            CREATE TABLE IF NOT EXISTS events(
              seq INTEGER PRIMARY KEY, record_id TEXT NOT NULL, event TEXT NOT NULL,
              prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS immutable_events_update BEFORE UPDATE ON events
              BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_events_delete BEFORE DELETE ON events
              BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_submission BEFORE UPDATE OF
              vendor_id,document_hash,cipher_hash,envelope,context,blob_path ON submissions
              BEGIN SELECT RAISE(ABORT,'immutable document binding'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_payload BEFORE UPDATE OF payload ON outbox
              BEGIN SELECT RAISE(ABORT,'immutable outbox payload'); END;
            ''')

    @contextmanager
    def connection(self, transaction=False):
        con = sqlite3.connect(self.path, timeout=60, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('PRAGMA synchronous=FULL')
        try:
            if transaction:
                con.execute('BEGIN IMMEDIATE')
            yield con
            if transaction:
                con.commit()
        except BaseException:
            if transaction:
                con.rollback()
            raise
        finally:
            con.close()

    @staticmethod
    def event(con, rid, kind, **fields):
        prev = con.execute('SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        prev = prev[0] if prev else '0'*64
        event = canonical({'recordID':rid, 'kind':kind, 'atNs':time.time_ns(), **fields}).decode()
        digest = hashlib.sha256(bytes.fromhex(prev)+event.encode()).hexdigest()
        con.execute('INSERT INTO events(record_id,event,prev_hash,event_hash) VALUES(?,?,?,?)', (rid,event,prev,digest))

    def get(self, rid):
        with self.connection() as con:
            row = con.execute('SELECT * FROM submissions WHERE id=?', (rid,)).fetchone()
            return dict(row) if row else None

    def ingest(self, rid, vendor, document_hash, cipher_hash, envelope, context, path):
        with self.connection(True) as con:
            if con.execute('SELECT 1 FROM submissions WHERE id=?', (rid,)).fetchone():
                raise Conflict('request already exists')
            con.execute('INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                        (rid,vendor,document_hash,cipher_hash,json.dumps(envelope),json.dumps(context),
                         str(path),'INGESTED',1,0,time.time()))
            self.event(con,rid,'INGESTED',documentHash=document_hash,ciphertextHash=cipher_hash)

    def claim(self, rid):
        with self.connection(True) as con:
            count = con.execute("UPDATE submissions SET state='PROCESSING',version=version+1,lease_until=? WHERE id=? AND state='INGESTED'", (time.time()+300,rid)).rowcount
            if count != 1:
                raise Conflict('request is already processing or completed')
            row = con.execute('SELECT * FROM submissions WHERE id=?', (rid,)).fetchone()
            self.event(con,rid,'PROCESSING')
            return dict(row)

    def prepare(self, row, payload):
        with self.connection(True) as con:
            count = con.execute("UPDATE submissions SET state='PREPARED',version=version+1,lease_until=0 WHERE id=? AND version=? AND state='PROCESSING'", (row['id'],row['version'])).rowcount
            if count != 1:
                raise Conflict('stale worker snapshot')
            con.execute('INSERT INTO outbox VALUES(?,?,?,?,NULL)', (row['id'],canonical(payload).decode(),row['version']+1,'PENDING'))
            self.event(con,row['id'],'PREPARED',receiptHash=payload['receiptHash'])

    def pending(self, rid):
        with self.connection() as con:
            row = con.execute('SELECT * FROM outbox WHERE id=?', (rid,)).fetchone()
            return dict(row) if row else None

    def finish(self, rid, snapshot, tx_id, receipt_hash):
        if not tx_id:
            raise ValueError('missing confirmed transaction ID')
        with self.connection(True) as con:
            row = con.execute('SELECT * FROM submissions WHERE id=?', (rid,)).fetchone()
            out = con.execute('SELECT * FROM outbox WHERE id=?', (rid,)).fetchone()
            if row['state'] == 'COMMITTED' and out['tx_id'] == tx_id:
                return  # Another recovery caller already completed this exact write.
            if row['state'] != 'PREPARED' or row['version'] != snapshot:
                raise Conflict('stale commit snapshot')
            if json.loads(out['payload'])['receiptHash'] != receipt_hash:
                raise Conflict('receipt changed')
            con.execute("UPDATE outbox SET status='CONFIRMED',tx_id=? WHERE id=?", (tx_id,rid))
            con.execute("UPDATE submissions SET state='COMMITTED',version=version+1 WHERE id=?", (rid,))
            self.event(con,rid,'COMMITTED',transactionID=tx_id,receiptHash=receipt_hash)

    def fail_processing(self, rid, version):
        with self.connection(True) as con:
            if con.execute("UPDATE submissions SET state='FAILED',version=version+1,lease_until=0 WHERE id=? AND version=? AND state='PROCESSING'", (rid,version)).rowcount:
                self.event(con,rid,'FAILED')

    def recover_expired(self):
        with self.connection(True) as con:
            rows = con.execute("SELECT id FROM submissions WHERE state='PROCESSING' AND lease_until<?", (time.time(),)).fetchall()
            for row in rows:
                con.execute("UPDATE submissions SET state='INGESTED',version=version+1,lease_until=0 WHERE id=?", (row['id'],))
                self.event(con,row['id'],'LEASE_RECOVERED')
            return len(rows)

    def verify_audit(self):
        prev = '0'*64
        with self.connection() as con:
            for row in con.execute('SELECT * FROM events ORDER BY seq'):
                expected = hashlib.sha256(bytes.fromhex(prev)+row['event'].encode()).hexdigest()
                if row['prev_hash'] != prev or row['event_hash'] != expected:
                    return False
                prev = expected
        return True
