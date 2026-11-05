"""PostgreSQL implementation of the same versioned ledger-first outbox protocol.

Run migrate() with a migration role once. Runtime credentials need ordinary data
access only, not ownership or DDL. Serialization failures are retained for retry.
"""
from contextlib import contextmanager
from pathlib import Path
from .store import Store, Conflict


class Row(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key,int) else super().__getitem__(key)


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.rowcount = cursor.rowcount

    def fetchone(self):
        row = self.cursor.fetchone()
        return None if row is None else Row(row)

    def fetchall(self):
        return [Row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


class Connection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, params=()):
        # SQL is static, internal Store SQL. No user SQL is accepted here.
        return Cursor(self.connection.execute(sql.replace('?', '%s'), params))


class PostgresStore(Store):
    def __init__(self, root, dsn, *, retention_seconds=86400):
        if retention_seconds <= 0:
            raise ValueError('replay retention must be positive')
        self.root, self.dsn, self.retention_seconds = Path(root), dsn, retention_seconds
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def migrate(self):
        import psycopg
        with psycopg.connect(self.dsn) as con:
            con.execute((Path(__file__).resolve().parents[1]/'sql/schema.sql').read_text())

    @contextmanager
    def connection(self, transaction=False):
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(self.dsn, row_factory=dict_row, autocommit=True) as con:
            if transaction:
                with con.transaction():
                    # Serializes event-chain append; digest uniqueness is also
                    # protected by its primary key inside this transaction.
                    con.execute('SELECT pg_advisory_xact_lock(738194650)')
                    yield Connection(con)
            else:
                yield Connection(con)
