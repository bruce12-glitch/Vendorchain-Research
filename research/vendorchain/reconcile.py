"""Compare every outbox record with the ledger and recover lost acknowledgements."""
import json


def reconcile(pipeline, *, repair=False):
    rows = []
    for entry in pipeline.store.outbox_entries():
        row = {'recordID':entry['id'],'sqlStatus':entry['status'],'repaired':False}
        try:
            payload = json.loads(entry['payload'])
            ack = pipeline.ledger.lookup(payload)
            submission = pipeline.store.get(entry['id'])
            if entry['status'] == 'CONFIRMED':
                if not submission or submission['state'] != 'COMMITTED' or not ack or ack.get('receiptHash') != payload['receiptHash'] or ack.get('transactionID') != entry['tx_id']:
                    row['status'] = 'DIVERGENCE'
                else:
                    row['status'] = 'CONSISTENT'
            elif ack:
                row['status'] = 'LEDGER_COMMITTED_SQL_PENDING'
                if repair:
                    pipeline.deliver(entry['id'])
                    row.update(status='CONSISTENT', repaired=True)
            else:
                row['status'] = 'NOT_COMMITTED'
                if repair:
                    pipeline.deliver(entry['id'])
                    row.update(status='CONSISTENT', repaired=True)
        except Exception as exc:
            # Keep operational evidence without leaking DSNs/tokens or payloads.
            row.update(status='CHECK_FAILED', error=type(exc).__name__)
        rows.append(row)
    return {'kind':'ledger-sql-reconciliation','records':rows,
            'divergences':sum(r['status'] not in ('CONSISTENT','NOT_COMMITTED') for r in rows),
            'repaired':sum(r['repaired'] for r in rows)}
