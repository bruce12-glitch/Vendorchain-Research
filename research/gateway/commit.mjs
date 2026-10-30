import { createHash } from 'node:crypto';

export async function commitRecord(contract, payload, {queryOnly=false}={}) {
  const hash = createHash('sha256').update(Buffer.from(payload.receipt, 'base64')).digest('hex');
  if (hash !== payload.receiptHash) throw new Error('receipt hash mismatch');
  // Read first so a lost acknowledgement can be recovered without a second write.
  const read = async () => JSON.parse(Buffer.from(await contract.evaluateTransaction('QueryCompliance', payload.recordID)).toString());
  let existing;
  try { existing = await read(); } catch { /* Missing/unavailable: submit still fails closed. */ }
  if (existing) {
    if (existing.receiptHash !== hash || !existing.transactionID) throw new Error('conflicting immutable record');
    return { successful: true, kind: 'fabric-commit-confirmed', transactionID: existing.transactionID, receiptHash: hash, recovered: true };
  }
  if (queryOnly) throw new Error('no matching committed record');
  const tx = await contract.submitAsync('RecordHardened', { arguments: [payload.recordID, payload.receipt, payload.signature] });
  const status = await tx.getStatus();
  if (!status.successful || status.code !== 0) throw new Error(`invalid Fabric commit: ${status.code}`);
  const record = await read();
  if (record.receiptHash !== hash || record.transactionID !== status.transactionId) throw new Error('committed ledger readback mismatch');
  return { successful: true, kind: 'fabric-commit-confirmed', transactionID: status.transactionId, receiptHash: hash, blockNumber: String(status.blockNumber), recovered: false };
}
