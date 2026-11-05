import { createHash } from 'node:crypto';

export async function commitRecord(contract, payload, {queryOnly=false}={}) {
  const hash = createHash('sha256').update(Buffer.from(payload.receipt, 'base64')).digest('hex');
  if (hash !== payload.receiptHash) throw new Error('receipt hash mismatch');
  const version = JSON.parse(Buffer.from(payload.receipt, 'base64').toString()).version;
  if (!['vendorchain.receipt.v1','vendorchain.receipt.v2'].includes(version)) throw new Error('unsupported receipt version');
  const hardened = version === 'vendorchain.receipt.v2';
  // Read first so a lost acknowledgement can be recovered without a second write.
  const read = async () => JSON.parse(Buffer.from(await contract.evaluateTransaction(hardened ? 'QueryEvidence' : 'QueryCompliance', payload.recordID)).toString());
  let existing;
  try { existing = await read(); } catch (error) {
    const details = [error.message, ...(Array.isArray(error.details) ? error.details.map(x=>x.message) : [])].join(' ');
    if (!/\b(?:compliance )?record not found\b/.test(details)) throw error;
  }
  if (existing) {
    if (existing.receiptHash !== hash || !existing.transactionID) throw new Error('conflicting immutable record');
    return { successful: true, kind: 'fabric-commit-confirmed', transactionID: existing.transactionID, receiptHash: hash, recovered: true };
  }
  if (queryOnly) { const error = new Error('no matching committed record'); error.code = 'NOT_FOUND'; throw error; }
  if (hardened && !payload.snapshotSignature) throw new Error('snapshot signature required');
  const tx = await contract.submitAsync(hardened ? 'RecordEvidence' : 'RecordHardened', {
    arguments: [payload.recordID, payload.receipt, payload.signature, ...(hardened ? [payload.snapshotSignature] : [])] });
  const status = await tx.getStatus();
  if (!status.successful || status.code !== 0) throw new Error(`invalid Fabric commit: ${status.code}`);
  const record = await read();
  if (record.receiptHash !== hash || record.transactionID !== status.transactionId) throw new Error('committed ledger readback mismatch');
  return { successful: true, kind: 'fabric-commit-confirmed', transactionID: status.transactionId, receiptHash: hash, blockNumber: String(status.blockNumber), recovered: false };
}
