import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { commitRecord } from './commit.mjs';
const raw = Buffer.from('{"recordID":"r1"}');
const payload = { recordID:'r1', receipt:raw.toString('base64'), receiptHash:createHash('sha256').update(raw).digest('hex'), signature:'fixture' };
function fake({ valid=true, mismatch=false, existing=false, outage=false }={}) {
  let committed=existing, submissions=0;
  return {
    get submissions() { return submissions; },
    evaluateTransaction: async () => { if (!committed || outage) throw Error('unavailable'); return Buffer.from(JSON.stringify({receiptHash:mismatch?'wrong':payload.receiptHash,transactionID:'tx1'})); },
    submitAsync: async () => { submissions++; return { getResult:()=>raw, getStatus:async()=> { committed=true; return {successful:valid,code:valid?0:11,transactionId:'tx1',blockNumber:4n}; } }; }
  };
}
test('waits for VALID commit and matching readback',async()=>{const c=fake(); const r=await commitRecord(c,payload);assert.equal(r.transactionID,'tx1');assert.equal(c.submissions,1);});
test('endorsement output cannot substitute for commit',async()=>assert.rejects(commitRecord(fake({valid:false}),payload)));
test('readback mismatch is failure',async()=>assert.rejects(commitRecord(fake({mismatch:true}),payload)));
test('lost acknowledgement reconciles without duplicate submission',async()=>{const c=fake({existing:true});assert.equal((await commitRecord(c,payload)).recovered,true);assert.equal(c.submissions,0);});
test('conflicting replay cannot be accepted',async()=>assert.rejects(commitRecord(fake({existing:true,mismatch:true}),payload)));
test('readback outage cannot be accepted',async()=>assert.rejects(commitRecord(fake({outage:true}),payload)));
test('receipt digest is validated before submission',async()=>{const c=fake();await assert.rejects(commitRecord(c,{...payload,receiptHash:'x'}));assert.equal(c.submissions,0);});

test('historical query confirms existing record without writing',async()=>{const c=fake({existing:true});assert.equal((await commitRecord(c,payload,{queryOnly:true})).recovered,true);assert.equal(c.submissions,0);});
test('historical query cannot create a missing record',async()=>{const c=fake();await assert.rejects(commitRecord(c,payload,{queryOnly:true}));assert.equal(c.submissions,0);});
