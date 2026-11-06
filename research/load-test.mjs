import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { committedResponse, summarizeRequests, runTrial } from './load-trial.mjs';

test('commit acknowledgement must match response evidence and submission ID', () => {
 const result={recordID:'r',evidence:'fabric-commit-confirmed',ack:{successful:true,transactionID:'tx',kind:'fabric-commit-confirmed'}};
 assert.equal(committedResponse({ok:true},result,'r'),true);
 assert.equal(committedResponse({ok:true},result,'other'),false);
 assert.equal(committedResponse({ok:true},{...result,ack:{...result.ack,kind:'local-non-consensus'}},'r'),false);
 assert.equal(committedResponse({ok:false},result,'r'),false);
});

test('FAIL and unknown committed decisions remain separate from workload PASS', () => {
 const requests=['PASS','FAIL',null].map((decision,i)=>({success:true,decision,latencyMs:i+1,evidence:'fabric-commit-confirmed'}));
 requests.push({success:false,status:503,latencyMs:10000});
 const result=summarizeRequests(requests,{concurrency:4,durationSeconds:1,maxInFlight:4});
 assert.equal(result.successful,3);assert.equal(result.failed,1);
 assert.equal(result.policyAllowed,1);assert.equal(result.policyDenied,1);assert.equal(result.policyUnknown,1);
 assert.equal(result.trialMeanMs,2);assert.equal(result.p50Ms,2);assert.equal(result.p95Ms,2.9);
});

test('all failed bursts retain null commit latency', () => {
 const result=summarizeRequests([{success:false,latencyMs:10}],{concurrency:1,durationSeconds:1,maxInFlight:1});
 assert.equal(result.failed,1);assert.equal(result.trialMeanMs,null);assert.equal(result.p99Ms,null);
 assert.equal(result.evidence,'local-or-unconfirmed');
});

test('duplicate levels and invalid timeouts fail before overwriting evidence', () => {
 for (const args of [['--concurrency','3,3'],['--timeout-ms','0'],['--drain-timeout-ms','NaN']]) {
  const result=spawnSync(process.execPath,['research/load.mjs',...args],{encoding:'utf8'});
  assert.notEqual(result.status,0);assert.match(result.stderr,/invalid sweep settings/);
 }
});

test('HTTP rejection and malformed JSON keep server status and failure reason', async () => {
 const directory=mkdtempSync(join(tmpdir(),'vendorchain-load-test-'));
 const original=process.env.API_TOKEN;process.env.API_TOKEN='test-token';
 let count=0;
 const server=createServer((request,response)=>{
  request.resume();response.writeHead(503,{'Content-Type':'application/json'});
  response.end(count++===0?'{"error":"upload memory budget reached"}':'broken-json');
 });
 try {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  writeFileSync(join(directory,'input'),Buffer.from('inert'));
  const result=await runTrial({url:'http://127.0.0.1:'+server.address().port,file:join(directory,'input'),result:join(directory,'result.json'),concurrency:2,timeoutMs:1000});
  assert.equal(result.summary.failed,2);assert.ok(result.requests.every(row=>row.status===503));
  assert.deepEqual(new Set(result.requests.map(row=>row.error)),new Set(['upload memory budget reached','SyntaxError']));
 } finally {
  await new Promise(resolve=>server.close(resolve));rmSync(directory,{recursive:true,force:true});
  if (original===undefined) delete process.env.API_TOKEN;else process.env.API_TOKEN=original;
 }
});
