// Each invocation is one independent client process, with fresh IDs and sockets.
import { readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
function uniquePng(data, nonce) {
 if (!data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])) || data.subarray(-8,-4).toString()!=='IEND') throw Error('unique-png mode requires a complete PNG');
 const text=Buffer.from('SubmissionNonce\0'+nonce);
 const chunk=Buffer.alloc(12+text.length);chunk.writeUInt32BE(text.length,0);chunk.write('tEXt',4);text.copy(chunk,8);
 let crc=0xffffffff;
 for (const value of chunk.subarray(4,-4)) {crc^=value;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}
 chunk.writeUInt32BE((crc^0xffffffff)>>>0,chunk.length-4);
 return Buffer.concat([data.subarray(0,-12),chunk,data.subarray(-12)]);
}
export function committedResponse(response, result, recordID) {
 return response.ok && result.recordID===recordID && result.ack?.successful===true
   && typeof result.ack?.transactionID==='string' && result.ack.transactionID.length>0
   && ['fabric-commit-confirmed','local-non-consensus'].includes(result.evidence)
   && result.ack.kind===result.evidence;
}

export function summarizeRequests(requests, {concurrency,durationSeconds,maxInFlight}) {
 const successes=requests.filter(r=>r.success);
 const sorted=successes.map(r=>r.latencyMs).sort((a,b)=>a-b);
 const percentile=q=>{
  if (!sorted.length) return null;
  const index=(sorted.length-1)*q, low=Math.floor(index);
  return sorted[low]+(sorted[Math.ceil(index)]-sorted[low])*(index-low);
 };
 return {concurrency,offered:requests.length,successful:successes.length,failed:requests.length-successes.length,
  policyAllowed:successes.filter(r=>r.decision==='PASS').length,policyDenied:successes.filter(r=>r.decision==='FAIL').length,
  policyUnknown:successes.filter(r=>!['PASS','FAIL'].includes(r.decision)).length,
  durationSeconds,trialMeanMs:successes.length?successes.reduce((s,r)=>s+r.latencyMs,0)/successes.length:null,
  p50Ms:percentile(.5),p95Ms:percentile(.95),p99Ms:percentile(.99),maxInFlight,
  latencyPopulation:'confirmed commits only; rejected and unconfirmed requests retained individually',quantileMethod:'R7',
  concurrencyScope:'simultaneous client HTTP attempts; not measured simultaneous server execution',
  evidence:successes.length && successes.every(r=>r.evidence==='fabric-commit-confirmed')?'fabric-commit-confirmed':'local-or-unconfirmed',
  clientPid:process.pid,independence:'fresh-client-process; shared-server-and-ledger-unless-reset-hook-supplied'};
}

export async function runTrial(config) {
const data=readFileSync(config.file);
const token=process.env.API_TOKEN;
if (!token) throw new Error('API_TOKEN required');
const start=performance.now();let inFlight=0,maxInFlight=0;
const requests=await Promise.all(Array.from({length:config.concurrency},async(_,i)=>{
  const rid=randomUUID().replaceAll('-','');
  const submittedAt=performance.now();inFlight++;maxInFlight=Math.max(maxInFlight,inFlight);
  let status=0;
  try {
    const body=config.uniquePng?uniquePng(data,rid):data;
    const response=await fetch(config.url+'/v1/uploads', { method:'POST',body,
      headers:{'authorization':'Bearer '+token,'content-type':'application/octet-stream',
               'x-vendor-id':'load-'+rid,'x-request-id':rid}, signal:AbortSignal.timeout(config.timeoutMs||300000) });
    status=response.status;
    const result=await response.json();
    const committed=committedResponse(response,result,rid);
    return {recordID:rid,success:committed,status:response.status,latencyMs:performance.now()-submittedAt,
            decision:result.decision||null,
            submittedBytes:body.length,
            schedulerDelayMs:submittedAt-start,evidence:result.evidence||null,
            serverLatencyMs:result.server_ingestion_to_commit_ms??null,stages:result.stages||null,
            error:typeof result.error==='string'?result.error.slice(0,256):null,
            transactionID:committed?result.ack.transactionID:null};
  } catch(error) {return {recordID:rid,success:false,status,latencyMs:performance.now()-submittedAt,error:error.name};}
  finally {inFlight--;}
}));
const durationSeconds=(performance.now()-start)/1000;
const summary=summarizeRequests(requests,{concurrency:config.concurrency,durationSeconds,maxInFlight});
writeFileSync(config.result,JSON.stringify({summary,requests})+'\n');
return {summary,requests};
}

if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 await runTrial(JSON.parse(readFileSync(process.argv[2])));
}
