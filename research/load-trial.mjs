// Each invocation is one independent client process, with fresh IDs and sockets.
import { readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
const config=JSON.parse(readFileSync(process.argv[2]));
const data=readFileSync(config.file);
const token=process.env.API_TOKEN;
if (!token) throw new Error('API_TOKEN required');
const start=performance.now();let inFlight=0,maxInFlight=0;
const requests=await Promise.all(Array.from({length:config.concurrency},async(_,i)=>{
  const rid=randomUUID().replaceAll('-','');
  const submittedAt=performance.now();inFlight++;maxInFlight=Math.max(maxInFlight,inFlight);
  try {
    const response=await fetch(config.url+'/v1/uploads', { method:'POST',body:data,
      headers:{'authorization':'Bearer '+token,'content-type':'application/octet-stream',
               'x-vendor-id':'load-'+rid,'x-request-id':rid}, signal:AbortSignal.timeout(config.timeoutMs||300000) });
    const result=await response.json();
    const committed=response.ok && result.ack?.successful===true && Boolean(result.ack?.transactionID);
    return {recordID:rid,success:committed,status:response.status,latencyMs:performance.now()-submittedAt,
            schedulerDelayMs:submittedAt-start,evidence:result.evidence||null,
            serverLatencyMs:result.server_ingestion_to_commit_ms||null,stages:result.stages||null,
            transactionID:committed?result.ack.transactionID:null};
  } catch(error) {return {recordID:rid,success:false,status:0,latencyMs:performance.now()-submittedAt,error:error.name};}
  finally {inFlight--;}
}));
const durationSeconds=(performance.now()-start)/1000;
const successes=requests.filter(r=>r.success);
const sorted=successes.map(r=>r.latencyMs).sort((a,b)=>a-b);
const percentile=q=>sorted.length?sorted[Math.min(sorted.length-1,Math.ceil(q*sorted.length)-1)]:null;
const summary={concurrency:config.concurrency,offered:requests.length,successful:successes.length,failed:requests.length-successes.length,
 durationSeconds,trialMeanMs:successes.length?successes.reduce((s,r)=>s+r.latencyMs,0)/successes.length:null,
 p50Ms:percentile(.5),p95Ms:percentile(.95),p99Ms:percentile(.99),maxInFlight,
 evidence:successes.length && successes.every(r=>r.evidence==='fabric-commit-confirmed')?'fabric-commit-confirmed':'local-or-unconfirmed',
 clientPid:process.pid,independence:'fresh-client-process; shared-server-and-ledger-unless-reset-hook-supplied'};
writeFileSync(config.result,JSON.stringify({summary,requests})+'\n');
