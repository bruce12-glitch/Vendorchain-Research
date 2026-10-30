import { mkdirSync, writeFileSync, appendFileSync, readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
const args=process.argv.slice(2);
const option=(name,fallback)=>{const i=args.indexOf('--'+name);return i<0?fallback:args[i+1];};
const url=option('url','http://127.0.0.1:8090');
const file=resolve(option('file',''));
const output=resolve(option('output','research/results/load-'+Date.now()));
const trials=Number(option('trials','50')),warmups=Number(option('warmups','5'));
const levels=option('concurrency','100,250,500,1000,2500,5000,10000').split(',').map(Number);
const reset=option('reset-script',null);
const metadata=option('metadata',null);
const timeoutMs=Number(option('timeout-ms','300000'));
async function drain() {
 const deadline=Date.now()+Number(option('drain-timeout-ms','1200000'));
 while (true) {
  const response=await fetch(url+'/health',{headers:{authorization:'Bearer '+process.env.API_TOKEN},signal:AbortSignal.timeout(5000)});
  if (!response.ok) throw Error('cannot verify server drain');
  const health=await response.json();
  if (health.pending===0) return;
  if (Date.now()>=deadline) throw Error('previous trial has not drained; stop to avoid contaminated trials');
  await new Promise(resolve=>setTimeout(resolve,1000));
 }
}
if (!Number.isInteger(trials)||trials<1||!Number.isInteger(warmups)||warmups<0||levels.some(n=>!Number.isInteger(n)||n<1||n>10000)) throw Error('invalid sweep settings');
mkdirSync(output,{recursive:true});
if (existsSync(join(output,'trials.jsonl'))) throw Error('use a new output directory for each campaign');
if (metadata) writeFileSync(join(output,'network-metadata.json'),readFileSync(metadata));
const temp=mkdtempSync(join(tmpdir(),'vendorchain-load-'));
try {
 for (const concurrency of levels) {
  for (let i=-warmups;i<trials;i++) {
   if (reset) {
    const r=spawnSync(resolve(reset),[],{stdio:'inherit',timeout:300000});
    if (r.status!==0) throw Error('trial reset failed');
   }
   await drain();
   const result=join(output,`requests-c${concurrency}-t${i}.json`);
   const config=join(temp,'trial.json');
   writeFileSync(config,JSON.stringify({url,file,concurrency,result,timeoutMs}));
   const trialStarted=performance.now();
   const child=spawnSync(process.execPath,[fileURLToPath(new URL('./load-trial.mjs',import.meta.url)),config],{stdio:'inherit',timeout:timeoutMs+60000});
   if (child.status!==0) {
    appendFileSync(join(output,'trials.jsonl'),JSON.stringify({concurrency,trial:i,warmup:i<0,offered:concurrency,successful:0,failed:concurrency,trialMeanMs:null,durationSeconds:(performance.now()-trialStarted)/1000,evidence:'trial-crash',reason:String(child.error?.name||child.status)})+'\n');
    throw Error(`trial crashed; failed trial retained (${child.status})`);
   }
   const {summary}=JSON.parse(readFileSync(result));
   const row={...summary,trial:i,warmup:i<0,resetHookUsed:Boolean(reset)};
   appendFileSync(join(output,'trials.jsonl'),JSON.stringify(row)+'\n');
   await drain();
   process.stdout.write(JSON.stringify({concurrency,trial:i,successful:row.successful,failed:row.failed})+'\n');
  }
 }
} finally {rmSync(temp,{recursive:true,force:true});}
