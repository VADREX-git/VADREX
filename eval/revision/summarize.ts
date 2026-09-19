import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { outputDir } from './config.js';

const out=outputDir(resolve('.'));
const summary=resolve(out,'summary'); mkdirSync(summary,{recursive:true});
const stats=(values:number[])=>{const mean=values.reduce((a,b)=>a+b,0)/values.length;
  return {n:values.length,mean,sd:Math.sqrt(values.reduce((a,b)=>a+(b-mean)**2,0)/values.length),min:Math.min(...values),max:Math.max(...values)};};
// Match paper-v1's population SD convention; all new summaries use the same denominator n.
const [header,...lines]=readFileSync('eval/reference/paper-v1/raw/handshake_overhead.csv','utf8').trim().split(/\r?\n/);
const keys=header.split(',');
const raw=lines.map(line=>Object.fromEntries(line.split(',').map((value,i)=>[keys[i],value])));
assert.equal(raw.length,30); assert(raw.every(r=>r.status==='ok'));
const handshake=['small','medium','large'].map(label=>{const rows=raw.filter(r=>r.studySizeLabel===label);assert.equal(rows.length,10);
  return {label,MiB:Number(rows[0].actualPixelBytes)/1048576,
    directSeconds:stats(rows.map(r=>Number(r.baselineDirectMs)/1000)),gatewaySeconds:stats(rows.map(r=>Number(r.gatewayHandshakeMs)/1000)),
    extraSeconds:stats(rows.map(r=>Number(r.overheadMs)/1000)),
    directMiBps:stats(rows.map(r=>Number(r.actualPixelBytes)/1048576/(Number(r.baselineDirectMs)/1000))),
    gatewayMiBps:stats(rows.map(r=>Number(r.actualPixelBytes)/1048576/(Number(r.gatewayHandshakeMs)/1000)))};});
writeFileSync(resolve(summary,'handshake.json'),JSON.stringify({source:'eval/reference/paper-v1/raw/handshake_overhead.csv',sdDenominator:'n',rows:handshake},null,2));
const gas=JSON.parse(readFileSync(resolve(out,'gas.json'),'utf8'));
const gasSummary=Object.fromEntries([...new Set<string>(gas.rows.map((r:any)=>r.operation))].map(operation=>{
  const group=gas.rows.filter((r:any)=>r.operation===operation);assert.equal(group.length,10);
  return [operation,{estimate:stats(group.map((r:any)=>r.estimatedGas)),used:stats(group.map((r:any)=>r.gasUsed))}];}));
writeFileSync(resolve(summary,'gas.json'),JSON.stringify(gasSummary,null,2));
const completed=resolve(out,'table1/completed.json');
if(existsSync(completed)) {
  const rows=readFileSync(resolve(out,'table1/rows.jsonl'),'utf8').trim().split('\n').map(s=>JSON.parse(s));
  assert.equal(rows.length,90);assert(rows.every(r=>r.detected));
  const order=['past-log-tamper','log-entry-omission','post-anchor-completion-entry-deletion','tree-size-regression-revert','k-plus-one','skip-seq','no-head-update','receiver-denial','no-timely-anchored-completion-pair'];
  const result=order.map(name=>{const group=rows.filter(r=>r.case===name);assert.equal(group.length,10);
    assert.deepEqual(group.map(r=>r.repeat),[1,2,3,4,5,6,7,8,9,10]);
    return {case:name,correct:group.filter(r=>r.detected).length,computeMs:group.every(r=>r.computeMs===null)?null:stats(group.map(r=>r.computeMs)),
      totalSeconds:stats(group.map(r=>r.totalMs/1000)),replayChecks:group.filter(r=>r.replayAgrees===true).length};});
  writeFileSync(resolve(summary,'timing.json'),JSON.stringify({sdDenominator:'n',rows:result},null,2));
  writeFileSync(resolve(summary,'timing.csv'),'case,correct,repetitions,computeMeanMs,computeSdMs,totalMeanSec,totalSdSec\n'+result.map(r=>[r.case,r.correct,10,r.computeMs?.mean??'',r.computeMs?.sd??'',r.totalSeconds.mean,r.totalSeconds.sd].join(',')).join('\n')+'\n');
  console.log(JSON.stringify(result));
} else console.log('Timing run in progress; only existing handshake and completed gas data summarized.');
console.log(JSON.stringify(handshake));
