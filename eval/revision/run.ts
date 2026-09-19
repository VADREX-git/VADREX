import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { Rfc6962LogTree } from '@vadrex/merkle';
import { AnchorClient } from '../../packages/gateway/src/anchorClient.js';
import { readWalletPrivateKey } from '../../packages/gateway/src/config.js';
import { verifyNonTransfer } from '../../packages/verifier-cli/src/verifier.js';
import { runS1OnchainTamper } from '../src/measure-attack.js';
import { addCheckpointAndAnchor, chainAnchors, pinnedAnchors, releasePeerHold, waitForGateway, verifierTlsOptions } from '../src/live.js';
import { createConsent, revokeConsent, anchorNow } from '../src/live.js';
import { writeSyntheticDicom, stowDicomToOrthancA } from '../src/dicom.js';
import { ports, runId } from './config.js';

const root = resolve('.');
const suffix = `revision-${runId}`;
assert(root.endsWith(`${suffix}\\workspace`) || root.endsWith(`${suffix}/workspace`), 'run only in the isolated workspace of this REVISION_RUN');
Object.assign(process.env, { GATEWAY_A_URL:`https://localhost:${ports.gatewayA}`,GATEWAY_B_URL:`https://localhost:${ports.gatewayB}`,
  ORTHANC_A_URL:`https://localhost:${ports.orthancA}`,ORTHANC_B_URL:`https://localhost:${ports.orthancB}`,
  CHAIN_RPC_URL_HOST:`http://127.0.0.1:${ports.rpc}`,
  AUDIT_DB_PATH:join(root,'data/inst-a/audit.db'),VADREX_ROOT:root,ENABLE_DEV_ENDPOINTS:'true',
  ANCHOR_INTERVAL_SEC:'30',ANCHOR_MAX_INTERVAL_SEC:'30' });
const label = process.env.REVISION_LABEL ?? 'table1';
const out = resolve('..',label); mkdirSync(out,{recursive:true});
const rawPath = join(out,'rows.jsonl');
if(existsSync(rawPath)) throw new Error('output already exists; choose a new REVISION_LABEL');
const repeats = Number(process.env.REVISION_REPEATS ?? 10);
const study = `1.3.6.1.4.1.5962.8.917.${Date.now()%1000000000}`;
const studyFile = join(out,'synthetic.dcm');
const anchors = pinnedAnchors();
const rpc = process.env.CHAIN_RPC_URL_HOST!;
const countAnchors = async () => ({a:(await chainAnchors(anchors.a)).length,b:(await chainAnchors(anchors.b)).length});

// Apply the same small evaluation-only patch as prepare.ts to a pre-existing snapshot.
const concealmentPath=join(root,'scripts/demo-concealment.ts');
let concealment=readFileSync(concealmentPath,'utf8');
if(!concealment.includes('lastRebuildMs')) {
  concealment='let lastRebuildMs = 0;\n'+concealment;
  concealment=concealment.replace('const tree = new Rfc6962LogTree();','const localStarted = performance.now();\n  const tree = new Rfc6962LogTree();')
    .replace('return { root: tree.currentRoot(), leafCount: rows.length };','const result = { root: tree.currentRoot(), leafCount: rows.length };\n  lastRebuildMs = performance.now() - localStarted;\n  return result;')
    .replace('if (tampered.leafCount >= anchor.treeSize || tampered.root === anchor.rootHash) {','const comparisonStarted = performance.now();\n    if (tampered.leafCount >= anchor.treeSize || tampered.root === anchor.rootHash) {')
    .replace('console.log(`  detection: only','appendFileSync(process.env.REVISION_TIMING_FILE!,JSON.stringify({kind:"verification",case:"post-anchor-completion-entry-deletion",computeMs:lastRebuildMs+performance.now()-comparisonStarted,ok:true,treeSize:anchor.treeSize})+"\\n");\n    console.log(`  detection: only');
  writeFileSync(concealmentPath,concealment);
}

function docker(args:string[],env:NodeJS.ProcessEnv=process.env) {
  const result=spawnSync('docker',['compose',...args],{cwd:root,encoding:'utf8',env,maxBuffer:8*1024*1024});
  appendFileSync(join(out,'environment.log'),`${result.stdout}\n${result.stderr}\n`);
  if(result.status!==0) throw new Error(`isolated docker ${args.join(' ')} failed: ${result.stderr}`);
}
async function receiptMode(late:boolean) {
  process.env.RECEIPT_TIMEOUT_SEC=late?'5':'30';
  process.env.SIMULATED_RECEIPT_DELAY_MS=late?'10000':'0';
  docker(['up','-d','--no-build','--no-deps','gateway-a','gateway-b']);
  await waitForGateway('A'); await waitForGateway('B');
}
function emit(row:Record<string,unknown>) {
  appendFileSync(rawPath,JSON.stringify(row)+'\n');
  console.log(JSON.stringify({repeat:row.repeat,case:row.case,computeMs:row.computeMs,totalMs:row.totalMs,detected:row.detected}));
}
async function anchoredLeaves() {
  const latest=(await chainAnchors(anchors.a)).at(-1)!;
  const db=new Database(process.env.AUDIT_DB_PATH!,{readonly:true,fileMustExist:true});
  try { return {anchor:latest, leaves:db.prepare('SELECT leafIndex,canonicalBytes FROM audit_entries WHERE leafIndex < ? ORDER BY leafIndex').all(latest.treeSize) as {leafIndex:number;canonicalBytes:Buffer}[]}; }
  finally {db.close();}
}
function tree(leaves:{canonicalBytes:Buffer}[]) {const t=new Rfc6962LogTree(); for(const leaf of leaves)t.appendLeaf(new Uint8Array(leaf.canonicalBytes)); return t;}
async function runScript(repeat:number, caseName:string,script:string) {
  await releasePeerHold().catch(()=>undefined);
  const before=await countAnchors();
  const timingPath=join(out,`${repeat}-${caseName}-timing.jsonl`);
  const start=performance.now();
  const child=spawnSync(process.execPath,['--import','tsx',`scripts/${script}.ts`],{cwd:root,env:{...process.env,
    SCENARIO_STUDY_UID:study,REVISION_CASE:caseName,REVISION_TIMING_FILE:timingPath},encoding:'utf8',maxBuffer:16*1024*1024,timeout:600000});
  const totalMs=performance.now()-start;
  writeFileSync(join(out,`${repeat}-${caseName}.log`),`${child.stdout}\n${child.stderr}`);
  assert.equal(child.status,0,`${caseName} failed: ${child.stderr?.slice(-1800)} ${child.error??''}`);
  const events=readFileSync(timingPath,'utf8').trim().split('\n').map(s=>JSON.parse(s));
  const measured=events.find(e=>e.kind==='verification'); assert(measured,`no verification timing for ${caseName}`);
  const caseTotal=events.find(e=>e.kind==='case-total');
  const expectedSteps:Record<string,string>={'k-plus-one':'provider head','skip-seq':'provider head','no-head-update':'provider cross-check'};
  if(caseName in expectedSteps) assert(measured.lines.some((line:string)=>line.includes(expectedSteps[caseName])));
  const after=await countAnchors();
  emit({repeat,case:caseName,detected:true,computeMs:measured.computeMs,invocationMs:measured.invocationMs??null,
    totalMs:caseTotal?.totalMs??totalMs,totalBoundary:caseTotal?'case preparation through final verdict':'script process start through successful script exit',
    beforeAnchors:before,afterAnchors:after,treeSize:measured.treeSize??null,replayAgrees:measured.replayAgrees??null,
    verdict:measured.lines??['anchored root mismatch'],timingFile:timingPath});
}

await waitForGateway('A');await waitForGateway('B');
writeSyntheticDicom({studyInstanceUid:study,seriesInstanceUid:`${study}.1`,sopInstanceUid:`${study}.1.1`,targetPixelBytes:262144,outputPath:studyFile});
await stowDicomToOrthancA(studyFile);
process.env.SCENARIO_STUDY_UID=study;
const normal=await createConsent(study);
const revoked=await revokeConsent(normal.consentId);
await anchorNow('A'); await addCheckpointAndAnchor('B',`${label}-positive-control`);
const control=await verifyNonTransfer({consentId:normal.consentId,secretC:normal.secretC,revocationSeq:revoked.seq,
  revocationEntryHash:revoked.entryHash,providerGateway:process.env.GATEWAY_A_URL!,receiverGateway:process.env.GATEWAY_B_URL!,
  rpcUrl:rpc,providerAnchorAddress:anchors.a,receiverAnchorAddress:anchors.b,graceSeconds:0,tls:verifierTlsOptions()});
writeFileSync(join(out,'positive-control.json'),JSON.stringify(control,null,2)); assert.equal(control.ok,true,'honest revocation control');
writeFileSync(join(out,'manifest.json'),JSON.stringify({label,repeats,start:new Date().toISOString(),node:process.version,
  initialAnchors:await countAnchors(),statePolicy:'isolated cumulative history; no reset between repeats',studyPixelBytes:262144,
  anchorIntervalSec:30,receiptTimeoutSec:30,lateReceipt:{timeoutSec:5,delayMs:10000},graceSecInAttack:0,
  computeDefinition:'active verifier elapsed segments excluding GatewayClient.tryGet and AnchorReader RPC methods (including TLS file reads and response-envelope decode); canonical entry parse, hash, proof, signature, log reconstruction and executed verdict logic included',
  buildExcluded:true,originalDataset:'paper-v1',purpose:'separate supplementary timing run'},null,2));
for(let repeat=1;repeat<=repeats;repeat++) {
  await addCheckpointAndAnchor('A',`${label}-${repeat}`);
  let start=performance.now();
  let snapshot=await anchoredLeaves();
  const tamper=await runS1OnchainTamper(snapshot.leaves,Math.floor(snapshot.leaves.length/2));
  assert(tamper.detected);emit({repeat,case:'past-log-tamper',detected:true,computeMs:tamper.verifyMs,totalMs:performance.now()-start,treeSize:snapshot.anchor.treeSize});
  start=performance.now(); snapshot=await anchoredLeaves();
  assert.equal(tree(snapshot.leaves).currentRoot(),snapshot.anchor.rootHash,'honest root control');
  const omitted=snapshot.leaves.filter((_,index)=>index!==Math.floor(snapshot.leaves.length/2));
  const localStart=performance.now();const changed=tree(omitted);
  const detected=omitted.length<snapshot.anchor.treeSize&&changed.currentRoot()!==snapshot.anchor.rootHash;
  const computeMs=performance.now()-localStart;assert(detected);
  emit({repeat,case:'log-entry-omission',detected,computeMs,totalMs:performance.now()-start,treeSize:snapshot.anchor.treeSize});
  start=performance.now();await addCheckpointAndAnchor('A',`${label}-revert-${repeat}`);
  const latest=(await chainAnchors(anchors.a)).at(-1)!;
  const client=new AnchorClient(rpc,anchors.a,readWalletPrivateKey(join(root,'scripts/out/inst-a/wallet.key')));
  let rejected=false;const callStart=performance.now();
  try{await client.registerAnchor(latest.rootHash,latest.treeSize,latest.mapRoot);}catch(error){rejected=String(error).includes('treeSize must increase');}
  assert(rejected,'expected contract rejection, not transport failure');
  emit({repeat,case:'tree-size-regression-revert',detected:true,computeMs:null,invocationMs:performance.now()-callStart,totalMs:performance.now()-start});
  for(const name of ['k-plus-one','skip-seq','no-head-update']) await runScript(repeat,name,'e2e-violation');
  await runScript(repeat,'receiver-denial','e2e-dispute');
  await runScript(repeat,'post-anchor-completion-entry-deletion','demo-concealment');
  await receiptMode(true);
  try{await runScript(repeat,'no-timely-anchored-completion-pair','e2e-receiptless-claim');}
  finally{await receiptMode(false);await releasePeerHold().catch(()=>undefined);}
}
const rows=readFileSync(rawPath,'utf8').trim().split('\n').map(s=>JSON.parse(s));
assert.equal(rows.length,repeats*9);assert(rows.every(r=>r.detected));
writeFileSync(join(out,'completed.json'),JSON.stringify({completed:new Date().toISOString(),rows:rows.length,allExpected:true,finalAnchors:await countAnchors()},null,2));
console.log(`COMPLETE ${label}: ${rows.length} rows`);
