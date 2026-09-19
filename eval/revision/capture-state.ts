import assert from 'node:assert/strict';
import { readFileSync,writeFileSync } from 'node:fs';
import { resolve,join } from 'node:path';
import { AnchorReader } from '../../packages/verifier-cli/src/anchor.js';
import { outputDir, ports } from './config.js';
const out=outputDir(resolve('.'));
const done=JSON.parse(readFileSync(join(out,'table1/completed.json'),'utf8'));
assert.equal(done.rows,90);
const deployed=JSON.parse(readFileSync(join(out,'workspace/data/deployments.local.json'),'utf8'));
const counter={apiCalls:0,rpcCalls:0,apiRequestBytes:0,apiResponseBytes:0};
const anchors:Record<string,unknown>={};
for(const org of ['A','B']){
  const reader=new AnchorReader(`http://127.0.0.1:${ports.rpc}`,deployed.anchors[org].address,counter);
  const list=await reader.anchors();
  assert.equal(list.length,done.finalAnchors[org.toLowerCase()]);
  anchors[org]=list;
}
writeFileSync(join(out,'table1/anchors-final.json'),JSON.stringify({description:'Read-only RPC snapshot after all timed trials; includes historical treeSize for each before/after batch.',anchors},null,2));
console.log('Recorded historical anchor roots, tree sizes and times after timed measurements.');
