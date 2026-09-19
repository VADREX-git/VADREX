import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync, symlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { describe, images, outputDir, ports, project, workspaceDir } from './config.js';

const source = resolve('.');
const output = outputDir(source);
const target = workspaceDir(source);
if (existsSync(target)) throw new Error('isolated workspace already exists');
mkdirSync(target, {recursive:true});
const files = execFileSync('git', ['ls-files','-z'], {encoding:'utf8'}).split('\0').filter(Boolean);
const hashes: Record<string,string> = {};
for (const file of files) {
  // .dockerignore comes along: without it the node_modules junctions below enter the build
  // context and the image build fails on COPY.
  if (!/^(packages\/|scripts\/|contracts\/|config\/|docker\/|eval\/src\/|package|tsconfig|docker-compose|\.nvmrc|\.dockerignore)/.test(file)) continue;
  const from = join(source,file), to = join(target,file);
  mkdirSync(resolve(to,'..'),{recursive:true}); cpSync(from,to);
  hashes[file] = createHash('sha256').update(readFileSync(from)).digest('hex');
}
for (const directory of ['scripts/out','contracts/artifacts', 'packages/shared/dist','packages/merkle/dist','packages/gateway/dist','packages/verifier-cli/dist','eval/revision']) {
  if (existsSync(join(source,directory))) cpSync(join(source,directory),join(target,directory),{recursive:true});
}
symlinkSync(join(source,'node_modules'),join(target,'node_modules'),'junction');
for (const directory of ['contracts','packages/shared','packages/merkle','packages/gateway','packages/verifier-cli']) {
  if (existsSync(join(source,directory,'node_modules'))) symlinkSync(join(source,directory,'node_modules'),join(target,directory,'node_modules'),'junction');
}
mkdirSync(join(target,'data'),{recursive:true});
let compose = readFileSync(join(target,'docker-compose.yml'),'utf8')
  .replace('name: vadrex',`name: ${project}`)
  .replace('image: vadrex-gateway:local',`image: ${images.gateway}`)
  .replace('image: vadrex-chain:local',`image: ${images.chain}`);
for (const [oldPort,newPort] of [[8545,ports.rpc],[8042,ports.orthancA],[8043,ports.orthancB],[7001,ports.gatewayA],[7002,ports.gatewayB]]) {
  compose = compose.replace(`127.0.0.1:${oldPort}:`,`127.0.0.1:${newPort}:`);
}
writeFileSync(join(target,'docker-compose.yml'),compose);
const hardhatConfig = join(target,'contracts','hardhat.config.ts');
writeFileSync(hardhatConfig,readFileSync(hardhatConfig,'utf8').replace('127.0.0.1:8545',`127.0.0.1:${ports.rpc}`));
cpSync(join(source,'eval/revision/gas.ts'),join(target,'contracts/scripts/revision-gas.ts'));
for (const file of ['e2e-violation.ts','e2e-dispute.ts','e2e-receiptless-claim.ts']) {
  const path = join(target,'scripts',file);
  let code = readFileSync(path,'utf8');
  code = code.replace('"packages", "verifier-cli", "dist", "index.js"','"eval", "revision", "verify-timing-cli.ts"')
    .replace('[verifierCliPath(), ...args]','["--import", "tsx", verifierCliPath(), ...args]');
  if (file === 'e2e-violation.ts') {
    code = 'import { appendFileSync } from "node:fs";\n' + code;
    code = code.replace('await runCase(spec);', `if (process.env.REVISION_CASE && process.env.REVISION_CASE !== spec.name) continue;
    const started = performance.now();
    await runCase(spec);
    appendFileSync(process.env.REVISION_TIMING_FILE!, JSON.stringify({ kind: "case-total", case: spec.name, totalMs: performance.now() - started }) + "\\n");`);
  }
  writeFileSync(path,code);
}
// The concealment demonstration has a local DB-read/rebuild check, not a verifier invocation.
const concealmentPath = join(target,'scripts','demo-concealment.ts');
let concealment = readFileSync(concealmentPath,'utf8');
concealment = 'import { appendFileSync } from "node:fs";\n' + concealment;
// Keep the original read and loop; preload the read outside the local calculation timer.
const bodyStart = concealment.indexOf('function rebuildRoot(');
const bodyEnd = concealment.indexOf('\nasync function anchorUntilCovered', bodyStart);
writeFileSync(join(output,'concealment-original-function.txt'),concealment.slice(bodyStart,bodyEnd));
concealment = concealment.replace('const tree = new Rfc6962LogTree();','const localStarted = performance.now();\n  const tree = new Rfc6962LogTree();');
concealment = concealment.replace('return { root: tree.currentRoot(), leafCount: rows.length };',
  'const result = { root: tree.currentRoot(), leafCount: rows.length };\n  lastRebuildMs = performance.now() - localStarted;\n  return result;');
concealment = 'let lastRebuildMs = 0;\n' + concealment;
concealment = concealment.replace('if (tampered.leafCount >= anchor.treeSize || tampered.root === anchor.rootHash) {',
  'const comparisonStarted = performance.now();\n    if (tampered.leafCount >= anchor.treeSize || tampered.root === anchor.rootHash) {');
concealment = concealment.replace('console.log(`  detection: only',
  'appendFileSync(process.env.REVISION_TIMING_FILE!, JSON.stringify({kind:"verification",case:"post-anchor-completion-entry-deletion",computeMs:lastRebuildMs + performance.now() - comparisonStarted,ok:true,treeSize:anchor.treeSize})+"\\n");\n    console.log(`  detection: only');
writeFileSync(concealmentPath,concealment);
writeFileSync(join(output,'source-hashes.json'),JSON.stringify(hashes,null,2));
// The instrumented copies are what actually ran, so the change is recorded file by file: the
// repository file it came from and the patched file in the workspace. sourceTreeHash covers
// neither this tool nor these copies, so this manifest is the link between them.
const instrumented = ['docker-compose.yml','contracts/hardhat.config.ts','scripts/e2e-violation.ts',
  'scripts/e2e-dispute.ts','scripts/e2e-receiptless-claim.ts','scripts/demo-concealment.ts'];
const sha = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
writeFileSync(join(output,'instrumentation.json'),JSON.stringify({
  note: 'evaluation-only copies; the repository files under source are unchanged',
  tool: Object.fromEntries(['config.ts','prepare.ts','run.ts','timing.ts','timing.test.ts','verify-timing-cli.ts',
    'gas.ts','summarize.ts','capture-state.ts','check-provenance.ts','README.md']
    .map(name => [`eval/revision/${name}`, sha(join(source,'eval/revision',name))])),
  workspace: Object.fromEntries(instrumented.map(file => [file,
    { repository: hashes[file] ?? sha(join(source,file)), patched: sha(join(target,file)) }]))
},null,2));
writeFileSync(join(output,'preparation.json'),JSON.stringify({source,target,originalFilesChanged:false,
  ...describe()},null,2));
console.log(target);
