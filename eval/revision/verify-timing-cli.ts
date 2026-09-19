import { readFileSync, appendFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import assert from 'node:assert/strict';
import { GatewayClient } from '../../packages/verifier-cli/src/http.js';
import { AnchorReader } from '../../packages/verifier-cli/src/anchor.js';
import { verifyNonTransfer, resolveDispute } from '../../packages/verifier-cli/src/verifier.js';
import { ActiveTimer } from './timing.js';

const names = ['consent-id','secret-c','revocation-seq','revocation-entry-hash','provider-gateway','receiver-gateway',
  'rpc-url','provider-anchor-address','receiver-anchor-address','grace-sec','tls-ca','tls-cert','tls-key',
  'transfer-ref','a-gateway','b-gateway','a-anchor-address','b-anchor-address','a-public-key','b-public-key','claim'];
const { values: v, positionals } = parseArgs({ allowPositionals: true,
  options: Object.fromEntries(names.map(name => [name, { type: 'string' as const }])) });
const tls = { caPath: v['tls-ca'], certPath: v['tls-cert'], keyPath: v['tls-key'] };
const timer = new ActiveTimer();
const recorded: {name:string; args:unknown[]; value:unknown}[] = [];
let replay = false;
let cursor = 0;
// These boundaries include transport setup, TLS file reads and API/RPC envelope decoding.
// Canonical entry parsing, hashing, proof/signature checks and verdict logic stay measured.
for (const [proto, name] of [[GatewayClient.prototype, 'tryGet'], [AnchorReader.prototype, 'anchorCount'],
  [AnchorReader.prototype, 'getAnchor']] as const) {
  const target = proto as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const original = target[name];
  target[name] = function (...args: unknown[]) {
    if (replay) {
      const entry = recorded[cursor++];
      assert.equal(entry.name,name); assert.deepEqual(entry.args,args);
      return Promise.resolve(structuredClone(entry.value));
    }
    return timer.outside(async () => {
      const value = await original.apply(this,args);
      recorded.push({name,args:structuredClone(args),value:structuredClone(value)});
      return value;
    });
  };
}
const options = positionals[0] === 'verify-non-transfer' ? {
  consentId: v['consent-id']!, secretC: v['secret-c']!, revocationSeq: Number(v['revocation-seq']),
  revocationEntryHash: v['revocation-entry-hash']!, providerGateway: v['provider-gateway']!,
  receiverGateway: v['receiver-gateway']!, rpcUrl: v['rpc-url']!,
  providerAnchorAddress: v['provider-anchor-address'], receiverAnchorAddress: v['receiver-anchor-address'],
  graceSeconds: Number(v['grace-sec']), tls
} : {
  transferRef: v['transfer-ref']!, aGateway: v['a-gateway']!, bGateway: v['b-gateway']!, rpcUrl: v['rpc-url']!,
  providerAnchorAddress: v['a-anchor-address'], receiverAnchorAddress: v['b-anchor-address'],
  aPublicKeyPem: readFileSync(v['a-public-key']!, 'utf8'), bPublicKeyPem: readFileSync(v['b-public-key']!, 'utf8'),
  claim: v.claim as 'b-denies' | undefined, tls
};
timer.start();
const result = positionals[0] === 'verify-non-transfer'
  ? await verifyNonTransfer(options as Parameters<typeof verifyNonTransfer>[0])
  : await resolveDispute(options as Parameters<typeof resolveDispute>[0]);
const measured = timer.finish();
replay = true;
const replayResult = positionals[0] === 'verify-non-transfer'
  ? await verifyNonTransfer(options as Parameters<typeof verifyNonTransfer>[0])
  : await resolveDispute(options as Parameters<typeof resolveDispute>[0]);
assert.equal(cursor,recorded.length);
assert.deepEqual({ok:result.ok,status:result.status,lines:result.lines},
  {ok:replayResult.ok,status:replayResult.status,lines:replayResult.lines});
for (const line of result.lines) console.log(line);
if (!process.env.REVISION_TIMING_FILE) throw new Error('REVISION_TIMING_FILE is required');
appendFileSync(process.env.REVISION_TIMING_FILE, JSON.stringify({ kind: 'verification', command: positionals[0],
  case: process.env.REVISION_CASE, replayAgrees:true, ...measured, ...result }) + '\n');
process.exitCode = result.ok ? 0 : result.status === 'waiting' ? 2 : 1;
