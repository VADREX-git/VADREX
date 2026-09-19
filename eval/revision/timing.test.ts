import assert from 'node:assert/strict';
import { ActiveTimer } from './timing.js';
let clock = 0;
const timer = new ActiveTimer(() => clock);
timer.start(); clock += 7;
const value = await timer.outside(async () => {
  clock += 100;
  return timer.outside(async () => { clock += 50; return 42; });
});
clock += 3;
assert.equal(value, 42);
assert.deepEqual(timer.finish(), { computeMs: 10, invocationMs: 160 });
timer.start(); clock += 2;
await assert.rejects(timer.outside(async () => { clock += 80; throw new Error('expected transport error'); }), /expected transport error/);
clock += 4;
assert.deepEqual(timer.finish(), { computeMs: 6, invocationMs: 86 });
assert.equal(await timer.outside(async () => 'unmeasured'), 'unmeasured');
console.log('PASS: nested I/O is excluded once, results/errors propagate, active timing resumes after failure.');
