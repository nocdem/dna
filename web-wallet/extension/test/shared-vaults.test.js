import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createSharedVaults, SHARED_READS } from '../src/background/shared-vaults.js';

// Package H call inventory is checked against the reference itself. No flags,
// network/artifacts. A hand-maintained subset alone could falsely pass.
test('shared vault bridge covers every reference client operation and reviews signing before use', async () => {
  const source = readFileSync(new URL('../../src/vaults/ui.js', import.meta.url), 'utf8');
  const methods = [...new Set([...source.matchAll(/client\.([A-Za-z]+)\s*\(/g)].map(match => match[1]))].sort();
  assert.deepEqual(methods, [...SHARED_READS, 'vaultApprove', 'vaultSubmit'].sort());
  const calls = [], request = { digest: 'ab'.repeat(64) }, review = { digest: request.digest, outputs: [{ owner: 'cd'.repeat(64), amount: '100', change: false }], fee: '1', expiryHeight: '99', inputs: ['ef'.repeat(64)] };
  const client = { state: 'ready', vaultable: true };
  for (const method of methods) client[method] = async fields => { calls.push([method, fields]); return method === 'vaultReview' ? review : { method }; };
  const session = { client }, api = createSharedVaults({ active: () => session });
  for (const method of SHARED_READS) assert.deepEqual(await api.read(method, {}), method === 'vaultReview' ? review : { method });
  for (const method of ['vaultApprove', 'vaultSubmit']) {
    const prepared = await api.prepare(method, { descriptor: 'public-fixture', request, digest: request.digest });
    assert.equal(calls.some(call => call[0] === method), false);
    assert.ok(prepared.review.some(([label, value]) => label === 'Pay to' && value === review.outputs[0].owner));
    assert.deepEqual(await api.confirm(prepared.id), { method });
    await assert.rejects(api.confirm(prepared.id), /closed/);
  }
  const prepared = await api.prepare('vaultApprove', { request, digest: request.digest }); api.lock();
  await assert.rejects(api.confirm(prepared.id), /closed/);
  await assert.rejects(api.read('vaultApprove', {}), /Unsupported/);
});
