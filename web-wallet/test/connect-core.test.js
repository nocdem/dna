// LOCAL FIRST — src/connect/core.js's split between the calls that need only
// the identity (run on the wallet's IDENTIFIED client: nodus.connectLocal)
// and the calls that reach the network (nodus.connect, 'ready' only).
// Against a fake wallet client that records which slot each export used:
// proves the JS routing and the constructor gate, nothing about the module
// (connect/nc_wasm.c refuses a network call before the connect on its own,
// session_ok).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusConnectCore } from '../src/connect/core.js';

const FP = 'ab'.repeat(64), OTHER = 'cd'.repeat(64);

function fakeNodus() {
  const calls = [], heap = new Uint8Array(4096);
  let last;
  const results = {
    nc_unlock: { fingerprint: FP, fresh: false },
    nc_profile_load: { profile: { fingerprint: OTHER } },
    nc_hist_key: {},
    nc_profile_get: { outcome: 'empty', why: 'none' }
  };
  const api = route => ({
    num: name => { calls.push(`${route}:${name}`); last = name; return name === 'nc_words_alloc' ? 64 : 0; },
    call: async name => { calls.push(`${route}:${name}`); last = name; return 0; },
    str: name => (name === 'nc_result' ? JSON.stringify(results[last] ?? {}) : ''),
    heap: () => heap
  });
  const nodus = {
    state: 'identified',
    fingerprint: FP,
    localConnectable: true,
    connect: async run => { if (nodus.state !== 'ready') throw new Error('Nodus connection is not ready.'); return run(api('net')); },
    connectLocal: async run => run(api('local')),
    connectSync: run => run(api('sync'))
  };
  return { nodus, calls, heap };
}

test('core: unlock, kept profiles and the history key run on the identified client; network reads wait for ready', async () => {
  const { nodus, calls, heap } = fakeNodus();
  const core = createNodusConnectCore({ nodus });
  const words = new TextEncoder().encode('alpha beta gamma');
  assert.deepEqual(await core.unlock({ words }), { fingerprint: FP, fresh: false });
  assert.ok(words.every(b => b === 0), 'the JS copy of the words is zeroed');
  assert.equal(new TextDecoder().decode(heap.subarray(64, 64 + 16)), 'alpha beta gamma', 'the words reached the module buffer');
  assert.equal(core.state, 'ready');
  assert.deepEqual((await core.profileLoad(OTHER, '{"kept":1}', '')).profile, { fingerprint: OTHER });
  await core.historyKey('00'.repeat(16));
  // The network is not there yet: refused by the wallet client, nothing ran.
  await assert.rejects(core.profileGet(OTHER), /not ready/);
  assert.deepEqual(calls, ['local:nc_words_alloc', 'local:nc_unlock', 'local:nc_profile_load', 'local:nc_hist_key']);
  nodus.state = 'ready';
  assert.equal((await core.profileGet(OTHER)).outcome, 'empty');
  assert.equal(calls.at(-1), 'net:nc_profile_get');
  core.lock();
  assert.equal(calls.at(-1), 'sync:nc_lock');
  await assert.rejects(core.historyKey('00'.repeat(16)), /not connected|locked/);
});

test('core: refuses a wallet client that is not identified, or one without the local slot', () => {
  const base = { connect() {}, connectLocal() {}, connectSync() {} };
  assert.throws(() => createNodusConnectCore({ nodus: { ...base, localConnectable: false } }), /not open/);
  const { connectLocal, ...noLocal } = base;
  assert.equal(typeof connectLocal, 'function');
  assert.throws(() => createNodusConnectCore({ nodus: { ...noLocal, localConnectable: true } }), /not available/);
});
