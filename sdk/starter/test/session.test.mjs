// Mock account tests: no network, WASM or secret; real local journal ordering.
// No special flags/env. Temporary dirs removed. Does not prove SDK signing or
// chain acceptance; SDK review.test.js tests the actual review gate separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withAccount } from '../src/session.mjs';
import { acquireJournal } from '../src/journal.mjs';

const chainId = '1'.repeat(64), fingerprint = '2'.repeat(128);
const row = { hash: '3'.repeat(128), expiryHeight: '1090', inputs: ['4'.repeat(128)] };
async function fixture(t, settled = false) {
  const stateDir = await mkdtemp(join(tmpdir(), 'nodus-session-'));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  let pending = [], closed = false;
  const evm = {
    fingerprint, chainId, evmActive: true,
    connect: async () => {}, close: () => { closed = true; },
    pending: () => pending,
    checkPending: async () => { if (settled) pending = []; }
  };
  const sdk = { deriveIdentity: async () => ({ fingerprint }), NodusEvm: { open: async opts => { pending = opts.pending; return evm; } } };
  return { sdk, evm, stateDir, config: { network: { chainId }, maxFee: 1000n }, phrase: 'synthetic',
    closed: () => closed, setPending: rows => { pending = rows; } };
}

test('onRecord is durable before a write can submit, then definitive success clears it', async t => {
  const f = await fixture(t);
  await withAccount({ ...f, write: true, confirm: async () => true, run: async (evm, options) => {
    await options.onRecord(row);
    const path = join(f.stateDir, chainId, fingerprint, 'pending.json');
    assert.deepEqual(JSON.parse(await readFile(path, 'utf8')).pending, [row]);
    return { status: 'applied-success', intentId: row.hash };
  } });
  const journal = await acquireJournal({ ...f, chainId, fingerprint });
  try { assert.deepEqual(journal.pending(), []); } finally { await journal.close(); }
  assert.equal(f.closed(), true);
});

test('uncertain write preserves its durable record even when SDK map is empty', async t => {
  const f = await fixture(t);
  await assert.rejects(withAccount({ ...f, write: true, confirm: async () => true, run: async (_, options) => {
    await options.onRecord(row);
    throw new Error('ambiguous submission or post-rename persistence failure');
  } }), /ambiguous/);
  const journal = await acquireJournal({ ...f, chainId, fingerprint });
  try { assert.deepEqual(journal.pending(), [row]); } finally { await journal.close(); }
  let ran = false;
  await assert.rejects(withAccount({ ...f, write: true, confirm: async () => true, run: async () => { ran = true; } }), /pending/);
  assert.equal(ran, false);
});

test('resolved record is removed only after SDK checkPending completes successfully', async t => {
  const f = await fixture(t, true);
  const journal = await acquireJournal({ ...f, chainId, fingerprint });
  await journal.record(row); await journal.close();
  await withAccount({ ...f, write: false, run: async evm => assert.deepEqual(evm.pending(), []) });
  const again = await acquireJournal({ ...f, chainId, fingerprint });
  try { assert.deepEqual(again.pending(), []); } finally { await again.close(); }
});
