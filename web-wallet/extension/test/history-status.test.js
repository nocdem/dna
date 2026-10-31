// Node >=22.14; no flags/network/artifacts. Execute the mounted screen's
// actual loader with public DOM/controller fixtures and a fake timer. This
// proves polling/status lifecycle; it does not prove full-screen rendering.
// An unmocked event-loop turn drains promises crossing the VM/host boundary;
// a fixed count of Promise.resolve() waits can assert before the poll resumes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { runInNewContext } from 'node:vm';
import { capabilitiesFor } from '../../src/capabilities.js';

async function loader(t) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const source = await readFile(new URL('../src/ui/wallet-screen.js', import.meta.url), 'utf8');
  const start = source.indexOf('  async function loadHistory('), end = source.indexOf("  $('history-refresh').onclick", start);
  const slots = { history: { replaceChildren() {} }, 'history-status': {} }, polls = [];
  let finish, text = 'Waiting for the provider, retrying in 43 seconds.';
  const held = new Promise(resolve => { finish = resolve; });
  const context = { document: {}, selected: 'ethereum', disposed: false, readGeneration: 0, historyController: undefined,
    capabilitiesFor, AbortController, selectedNetwork: () => ({ id: 'mainnet' }), $: id => slots[id],
    setTimeout, clearTimeout, isSolanaTron: () => false,
    element: () => ({ querySelector: () => ({ children: [] }) }), renderSolanaTronHistory() {},
    ui: { request: async (method, [chain, options]) => {
      assert.equal(method, 'getChainHistory'); assert.equal(chain, 'ethereum');
      if (options.poll) { polls.push(options); return { status: text }; }
      return held;
    } } };
  runInNewContext(source.slice(start, end), context);
  return { context, slots, polls, finish, setText: value => { text = value; } };
}

test('extension polls status while the original history read remains pending and stops after completion', async t => {
  const { context, slots, polls, finish, setText } = await loader(t);
  const reading = context.loadHistory();
  t.mock.timers.tick(1000); await nextTurn();
  assert.equal(slots['history-status'].textContent, 'Waiting for the provider, retrying in 43 seconds.');
  setText('Waiting for the provider, retrying in 42 seconds.');
  t.mock.timers.tick(1000); await nextTurn();
  assert.equal(slots['history-status'].textContent, 'Waiting for the provider, retrying in 42 seconds.');
  finish({ rows: [], status: 'History read complete.' }); await reading;
  assert.equal(slots['history-status'].textContent, 'History read complete.');
  const count = polls.length; t.mock.timers.tick(5000); await nextTurn();
  assert.equal(polls.length, count);
});

test('extension stops status polling when its screen is disposed', async t => {
  const { context, slots, polls, finish } = await loader(t);
  const reading = context.loadHistory();
  context.disposed = true;
  t.mock.timers.tick(1000); await nextTurn();
  assert.equal(polls.length, 0);
  finish({ rows: [], status: 'Late result.' }); await reading;
  assert.notEqual(slots['history-status'].textContent, 'Late result.');
});

test('switching network cancels pending history and discards its late result', async t => {
  const { context, slots, polls, finish } = await loader(t);
  const reading = context.loadHistory();
  const original = context.historyController;
  t.mock.timers.tick(1000); await nextTurn();
  assert.equal(polls.length, 1);
  // CKB has balances but no implemented account history. Its new context
  // must clear the old history and cancel it without issuing another read.
  context.selected = 'ckb';
  await context.loadHistory();
  assert.equal(original.signal.aborted, true);
  assert.equal(slots['history-status'].textContent, '');
  const count = polls.length;
  t.mock.timers.tick(5000); await nextTurn();
  assert.equal(polls.length, count);
  finish({ rows: [{ hash: 'old-network' }], status: 'Late Ethereum result.' });
  await reading;
  assert.equal(slots['history-status'].textContent, '');
});
