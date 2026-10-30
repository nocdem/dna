// No flags/network/artifacts. Execute the site's actual history functions
// with public state and DOM slots; this proves status callback wiring, not
// layout, full-page startup, or live provider behavior.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

test('the site displays the live countdown and ignores a stale wallet callback', async () => {
  const source = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
  const render = source.slice(source.indexOf('function renderHistory()'), source.indexOf('async function loadHistory('));
  const load = source.slice(source.indexOf('async function loadHistory('), source.indexOf('function persistHistory()'));
  const slots = { chain: { value: 'ethereum' }, history: { replaceChildren() {} }, 'history-status': {}, 'history-refresh': {} };
  let reportStatus, finish;
  const held = new Promise(resolve => { finish = resolve; });
  const context = { $: id => slots[id], wallet: { addresses: { ethereum: 'public-ethereum' } },
    NODUS_ASSET: { chain: 'nodus' }, historyJob: null, historyNote: {}, historyByChain: {},
    historyFor: () => null, historySupported: () => true, HISTORY_SOURCES: { ethereum: 'Blockscout' },
    HISTORY_AUTO_MS: { ethereum: 1800000 }, HISTORY_AUTO_DEFAULT_MS: 300000, HISTORY_MANUAL_MS: 30000,
    endpoints: {}, AbortController, Date, mergeHistory: (_kept, rows) => rows, persistHistory() {}, renderActivity() {},
    readHistory: async (_chain, _address, options) => { reportStatus = options.onStatus; return held; } };
  runInNewContext(render + load, context);
  const reading = context.loadHistory('ethereum');
  assert.equal(slots['history-status'].textContent, 'Reading account history from Blockscout…');
  reportStatus('Waiting for the provider, retrying in 43 seconds.');
  assert.equal(slots['history-status'].textContent, 'Waiting for the provider, retrying in 43 seconds.');
  reportStatus('Waiting for the provider, retrying in 42 seconds.');
  assert.equal(slots['history-status'].textContent, 'Waiting for the provider, retrying in 42 seconds.');
  reportStatus('');
  assert.equal(slots['history-status'].textContent, 'Reading account history from Blockscout…');
  context.wallet = { addresses: { ethereum: 'another-wallet' } };
  reportStatus('Waiting for the provider, retrying in 99 seconds.');
  assert.equal(slots['history-status'].textContent, 'Reading account history from Blockscout…');
  finish([]); await reading;
});
