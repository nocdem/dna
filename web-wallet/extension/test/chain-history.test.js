import test from 'node:test';
import assert from 'node:assert/strict';
import { createChainHistory } from '../src/background/chain-history.js';
import { walletSession, phrase } from './fixtures/wallet-session.js';
import { balancesKeyFor, serializeBalances, parseBalances } from '../../src/activity-storage.js';
import { BALANCES_KEY, encryptVault, parseVault } from '../../src/vault.js';

// Package B2: cache age, actual chain/address and encrypted-cache writer
// boundary. No flags/network/artifacts. An always-empty reply misses merge.
test('history uses the selected account and web-wallet refresh limits', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: 2_000_000 });
  let page, reads = 0;
  const activity = { rows: () => [], history: () => page, saveHistory: async value => { page = value; } };
  const controller = createChainHistory({ getActivity: () => activity, getAddresses: () => ({ ethereum: 'public-ethereum' }),
    assertCurrent() {}, read: async (chain, address) => { reads++; assert.equal(chain, 'ethereum'); assert.equal(address, 'public-ethereum'); return []; } });
  await controller.getHistory('ethereum'); await controller.getHistory('ethereum'); assert.equal(reads, 1);
  assert.match((await controller.getHistory('ethereum', { manual: true })).status, /provider limits/);
  t.mock.timers.tick(30001); await controller.getHistory('ethereum', { manual: true }); assert.equal(reads, 2);
  await assert.rejects(controller.getHistory('bsc'), /Unsupported/);
});

// Public read fixture only; no flags/network/artifacts. Polls must expose
// intermediate text without starting another provider read or saving a page.
test('waiting history status is readable while the original job is pending', async () => {
  let page, finish, reportStatus, reads = 0, saves = 0;
  const held = new Promise(resolve => { finish = resolve; });
  const activity = { rows: () => [], history: () => page, saveHistory: async value => { saves++; page = value; } };
  const controller = createChainHistory({ getActivity: () => activity, getAddresses: () => ({ ethereum: 'public-ethereum' }),
    assertCurrent() {}, read: async (_chain, _address, options) => { reads++; reportStatus = options.onStatus; return held; } });
  const reading = controller.getHistory('ethereum');
  await Promise.resolve();
  reportStatus('Waiting for the provider, retrying in 43 seconds.');
  const waiting = await controller.getHistory('ethereum', { poll: true });
  assert.equal(waiting.status, 'Waiting for the provider, retrying in 43 seconds.');
  assert.equal(reads, 1); assert.equal(saves, 0);
  const duplicate = controller.getHistory('ethereum', { manual: true });
  reportStatus('');
  assert.match((await controller.getHistory('ethereum', { poll: true })).status, /Reading account history/);
  finish([]);
  assert.deepEqual(await duplicate, await reading);
  assert.equal(reads, 1); assert.equal(saves, 1);
  await controller.getHistory('ethereum', { poll: true });
  assert.equal(reads, 1, 'polling a settled job never starts another provider read');
});

test('a bounded history refusal reaches the original caller without saving a fresh page', async () => {
  let saves = 0;
  const message = 'The history provider is limiting requests right now. Try again in a few minutes.';
  const activity = { rows: () => [], history: () => null, saveHistory: async () => { saves++; } };
  const controller = createChainHistory({ getActivity: () => activity, getAddresses: () => ({ ethereum: 'public-ethereum' }),
    assertCurrent() {}, read: async () => { throw new Error(message); } });
  assert.equal((await controller.getHistory('ethereum')).error, message);
  assert.equal(saves, 0);
});

// B2: cross-read the site's balance format; a different id must not decrypt.
// No flags/network/artifacts. Reusing the same id would miss cache isolation.
test('kept balances use the web-wallet key and reject another vault id', async t => {
  let entries;
  const { nodus, values, lockCoordinator } = await walletSession(t, { beforeOpen: async ({ values, id, addresses }) => {
    entries = { 'ethereum:ETH': { units: '123', observedAt: Date.now(), address: addresses.ethereum } };
    values[BALANCES_KEY] = await serializeBalances(id, entries, await balancesKeyFor(phrase, id));
  } });
  assert.deepEqual(nodus.getKeptBalances(), entries); await nodus.keepBalances(entries);
  const another = parseVault(await encryptVault(phrase, 'public-second-password-456')).id;
  await assert.rejects(parseBalances(values[BALANCES_KEY], another, await balancesKeyFor(phrase, another)));
  await lockCoordinator.lock(); assert.throws(() => nodus.getKeptBalances(), /locked/);
});
