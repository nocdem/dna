import test from 'node:test';
import assert from 'node:assert/strict';
import { CHAINS } from '../../src/config.js';
import { ACTIVITY_KEY, HISTORY_KEY, VAULT_KEY, parseVault } from '../../src/vault.js';
import { activityKeyFor, parseActivity, serializeActivity, historyKeyFor, parseHistory } from '../../src/activity-storage.js';
import { setup, deferred, phrase, password, unlockOptions } from './solana-tron-fixture.js';
import { checkNetwork, checkTestnetActivity } from '../src/background/testnet-adapters.js';
import { createNetworkActivity } from '../src/background/network-activity.js';
import { chainNetwork } from '../src/constants/networks.js';

// Node >=22.14, no flags. All RPC and storage are faked by setup; no files,
// live chains or skips. Literal endpoints/genesis values below independently
// pin the references and tasks/orchestration.md:5921 live-read record.
// Wrong-identity fixtures return another network's well-formed genesis, so
// checking only the RPC response shape cannot satisfy the refusal assertions.
const testnets = [
  ['solana', 'testnet', 'https://api.testnet.solana.com', '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY'],
  ['solana', 'devnet', 'https://api.devnet.solana.com', 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'],
  ['tron', 'nile', 'https://nile.trongrid.io', '0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc'],
];

test('each chain defaults to mainnet except the only available Nodus testnet; choices persist', async t => {
  const { background, client, fixture } = await setup(t);
  assert.deepEqual((await client.request('getState')).networks, {
    nodus: 'testnet', ethereum: 'mainnet', bsc: 'mainnet', solana: 'mainnet', tron: 'mainnet', cellframe: 'mainnet',
  });
  for (const chain of ['ethereum', 'bsc', 'solana', 'tron']) assert.equal(background.networks.get(chain).endpoint, CHAINS[chain].endpoint);
  for (const chain of ['ethereum', 'bsc', 'cellframe']) await assert.rejects(client.request('setChainNetwork', [chain, 'testnet']), /network/i);
  await assert.rejects(client.request('setChainNetwork', ['nodus', 'mainnet']), /network/i);
  await client.request('setChainNetwork', ['solana', 'devnet']);
  const { createBackground } = await import('../src/background/index.js');
  const restarted = await createBackground(fixture);
  try {
    assert.equal(restarted.networks.getState().solana, 'devnet');
    assert.equal(restarted.lockCoordinator.isLocked, true);
    assert.equal(restarted.networks.getState().tron, 'mainnet');
  } finally { await restarted.destroy(); }
});

// Same-prefix Solana and same-suffix TRON negative controls reject the
// retracted identity derivations, even when another-network controls pass.
test('Solana mainnet and every runnable network require the complete expected genesis', async t => {
  const { state } = await setup(t);
  for (const [chain, id, endpoint, genesis] of [
    ['solana', 'mainnet', CHAINS.solana.endpoint, '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'],
    ['tron', 'mainnet', CHAINS.tron.endpoint, '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc'],
    ...testnets,
  ]) {
    const network = chainNetwork(chain, id);
    assert.equal(network.endpoint, endpoint);
    if (id !== 'mainnet') assert.equal(network.genesisHash, genesis);
    state.genesisOverride = genesis;
    await checkNetwork(chain, network);
    const wrong = chain === 'solana'
      ? [genesis.slice(0, 32), `${genesis.slice(0, -1)}${genesis.endsWith('1') ? '2' : '1'}`]
      : [`f${genesis.slice(1)}`, '0'.repeat(56) + genesis.slice(-8)];
    for (const other of wrong) {
      state.genesisOverride = other;
      await assert.rejects(checkNetwork(chain, network), /network|genesis|mainnet/i, `${chain}/${id} refuses ${other}`);
    }
  }
});

// src/app.js:343-347 reads mainnet history without an identity RPC. Empty
// local activity keeps tracker RPCs from hiding an extra getHistory check.
test('mainnet history reads do not add identity RPCs', async t => {
  const { background, state, calls } = await setup(t);
  state.wrongNetwork = true;
  for (const chain of ['solana', 'tron']) {
    const start = calls.length;
    const history = await background[chain].getHistory();
    assert.equal(history.error, '');
    assert.ok(history.rows.length, `${chain} account history was read`);
    assert.ok(calls.slice(start).every(call => call.body.method !== 'getGenesisHash' && !call.url.endsWith('/wallet/getblockbynum')));
    await assert.rejects(background[chain].getBalances(), /mainnet/i);
  }
});

test('every testnet reads, prepares, signs and tracks through its pinned endpoint and rejects wrong identity', async t => {
  const { background, client, state, calls, broadcasts } = await setup(t);
  for (const [chain, network, endpoint] of testnets) {
    await client.request('setChainNetwork', [chain, network]);
    const start = calls.length;
    const fields = { symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' };
    const review = await background[chain].prepareSend(fields);
    assert.equal(review.network, network);
    await background[chain].confirmSend(review.id);
    const balances = await background[chain].getBalances();
    assert.equal(balances[0].balance, chain === 'solana' ? '10.0' : '123.0');
    const history = await background[chain].getHistory();
    assert.equal(history.network, network);
    const local = background.nodus.chainActivity(chain, network).rows()[0];
    assert.ok(local, 'the signed send is stored on this network');
    assert.equal((await checkTestnetActivity(local, chainNetwork(chain, network))).status, 'confirmed');
    assert.ok(calls.slice(start).length);
    assert.ok(calls.slice(start).every(call => call.url.startsWith(endpoint)), `${chain}/${network} uses only its endpoint`);
    const before = broadcasts.length;
    state.wrongNetwork = true;
    await assert.rejects(background[chain].getBalances(), /network|genesis/i);
    await assert.rejects(checkTestnetActivity(local, chainNetwork(chain, network)), /network|genesis/i);
    await assert.rejects(background[chain].prepareSend(fields), /network|genesis/i);
    const later = Date.now() + 31000, clock = t.mock.method(Date, 'now', () => later);
    const failed = await background[chain].getHistory({ manual: true }); clock.mock.restore();
    assert.match(failed.error, /network|genesis/i);
    state.wrongNetwork = false;
    const pending = await background[chain].prepareSend(fields);
    state.wrongNetwork = true;
    await assert.rejects(background[chain].confirmSend(pending.id), /network|genesis/i);
    state.wrongNetwork = false;
    assert.equal(broadcasts.length, before, 'wrong identity cannot broadcast');
    await background.lock(); await background.unlock(password, unlockOptions);
  }
});

// Explicitly hold history's transport past a switch: merely comparing two
// completed pages cannot catch a late mainnet cache write on a testnet page.
test('a history read crossing a network switch is cancelled and cannot populate the new network', async t => {
  for (const chain of ['solana', 'tron']) {
    const { background, client, state } = await setup(t);
    state.entered = deferred(); state.readGate = deferred();
    state.pauseMethod = chain === 'solana' ? 'getSignaturesForAddress' : undefined;
    state.pausePath = chain === 'tron' ? `/v1/accounts/${state.addresses.tron}/transactions` : undefined;
    const old = background[chain].getHistory(), rejected = assert.rejects(old, /network changed/i);
    await state.entered.promise;
    await client.request('setChainNetwork', [chain, chain === 'solana' ? 'devnet' : 'nile']);
    await rejected; state.readGate.resolve(); state.readGate = undefined;
    const current = await background[chain].getHistory();
    assert.equal(current.network, chain === 'solana' ? 'devnet' : 'nile');
    if (chain === 'tron') assert.deepEqual(current.rows, []);
    else assert.deepEqual(current.rows.map(row => [row.hash, row.amount]), [['4'.repeat(88), '3.0']]);
    assert.deepEqual(current.local, []);
  }
});

test('unreadable testnet activity blocks its sends and explicit settings recovery preserves mainnet', async t => {
  const { background, client, state, values } = await setup(t);
  const main = await background.tron.getHistory();
  values[`${ACTIVITY_KEY}.tron.nile`] = 'invalid encrypted fixture';
  await client.request('setChainNetwork', ['tron', 'nile']);
  const fields = { symbol: 'TRX', to: state.recipients.tron, amount: '1' };
  await assert.rejects(background.tron.prepareSend(fields), /discard the unreadable history/);
  assert.ok(background.nodus.getState().activityError);
  assert.equal(await background.nodus.discardActivity(), 'Unreadable local history discarded; readable records and their held coins were kept. Check the account explorer before resending any previous payment.');
  const review = await background.tron.prepareSend(fields); background.tron.cancelSend(review.id);
  await client.request('setChainNetwork', ['tron', 'mainnet']);
  assert.deepEqual((await background.tron.getHistory()).rows, main.rows);
});

// Change the saved data at the post-encryption read. Without that read the
// operation writes and this rejection fails; no scheduling race or skip.
test('testnet discard refuses a wallet or saved activity changed during encryption', async t => {
  const { values, state } = await setup(t);
  const id = parseVault(values[VAULT_KEY]).id, key = await activityKeyFor(phrase, id);
  const activityKey = `${ACTIVITY_KEY}.tron.nile`, vault = values[VAULT_KEY];
  for (const changedKey of [activityKey, VAULT_KEY]) {
    const replacement = changedKey === activityKey ? await serializeActivity(id, [], key) : 'changed vault fixture';
    values[VAULT_KEY] = vault; values[activityKey] = 'invalid encrypted fixture';
    let discarding = false, reads = 0, writes = 0;
    const activity = createNetworkActivity({ chain: 'tron', network: chainNetwork('tron', 'nile'),
      session: { id, key, vault, addresses: state.addresses }, current() {},
      storage: {
        async get(keys) {
          if (discarding && ++reads === 2) values[changedKey] = replacement;
          return Object.fromEntries(keys.map(name => [name, values[name]]));
        },
        async set(items) { writes++; Object.assign(values, items); },
      },
    });
    await activity.ready; assert.equal(activity.blocked, true);
    discarding = true;
    await assert.rejects(activity.discard(), /Wallet or history changed/);
    assert.equal(writes, 0, 'changed saved data is never overwritten');
    assert.equal(values[changedKey], replacement);
    assert.equal(activity.blocked, true, 'a failed discard does not unblock sending');
  }
});

test('switching cancels reviews and late reads; encrypted histories and sends stay per network after unlock', async t => {
  const { background, client, state, values } = await setup(t);
  for (const chain of ['solana', 'tron']) {
    const network = chain === 'solana' ? 'devnet' : 'nile';
    const main = await background[chain].getHistory();
    const fields = { symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' };
    const review = await background[chain].prepareSend(fields);
    state.entered = deferred(); state.readGate = deferred();
    state.pauseMethod = chain === 'solana' ? 'getBalance' : undefined;
    state.pausePath = chain === 'tron' ? `/v1/accounts/${state.addresses.tron}` : undefined;
    const reading = background[chain].getBalances(), rejected = assert.rejects(reading, /network changed/i);
    await state.entered.promise;
    await client.request('setChainNetwork', [chain, network]);
    await rejected; state.readGate.resolve(); state.readGate = undefined;
    await assert.rejects(background[chain].confirmSend(review.id), /closed/);
    const fresh = await background[chain].getHistory();
    assert.notDeepEqual(fresh.rows, main.rows, 'the network fixtures have distinct histories');
    assert.ok(fresh.rows.every(row => row.symbol === CHAINS[chain].symbol), 'testnet never imports mainnet token history');
    const sending = await background[chain].prepareSend(fields);
    await background[chain].confirmSend(sending.id);
    const id = parseVault(values[VAULT_KEY]).id;
    const rows = await parseActivity(values[`${ACTIVITY_KEY}.${chain}.${network}`], id, state.addresses, await activityKeyFor(phrase, id));
    assert.equal(rows.length, 1);
    const history = await parseHistory(values[`${HISTORY_KEY}.${chain}.${network}`], id, await historyKeyFor(phrase, id));
    assert.deepEqual(history[chain].rows, fresh.rows);
    await background.lock(); await background.unlock(password, unlockOptions);
    const reloaded = await background[chain].getHistory();
    assert.equal(reloaded.local.length, 1);
    assert.ok(reloaded.local.every(row => row.network === network));
    await client.request('setChainNetwork', [chain, 'mainnet']);
    const restored = await background[chain].getHistory();
    assert.deepEqual(restored.rows, main.rows);
    assert.equal(restored.local.length, 0, 'a testnet send is absent on mainnet');
  }
});

test('manual cooldown explains the provider limit and confirmation schedules one account-history re-read', async t => {
  const { background, state, calls } = await setup(t);
  for (const chain of ['solana', 'tron']) {
    await background[chain].getHistory();
    const early = await background[chain].getHistory({ manual: true });
    assert.match(early.status, /Try again in a minute/);
    // Restart the tracker without refreshing the kept account history, so
    // the first tick after this send checks the newly appended record.
    await background.lock(); await background.unlock(password, unlockOptions);
    const future = Date.now() + 31000, clock = t.mock.method(Date, 'now', () => future);
    const fields = { symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' };
    state.historyEntered = deferred();
    const count = () => calls.filter(call => chain === 'solana' ? call.body.method === 'getSignaturesForAddress' : call.url.includes('/transactions?')).length;
    const before = count();
    const review = await background[chain].prepareSend(fields); await background[chain].confirmSend(review.id);
    // This gate is reached only by the confirmation-triggered source read;
    // manually calling getHistory first would hide the missing behaviour.
    await state.historyEntered.promise;
    await background[chain].getHistory();
    assert.equal(count(), before + 1);
    await background[chain].getHistory(); assert.equal(count(), before + 1);
    state.historyEntered = undefined; clock.mock.restore();
  }
});
