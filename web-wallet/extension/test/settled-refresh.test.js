import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { phrase, password, address, input, intent } from './fixtures/wallet-session.js';
import { createNodus } from '../src/background/nodus.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { encryptVault, parseVault, VAULT_KEY } from '../../src/vault.js';
import { nodusSigningSeed } from '../../src/nodus/derive.js';
import { deriveWallet, disposeWallet } from '../../src/keys.js';
import { mountNameBlock } from '../src/ui/name-block.js';
import { mountEarn } from '../src/ui/earn-page.js';
import { mountClaimAction } from '../src/ui/claim-action.js';
import { activityKeyFor, serializeActivity } from '../../src/activity-storage.js';
import { ACTIVITY_KEY } from '../../src/vault.js';

// What this file proves (web wallet contract, src/app.js:660-667): when a Nodus transaction of this wallet moves from a
// non-final to a final status, the screen that is ALREADY OPEN reads again, once, what that transaction may have changed:
// a claim row -> the claim status; any other row -> the staking overview and the wallet's own chain name. Before this
// change the screen read once at confirm time (the transaction was only in the mempool then) and never again.
//
// Fixtures: the real background session (startSession below, built like fixtures/wallet-session.js: real Nodus adapter, activity tracker, kept-name logic) with an
// in-memory module whose reads answer from `chain` (name registered / validator list / claim status change only when
// `chain.confirmed` is set, as a block commit would) and the real name block, earn page and claim block mounted on a
// minimal DOM. The tracker's 12 s timer is the existing mocked setTimeout; nothing else is timed. Nothing is left on disk.
// The popup's state refresh is simulated by `sync()`: it copies the background's current public getState() into
// ui.state.nodus and calls each block's update(), which is what wallet-ui.js does after every state change. The tests
// pin that observable behaviour (request counts and what the screen shows), not how the signal is carried.
//
// How a test can pass falsely: (1) the tracker never ran, so nothing could change: every "no re-read" test first asserts
// the tracker scanned a row and the last step of that session makes a row final and requires the re-read, so the
// counters are proven able to move; (2) a re-read caused by something else (reconnect, address change): counts are exact
// deltas from a baseline taken after the mount, and the connection state is the same fixture throughout.
// Not covered: a Nodus row of another address cannot be saved (src/activity-storage.js readActivityRow rejects it), and the
// background tracker only walks rows with chain 'nodus' and this wallet's address (src/background/nodus.js track), so no
// such row can reach a check; this file has no fixture for another network's row.

const VALIDATOR = 'ab'.repeat(64), SECOND = 'cd'.repeat(64), COIN = 20000000000n;
const settle = async (rounds = 40) => { for (let i = 0; i < rounds; i++) await new Promise(resolve => setImmediate(resolve)); };

class Node extends EventTarget {
  constructor() { super(); this.hidden = false; this.disabled = false; this.textContent = ''; this.value = ''; this.title = ''; this.dataset = {}; this.children = []; }
  append(...kids) { this.children.push(...kids); }
  replaceChildren(...kids) { this.children = kids; }
  querySelector() { return null; } querySelectorAll() { return []; }
  setAttribute() {} focus() {} scrollIntoView() {} setSelectionRange() {}
}

function chainModule(chain, scans) {
  const validator = (fingerprint, delegated) => ({ fingerprint, selfStake: '1000000000000000', delegated, commissionBps: 500, status: 0 });
  return {
    // chain names
    async nameOf() { return { found: chain.confirmed && chain.name, name: 'regname', committedHeight: '10' }; },
    async nameLookup() { return { found: false, committedHeight: '10' }; },
    async profileAddress() { throw new Error('Unexpected profile read.'); },
    async namePrices() { return { prices: ['100', '100', '100', '100'], scheduled: [] }; },
    async rulesetInfo() { return { generation: '2', tip: '10', gen2Height: '0' }; },
    async nameBuild(request) { return { envelope: Uint8Array.of(1, 2), intentId: intent, decoded: { name: request.name, owner: address,
      chainId: '12'.repeat(32), inputs: [input], price: '100', fee: '1', change: (COIN - 101n).toString(), expiryHeight: request.expiryHeight } }; },
    // staking: the validator list grows when the delegation is included
    stakingRules: { minDelegation: '10000000000', selfStake: '1000000000000000', commissionMaxBps: '5000', undelegateLockEpochs: '12', epochLength: '720', maxDelegators: '2048' },
    async validators() { return { validators: chain.confirmed && chain.stake ? [validator(VALIDATOR, '0'), validator(SECOND, '0')] : [validator(VALIDATOR, '0')], truncated: false }; },
    async delegations() { return []; },
    async balance() { return { total: COIN.toString(), spendable: COIN.toString() }; },
    async list() { return { tip: '10', coins: [{ nullifier: input, amount: COIN.toString() }], truncated: false }; },
    async stakeBuild(request) { return { envelope: Uint8Array.of(7, 7), intentId: intent, decoded: { op: request.op, validator: request.validator, validatorId: '',
      amount: request.amount, commissionBps: request.commissionBps, fee: '1', change: (COIN - BigInt(request.amount) - 1n).toString(),
      expiryHeight: request.expiryHeight, chainId: '12'.repeat(32), inputs: request.coins.map(coin => coin.nullifier) } }; },
    // claim
    async claimStatus() { return { found: true, amount: '500000000', tip: '10', startHeight: '0', endHeight: '18446744073709551615', window: 'open',
      claimed: chain.confirmed && chain.claim ? 'yes' : 'no-evidence', outputId: '77'.repeat(64) }; },
    async claimBuild() { return { bytes: Uint8Array.of(9, 8, 7), claimId: '66'.repeat(64), decoded: { recipient: address, amount: '500000000', chainId: '12'.repeat(32),
      nullifier: '55'.repeat(64), outputId: '77'.repeat(64), leafIndex: '0' } }; },
    async claimSubmit() { return { accepted: true }; },
    // the activity tracker: a row is found in a block only after the chain commits it
    async scanConfirm({ intentId }) { scans.push(intentId); return chain.confirmed ? { found: true, tip: '11', height: '11' } : { found: false, tip: '10' }; },
  };
}

// The unlocked background session of fixtures/wallet-session.js (same construction), with the background's
// onStateChanged callback counted: it is what posts walletStateChanged to every open page (background/index.js).
// The mocked timers are enabled BEFORE the session starts, as in nodus-background.test.js: the tracker starts at unlock and
// schedules its next pass with setTimeout, so a mock enabled later would never fire it.
async function startSession(t, module, saved) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const values = { [VAULT_KEY]: await encryptVault(phrase, password) }, id = parseVault(values[VAULT_KEY]).id;
  const wallet = deriveWallet(phrase), addresses = { ...wallet.addresses, nodus: address };
  const storage = { async get(keys) { return keys === null ? structuredClone(values) : Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, values[key]])); },
    async set(items) { Object.assign(values, structuredClone(items)); }, async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; } };
  const published = { count: 0 };
  const fullModule = { memory: { buffer: new ArrayBuffer(256) }, async unlock() { return { fingerprint: address, chainId: '12'.repeat(32) }; },
    async identify() { return { fingerprint: address, chainId: '12'.repeat(32) }; }, async connectNetwork() {},
    async buildAndSign() { throw new Error('Unexpected fixture build.'); }, async submit() { return { accepted: true }; },
    async tick() {}, cancel() {}, lock() {}, release() {}, ...module };
  const lockCoordinator = createLockCoordinator();
  const nodus = createNodus({ storage, lockCoordinator, getAddresses: () => addresses, factory: async () => fullModule, getWords: () => phrase,
    onStateChanged() { published.count++; } });
  if (saved) values[ACTIVITY_KEY] = await serializeActivity(id, saved, await activityKeyFor(phrase, id));
  await lockCoordinator.unlock(() => nodus.consumeNodusSeed(nodusSigningSeed(phrase), { phrase, id, addresses,
    nodusWasmBytes: readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url)) }));
  nodus.startNetwork();
  for (let turns = 0; nodus.getState().state !== 'ready'; turns++) { assert.ok(turns < 5000, 'fixture connection never became ready'); await new Promise(resolve => setImmediate(resolve)); }
  t.after(async () => { await lockCoordinator.lock(); disposeWallet(wallet); });
  return { nodus, published };
}

// rows: saved activity records of this wallet that exist before the wallet opens (still pending).
async function openWallet(t, { rows = [], what } = {}) {
  const chain = { confirmed: false, name: what === 'name', stake: what === 'stake', claim: what === 'claim' }, scans = [];
  const { nodus, published } = await startSession(t, chainModule(chain, scans), rows.length ? rows : undefined);
  const calls = [], pending = new Set(), nodes = new Map(), node = id => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); };
  const ui = { state: { addresses: { nodus: address }, nodus: nodus.getState(), nodusSettled: nodus.getSettled() },
    // Every screen request is kept until it answers: some answers take real time (getOwnName saves the name, encrypted,
    // before it answers), so the tests wait for the requests themselves instead of a fixed number of turns.
    async request(method, args = []) { calls.push(method); const answer = Promise.resolve().then(() => nodus[method](...args)); pending.add(answer);
      try { return await answer; } finally { pending.delete(answer); } },
    cancelNodusSend: id => nodus.cancelSend(id) };
  const root = { querySelector: selector => node(selector.slice(1)) }, run = action => action(), selected = () => 'nodus';
  const names = mountNameBlock({ root, ui, selected, run, showReview: () => assert.fail('No review is shown here.') });
  const earn = mountEarn({ root, document: { createElement: () => new Node() }, ui, selected, portfolio: { setEarn() {} }, run, showReview: () => assert.fail('No review is shown here.'), navigate() {} });
  let action = 'unset';
  const claim = mountClaimAction({ ui, portfolio: { setAction(_chain, value) { action = value; } }, run, showReview: () => assert.fail('No review is shown here.') });
  // What the background's getState carries (background/index.js): `nodus`, and the settled counts as their own top-level field.
  const sync = async () => { ui.state.nodus = nodus.getState(); ui.state.nodusSettled = nodus.getSettled(); names.update(); earn.update(); claim.update(); await drain(); };
  // One tracker pass: the mocked 12 s timer fires, the tracker finishes, then the screen takes the new public state.
  // Waits until no screen request is still answering, then lets the screens write the answers.
  const drain = async () => { await settle(); while (pending.size) { await Promise.allSettled([...pending]); await settle(); } };
  const pass = async () => { await settle(); t.mock.timers.tick(12000); await settle(); await sync(); };
  const count = method => calls.filter(name => name === method).length;
  return { nodus, published, chain, scans, ui, calls, node, names, earn, claim, sync, pass, drain, count, action: () => action };
}

const savedRow = changes => ({ chain: 'nodus', address, to: 'ab'.repeat(64), symbol: 'NODUS', amount: '1.0', hash: '01'.repeat(64),
  createdAt: '2026-10-28T00:00:00.000Z', status: 'pending', expiryHeight: '100', fromHeight: '1', inputs: ['aa'.repeat(64)], ...changes });

// Proves the reported defect is gone: after the registration is confirmed, the open screen still says "no chain name yet"
// (the first read found the transaction only in the mempool); when the chain commits the name, the transaction turns
// final and the same open screen (no reopen, no reconnect) reads the name once and shows it with the registration
// fields hidden, and does not read again on later passes. Could falsely pass if the name came from the confirm-time read:
// the mempool answer is asserted first, and the read count is asserted exactly.
test('a name registration turning final updates the open screen once', async t => {
  const w = await openWallet(t, { what: 'name' });
  await w.sync();
  assert.equal(w.count('getOwnName'), 1);
  assert.match(w.node('own-name').textContent, /no chain name yet/); assert.equal(w.node('name-fields').hidden, false);
  const review = await w.ui.request('prepareName', ['regname']);
  await w.nodus.confirmSend(review.id); w.names.sent(); await w.drain();
  assert.equal(w.count('getOwnName'), 2, 'the confirm-time read');
  assert.match(w.node('own-name').textContent, /no chain name yet/, 'the name is only in the mempool at that time');
  w.chain.confirmed = true;
  await w.pass();
  assert.equal(w.count('getOwnName'), 3, 'the final status causes one more read');
  assert.match(w.node('own-name').textContent, /^Your chain name is "regname"/);
  assert.equal(w.node('wallet-title').textContent, 'Welcome back, regname');
  assert.equal(w.node('name-fields').hidden, true);
  await w.pass(); await w.pass();
  assert.equal(w.count('getOwnName'), 3, 'once, not on every later pass');
});

// Proves a Nodus delegation turning final makes the open earn page read the staking overview once and show the new list.
// Could falsely pass if the page re-read for its own reasons: the confirm-time read is asserted, then the list is still
// the old one until the chain commits.
test('a staking transaction turning final updates the open earn page once', async t => {
  const w = await openWallet(t, { what: 'stake' });
  await w.sync();
  assert.equal(w.count('getStakingOverview'), 1); assert.equal(w.node('validator-list').children.length, 1);
  const review = await w.ui.request('prepareStake', ['delegate', { validator: VALIDATOR, amount: '100' }]);
  await w.nodus.confirmSend(review.id); w.earn.sent(); await w.drain();
  assert.equal(w.count('getStakingOverview'), 2, 'the confirm-time read');
  assert.equal(w.node('validator-list').children.length, 1, 'still the old list in the mempool');
  const before = w.count('getStakingOverview');
  w.chain.confirmed = true;
  await w.pass();
  assert.equal(w.count('getStakingOverview'), before + 1, 'the final status causes one more read');
  assert.equal(w.node('validator-list').children.length, 2, 'the page shows the new list');
  await w.pass(); await w.pass();
  assert.equal(w.count('getStakingOverview'), before + 1, 'once, not on every later pass');
});

// Proves a claim row turning final makes the claim block read the claim status once, and that the staking and name reads
// do not run for it (src/app.js:660-667 chooses one branch). Could falsely pass if no claim row were tracked: the scan of
// the claim's hash is asserted, and the claim read count is exact.
test('a claim turning final re-reads only the claim status', async t => {
  const w = await openWallet(t, { what: 'claim' });
  await w.sync();
  const review = await w.ui.request('prepareClaim');
  await w.nodus.confirmSend(review.id); await w.claim.refresh(); await w.drain();
  // The tracker checks the new record on its next 12 s pass (it was started at unlock); the chain has not committed it yet.
  await w.pass();
  // A claim record's hash is the output id it creates (src/adapters/nodus.js prepareClaim onBroadcast: hash: d.outputId), not the claim id.
  assert.ok(w.scans.includes('77'.repeat(64)), 'the tracker scanned the claim record');
  const before = { claim: w.count('getClaimStatus'), name: w.count('getOwnName'), stake: w.count('getStakingOverview') };
  w.chain.confirmed = true;
  await w.pass();
  assert.equal(w.count('getClaimStatus'), before.claim + 1, 'the final claim causes one claim read');
  assert.equal(w.count('getOwnName'), before.name, 'no name read for a claim');
  assert.equal(w.count('getStakingOverview'), before.stake, 'no staking read for a claim');
  await w.pass();
  assert.equal(w.count('getClaimStatus'), before.claim + 1, 'once, not on every later pass');
});

// Proves no re-read without a transition: a saved record the tracker checks and finds still pending changes nothing on the
// open screen over several passes; when it then becomes final, the name and staking re-reads happen exactly once each
// (claim block untouched, a plain send is not a claim), and a record that is already final causes nothing on later passes.
// (A record saved as confirmed cannot be the "already final" fixture: it is loaded as pending and verified again after
// unlock, src/activity-storage.js savedStatus, so its confirmation is a transition like the web wallet's.) Could falsely
// pass if the tracker never started: the scans are asserted, and the final step shows the counters can move.
test('no re-read happens without a non-final to final transition', async t => {
  const pending = savedRow({ hash: '02'.repeat(64), inputs: ['bb'.repeat(64)] });
  const w = await openWallet(t, { rows: [pending] });
  await w.sync(); await w.nodus.getBalances(); await w.drain();
  const base = { name: w.count('getOwnName'), stake: w.count('getStakingOverview'), claim: w.count('getClaimStatus') };
  assert.ok(base.name >= 1 && base.stake >= 1, 'the screen read once when it opened');
  await w.pass(); await w.pass();
  assert.ok(w.scans.length >= 1, 'the tracker ran');
  assert.ok(w.scans.every(hash => hash === pending.hash), 'only the saved record was scanned');
  assert.deepEqual({ name: w.count('getOwnName'), stake: w.count('getStakingOverview'), claim: w.count('getClaimStatus') }, base, 'still pending: no re-read');
  w.chain.confirmed = true;
  await w.pass();
  assert.equal(w.count('getOwnName'), base.name + 1); assert.equal(w.count('getStakingOverview'), base.stake + 1);
  assert.equal(w.count('getClaimStatus'), base.claim, 'a plain Nodus send is not a claim');
  const scanned = w.scans.length;
  await w.pass(); await w.pass();
  assert.equal(w.scans.length, scanned, 'a final record is not scanned again');
  assert.equal(w.count('getOwnName'), base.name + 1); assert.equal(w.count('getStakingOverview'), base.stake + 1);
});

// Proves how the open pages learn of it: a settle publishes exactly one state invalidation (the background's onStateChanged,
// which posts walletStateChanged to every open page, background/index.js), and none while the record stays pending; the
// counts are their own value (getSettled, a top-level field of the background's getState) and `state.nodus` is byte-for-byte
// unchanged by it, because a change of state.nodus makes the popup clear every chain's cached balances (wallet-ui.js refresh
// identity). Could falsely pass if the pass never settled the record: the count 1 is asserted, and the same session's earlier
// passes show the counter does not move without a settle.
test('a settle publishes one state invalidation and leaves state.nodus unchanged', async t => {
  const w = await openWallet(t, { rows: [savedRow({ hash: '02'.repeat(64), inputs: ['bb'.repeat(64)] })] });
  await w.sync(); await w.drain();
  await w.pass(); await w.pass();
  assert.deepEqual(w.nodus.getSettled(), { claim: 0, other: 0 });
  const published = w.published.count, before = JSON.stringify(w.nodus.getState());
  await w.pass();
  assert.equal(w.published.count, published, 'a still pending record publishes nothing');
  w.chain.confirmed = true;
  await w.pass();
  assert.deepEqual(w.nodus.getSettled(), { claim: 0, other: 1 });
  assert.equal(w.published.count, published + 1, 'one invalidation for the one settle');
  assert.equal(JSON.stringify(w.nodus.getState()), before, 'state.nodus does not carry the count');
});
