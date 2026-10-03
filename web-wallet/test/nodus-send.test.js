// NODUS send skeleton (package (d)) against the TEST-ONLY mock module
// (test/nodus-mock-module.js). Proves the wallet-side rules; says nothing about
// the real (c3) module, the chain, or the browser UI wiring in src/app.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusClient, NODUS_TICK_MS } from '../src/nodus/client.js';
import { nodusSendModuleFactory } from '../src/nodus/send-module.js';
import { NODUS_NETWORK, nodusNetworkFor } from '../src/nodus/network.js';
import { prepareTransfer } from '../src/wallet.js';
import { recordActivity, watchActivity, submissionStatus, terminal } from '../src/activity.js';
import { serializeActivity, parseActivity, activityKeyFor } from '../src/activity-storage.js';
import { expiryHeightFor, lockedInputs, resendInputs, balances, checkNodusActivity, nodusRecipient, nodusAmountUnits, NODUS_EXPIRY_AHEAD, claimStatus, prepareClaim, isClaimRow, stakingOverview, prepareStake } from '../src/adapters/nodus.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, CHAIN_ID, INTENT_ID, FEE, coin } from './nodus-mock-module.js';

const settle = () => new Promise(resolve => setImmediate(resolve));
async function readyClient() {
  const mock = createMockNodusModule(), timers = { cleared: [] }, states = [];
  const client = createNodusClient({
    factory: mock.factory, onState: state => states.push(state),
    setInterval: (fn, ms) => { timers.fn = fn; timers.ms = ms; return 7; }, clearInterval: id => timers.cleared.push(id)
  });
  const seed = new Uint8Array(32).fill(5);
  const info = await client.unlock({ seed, fingerprint: FINGERPRINT });
  return { mock, client, seed, info, timers, states };
}
const walletFor = client => ({ addresses: { nodus: FINGERPRINT }, nodusClient: client });

test('without a ready send module NODUS stays exactly as before: receive-only, no balance, no send', async () => {
  assert.equal(typeof nodusSendModuleFactory, 'function'); // shipped: testnet settings (send-module.js)
  assert.equal(nodusNetworkFor(false), NODUS_NETWORK);
  assert.equal(nodusNetworkFor(undefined), NODUS_NETWORK);
  // with a send module in the build, the not-ready entry says it is connecting
  const connecting = nodusNetworkFor(false, { module: true });
  assert.equal(connecting.receiveOnly, true); assert.equal(connecting.balanceUnavailable, true);
  assert.match(connecting.sendNote, /^Connecting to the Nodus network/);
  assert.equal(nodusNetworkFor(false, { module: true }), connecting);
  assert.equal(nodusNetworkFor(true, { module: true }), nodusNetworkFor(true));
  assert.equal(NODUS_NETWORK.receiveOnly, true); assert.equal(NODUS_NETWORK.balanceUnavailable, true);
  const ready = nodusNetworkFor(true);
  assert.equal(ready.receiveOnly, false); assert.equal(ready.balanceUnavailable, false); assert.equal(ready.sendNote, undefined);
  assert.equal(ready.endpoint, undefined); assert.equal(ready.rpcOptions, undefined);
  assert.throws(() => createNodusClient({ factory: null }), /not available/);
  // No client on the wallet: the adapter refuses before any network step.
  await assert.rejects(prepareTransfer({ wallet: { addresses: { nodus: FINGERPRINT } }, chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1' }), /not available right now/);
});

test('unlock checks the module identity, wipes the JS seed and starts a 60 s keepalive', async () => {
  const { mock, client, seed, info, timers, states } = await readyClient();
  assert.deepEqual(info, { fingerprint: FINGERPRINT, chainId: CHAIN_ID });
  assert.equal(client.state, 'ready'); assert.deepEqual(states, ['connecting', 'ready']);
  assert.ok(seed.every(b => b === 0), 'JS copy of the seed is zeroed after unlock');
  assert.equal(timers.ms, NODUS_TICK_MS); assert.equal(NODUS_TICK_MS, 60000);
  timers.fn(); await settle();
  assert.deepEqual(mock.log.filter(entry => entry.startsWith('tick')), ['tick:start', 'tick:end']);
  // A second unlock on a ready client is refused without touching the session.
  const again = new Uint8Array(32).fill(4);
  await assert.rejects(client.unlock({ seed: again, fingerprint: FINGERPRINT }), /already used/);
  assert.equal(client.state, 'ready'); assert.ok(again.every(b => b === 0)); assert.ok(!mock.log.includes('cancel'));
  // A module that derives another identity is wiped and never becomes ready.
  const other = createMockNodusModule(); other.state.fingerprint = 'cd'.repeat(64);
  const client2 = createNodusClient({ factory: other.factory, setInterval: () => 1, clearInterval: () => {} });
  const seed2 = new Uint8Array(32).fill(9);
  await assert.rejects(client2.unlock({ seed: seed2, fingerprint: FINGERPRINT }), /different address/);
  assert.equal(client2.state, 'error'); assert.ok(seed2.every(b => b === 0));
  assert.deepEqual(other.log.slice(-3), ['cancel', 'lock', 'release']); assert.equal(other.state.zeroAtRelease, true);
  await assert.rejects(client2.balance(), /not ready/);
  // A factory result without the contract is refused and wiped too.
  const broken = createNodusClient({ factory: async () => ({ memory: new WebAssembly.Memory({ initial: 1 }) }), setInterval: () => 1, clearInterval: () => {} });
  await assert.rejects(broken.unlock({ seed: new Uint8Array(32), fingerprint: FINGERPRINT }), /does not match this wallet version/);
  await assert.rejects(createNodusClient({ factory: mock.factory }).unlock({ seed: new Uint8Array(31), fingerprint: FINGERPRINT }), /32 bytes/);
  client.lock();
});

test('one operation queue: a second call never enters the module while the first is running', async () => {
  const { mock, client, timers } = await readyClient();
  const open = mock.gate('balance');
  const first = client.balance(), second = client.list();
  timers.fn(); timers.fn(); // two keepalives while busy: only one is queued
  await settle();
  // mock.log[0..1] is the unlock call.
  assert.deepEqual(mock.log.slice(2), ['balance:start'], 'list and tick wait for balance to return');
  open();
  await first; await second; await settle();
  assert.deepEqual(mock.log.slice(2), ['balance:start', 'balance:end', 'list:start', 'list:end', 'tick:start', 'tick:end']);
  assert.equal(mock.state.overlap, false);
  // A caller that gives up before its call started leaves the queue; the
  // module still finishes a started call before the next one enters.
  const openBuild = mock.gate('balance');
  const controller = new AbortController();
  const running = client.balance();
  const skipped = client.list({ signal: controller.signal });
  controller.abort();
  await assert.rejects(skipped, /cancelled/);
  const after = client.list();
  await settle();
  assert.equal(mock.log.at(-1), 'balance:start');
  openBuild(); await running; await after;
  assert.deepEqual(mock.log.slice(-4), ['balance:start', 'balance:end', 'list:start', 'list:end']);
  assert.equal(mock.state.overlap, false);
  // A failed keepalive (session gone) takes the client out of 'ready'.
  mock.state.tickFails = true; timers.fn(); await settle();
  assert.equal(client.state, 'error');
  client.lock();
});

test('lock order: queue stopped -> cancel flag -> socket closed -> memory zeroed -> released', async () => {
  const { mock, client, timers, states } = await readyClient();
  mock.gate('balance'); // never opened: the call stays suspended
  const inFlight = client.balance(), queued = client.list();
  await settle();
  const before = mock.log.length;
  client.lock();
  assert.deepEqual(mock.log.slice(before), ['cancel', 'lock', 'release']);
  assert.equal(mock.state.seedAtLock, true, 'secret still in module memory when lock() runs');
  assert.equal(mock.state.zeroAtRelease, true, 'whole linear memory zeroed before release()');
  await assert.rejects(inFlight, /locked/); await assert.rejects(queued, /locked/);
  assert.ok(!mock.log.includes('list:start'), 'a queued call never reaches the module');
  assert.deepEqual(timers.cleared, [7]); assert.equal(client.state, 'locked'); assert.equal(states.at(-1), 'locked');
  await assert.rejects(client.balance(), /not ready/);
  // A throwing step never skips the wipe.
  const second = await readyClient();
  second.mock.state.failCancel = true; second.client.lock();
  assert.deepEqual(second.mock.log.slice(-3), ['cancel', 'lock', 'release']); assert.equal(second.mock.state.zeroAtRelease, true);
  // Locked while the module was still loading: wiped and dropped unused.
  const slow = createMockNodusModule(); let loaded;
  const pendingLoad = new Promise(resolve => { loaded = resolve; });
  const client3 = createNodusClient({ factory: () => pendingLoad, setInterval: () => 1, clearInterval: () => {} });
  const unlocking = client3.unlock({ seed: new Uint8Array(32).fill(1), fingerprint: FINGERPRINT });
  client3.lock(); loaded(slow.module);
  await assert.rejects(unlocking, /locked/);
  assert.deepEqual(slow.log, ['cancel', 'lock', 'release']); assert.equal(slow.state.zeroAtRelease, true);
});

// LOCAL FIRST (identify / connectNetwork): the client's state machine.
// Against the mock module: proves the JS gates and the queue, not the C
// side (nodus-send-wasm.c nsw_identify / nsw_connect, nc_wasm.c session_ok).
test('local first: identify builds the identity only; network calls wait for connectNetwork; local Messages calls run at once', async () => {
  const mock = createMockNodusModule(), states = [], timers = {};
  const client = createNodusClient({
    factory: mock.factory, onState: state => states.push(state),
    setInterval: (fn, ms) => { timers.fn = fn; timers.ms = ms; return 7; }, clearInterval: () => {}
  });
  assert.equal(client.identified, false); assert.equal(client.localConnectable, false);
  await assert.rejects(client.connectNetwork(), /not ready/);
  const seed = new Uint8Array(32).fill(5);
  assert.deepEqual(await client.identify({ seed, fingerprint: FINGERPRINT }), { fingerprint: FINGERPRINT, chainId: CHAIN_ID });
  assert.deepEqual(states, ['identifying', 'identified']);
  assert.ok(seed.every(b => b === 0), 'JS copy of the seed is zeroed after identify');
  assert.equal(client.identified, true); assert.equal(client.localConnectable, true); assert.equal(client.connectable, false);
  assert.equal(client.fingerprint, FINGERPRINT);
  assert.equal(mock.state.connected, false, 'identify opens no session');
  assert.equal(timers.fn, undefined, 'no keepalive before the session');
  // Network operations (Messages' connect included) refuse before the session.
  await assert.rejects(client.balance(), /not ready/);
  await assert.rejects(client.connect(() => 'net'), /not ready/);
  // The local Messages slot runs in the same queue.
  assert.equal(await client.connectLocal(() => 'local'), 'local');
  await assert.rejects(client.connectLocal('not a function'), /Invalid Messages operation/);
  await client.connectNetwork();
  assert.equal(client.state, 'ready'); assert.deepEqual(states, ['identifying', 'identified', 'connecting', 'ready']);
  assert.equal(timers.ms, NODUS_TICK_MS);
  assert.deepEqual(await client.balance(), { total: '450000000', spendable: '450000000' });
  assert.equal(await client.connect(() => 'net'), 'net');
  await client.connectNetwork(); // already ready: nothing more is sent
  assert.equal(mock.log.filter(entry => entry === 'connectNetwork:start').length, 1);
  // Used once: neither unlock nor identify runs again.
  await assert.rejects(client.unlock({ seed: new Uint8Array(32).fill(1), fingerprint: FINGERPRINT }), /already used/);
  await assert.rejects(client.identify({ seed: new Uint8Array(32).fill(1), fingerprint: FINGERPRINT }), /already used/);
  client.lock();
  assert.equal(client.identified, false); assert.equal(client.localConnectable, false);
});

test('local first: a failed connection keeps the identity and is tried again on the same client; a final refusal locks', async () => {
  const mock = createMockNodusModule(), states = [];
  mock.state.connectErrors.push(new Error('Could not open a verified connection to any Nodus node.'));
  const client = createNodusClient({ factory: mock.factory, onState: state => states.push(state), setInterval: () => 1, clearInterval: () => {} });
  await client.identify({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  await assert.rejects(client.connectNetwork(), /verified connection/);
  assert.equal(client.state, 'identified'); assert.equal(client.identified, true);
  assert.ok(!mock.log.includes('lock') && !mock.log.includes('cancel'), 'a failure that may be retried wipes nothing');
  assert.equal(await client.connectLocal(() => 'kept'), 'kept');
  // Two callers during one attempt share it: one connectNetwork reaches the module.
  const first = client.connectNetwork(), second = client.connectNetwork();
  assert.equal(first, second);
  await first;
  assert.equal(client.state, 'ready');
  assert.deepEqual(states, ['identifying', 'identified', 'connecting', 'identified', 'connecting', 'ready']);
  assert.equal(mock.log.filter(entry => entry === 'connectNetwork:start').length, 2);
  client.lock();

  // A node of another chain: final — the client locks itself (wipe order as lock()).
  const other = createMockNodusModule();
  other.state.connectErrors.push(Object.assign(new Error('This Nodus node is on a different chain. Nothing was done.'), { final: true }));
  const client2 = createNodusClient({ factory: other.factory, setInterval: () => 1, clearInterval: () => {} });
  await client2.identify({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  await assert.rejects(client2.connectNetwork(), /different chain/);
  assert.equal(client2.state, 'error'); assert.equal(client2.identified, false);
  assert.deepEqual(other.log.slice(-3), ['cancel', 'lock', 'release']); assert.equal(other.state.zeroAtRelease, true);
  await assert.rejects(client2.connectNetwork(), /locked/);
  await assert.rejects(client2.connectLocal(() => 1), /locked/);
});

test('local first: lock while identified or while connecting wipes the module; identify refuses a module without the split', async () => {
  const mock = createMockNodusModule();
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await client.identify({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  mock.gate('connectNetwork'); // never opened: the attempt stays suspended
  const attempt = client.connectNetwork(), local = client.connectLocal(() => 'queued');
  await settle();
  const before = mock.log.length;
  client.lock();
  assert.deepEqual(mock.log.slice(before), ['cancel', 'lock', 'release']);
  assert.equal(mock.state.zeroAtRelease, true);
  await assert.rejects(attempt, /locked/); await assert.rejects(local, /locked/);
  assert.ok(!mock.log.includes('connect:start'), 'a queued local call never reaches the module');
  assert.equal(client.state, 'locked'); assert.equal(client.identified, false);

  // A module without identify / connectNetwork still unlocks (unlock()), but
  // identify is refused and wiped.
  const plain = createMockNodusModule();
  delete plain.module.identify; delete plain.module.connectNetwork;
  const client2 = createNodusClient({ factory: plain.factory, setInterval: () => 1, clearInterval: () => {} });
  const seed = new Uint8Array(32).fill(3);
  await assert.rejects(client2.identify({ seed, fingerprint: FINGERPRINT }), /does not match this wallet version/);
  assert.equal(client2.state, 'error'); assert.ok(seed.every(b => b === 0));
  assert.deepEqual(plain.log.slice(-3), ['cancel', 'lock', 'release']);
  const plain2 = createMockNodusModule();
  delete plain2.module.identify; delete plain2.module.connectNetwork;
  const client3 = createNodusClient({ factory: plain2.factory, setInterval: () => 1, clearInterval: () => {} });
  assert.deepEqual(await client3.unlock({ seed: new Uint8Array(32).fill(3), fingerprint: FINGERPRINT }), { fingerprint: FINGERPRINT, chainId: CHAIN_ID });
  assert.equal(client3.state, 'ready');
  client3.lock();
});

test('expiry = tip + 90; tip 0 or unknown refuses before anything is built', async () => {
  assert.equal(NODUS_EXPIRY_AHEAD, 90n);
  const gen1 = { generation: 1n, tip: 0n, gen2Height: 0n };
  assert.equal(expiryHeightFor(1000n, gen1), 1090n); assert.equal(expiryHeightFor(1n, gen1), 91n);
  for (const tip of [0n, undefined, null, 1000, '1000']) assert.throws(() => expiryHeightFor(tip, gen1), /height is unknown/);
  // The network's rules are required (HF-4): no ruleset answer, no expiry.
  assert.throws(() => expiryHeightFor(1000n), /rules are unknown/);
  for (const tip of ['0', undefined]) {
    const { mock, client } = await readyClient();
    mock.state.tip = tip;
    await assert.rejects(prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1' }), /height is unknown/);
    assert.ok(!mock.log.includes('buildAndSign:start'), `tip ${tip}: nothing built`);
    client.lock();
  }
  const { mock, client } = await readyClient();
  mock.state.tip = '-1';
  await assert.rejects(prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1' }), /invalid block height/);
  // An empty coin list with a positive spendable balance is a read failure, not "insufficient".
  mock.state.tip = '1000'; mock.state.coins = [];
  await assert.rejects(prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1' }), /coin list could not be read/);
  client.lock();
});

test('recipient and amount input rules: 128-hex fingerprint, 8 decimals, BigInt within uint64', () => {
  assert.equal(nodusRecipient(` ${RECIPIENT.toUpperCase()} `), RECIPIENT);
  for (const bad of [RECIPIENT.slice(1), RECIPIENT + '0', 'g'.repeat(128), '0x' + RECIPIENT.slice(2), '', undefined]) assert.throws(() => nodusRecipient(bad), /128 characters/);
  assert.equal(nodusAmountUnits('1.5'), 150000000n); assert.equal(nodusAmountUnits('0.00000001'), 1n);
  assert.equal(nodusAmountUnits('184467440737.09551615'), 2n ** 64n - 1n);
  assert.throws(() => nodusAmountUnits('184467440737.09551616'), /out of range/);
  for (const bad of ['0', '1.000000001', '-1', '1e3', '.5']) assert.throws(() => nodusAmountUnits(bad));
});

test('G1: the review shows what the module decoded from the signed envelope, never the form', async () => {
  const { mock, client } = await readyClient();
  const transfer = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT.toUpperCase(), amount: '1.50000000' });
  assert.equal(transfer.to, RECIPIENT); assert.equal(transfer.amount, '1.5'); assert.equal(transfer.from, FINGERPRINT);
  const review = Object.fromEntries(transfer.review);
  assert.equal(review.To, RECIPIENT); assert.equal(review.Amount, '1.5 NODUS');
  assert.equal(review['Network fee'], '0.00001 NODUS');
  // 2 NODUS in (the largest coin, 3 NODUS, alone) - 1.5 - fee.
  assert.equal(review['Change back to you'], '1.49999 NODUS');
  assert.equal(review['Valid until block'], '1090'); assert.equal(review['Chain ID'], CHAIN_ID);
  assert.match(review['Address check'], /128 characters/);
  assert.match(review['Fee note'], /may be charged even if the transfer fails/);
  assert.deepEqual(mock.state.lastBuild, { to: RECIPIENT, amount: '150000000', expiryHeight: '1090', coins: mock.state.coins });
  transfer.cancel();
  // Any mismatch between request and signed envelope stops before review.
  for (const [tamper, pattern] of [
    [{ amount: '150000001' }, /does not match your request/], [{ recipient: 'ef'.repeat(64) }, /does not match your request/],
    [{ expiryHeight: '1091' }, /does not match your request/], [{ chainId: 'd'.repeat(64) }, /does not match your request/],
    [{ inputs: ['7'.repeat(128)] }, /coins it may not use/], [{ fee: '1.5' }, /invalid network fee/], [{ inputs: [] }, /invalid transaction/]
  ]) {
    mock.state.tamper = tamper;
    await assert.rejects(prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1.5' }), pattern, JSON.stringify(tamper));
  }
  assert.ok(!mock.log.includes('submit:start'), 'nothing was submitted');
  client.lock();
});

test('pending send: record is durable before submit, keeps intent_id / expiry / inputs through storage', async () => {
  const { mock, client } = await readyClient();
  const transfer = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1.5' });
  let record;
  const hash = await transfer.confirm(async details => {
    assert.ok(!mock.log.includes('submit:start'), 'record written before the envelope leaves');
    record = recordActivity(transfer, details);
  });
  assert.equal(hash, INTENT_ID); assert.deepEqual(mock.state.submitted, Uint8Array.of(1, 2, 3));
  assert.equal(record.hash, INTENT_ID); assert.equal(record.expiryHeight, '1090'); assert.equal(record.fromHeight, '1001');
  assert.deepEqual(record.inputs, [coin(2, '300000000').nullifier]); assert.equal(record.to, RECIPIENT); assert.equal(record.amount, '1.5');
  await assert.rejects(transfer.confirm(async () => {}), /already closed/);
  // Round trip through the encrypted activity envelope.
  const phrase = 'abandon '.repeat(23) + 'art', id = btoa(String.fromCharCode(...new Uint8Array(16).fill(3)));
  const key = await activityKeyFor(phrase, id);
  const saved = await serializeActivity(id, [record], key);
  for (const addresses of [{}, { nodus: FINGERPRINT }]) {
    const [row] = await parseActivity(saved, id, addresses, key);
    assert.deepEqual({ hash: row.hash, expiryHeight: row.expiryHeight, fromHeight: row.fromHeight, inputs: row.inputs, status: row.status, endpoint: row.endpoint }, { hash: INTENT_ID, expiryHeight: '1090', fromHeight: '1001', inputs: record.inputs, status: 'pending', endpoint: undefined });
  }
  await assert.rejects(parseActivity(saved, id, { nodus: 'ef'.repeat(64) }, key), /Invalid saved activity/);
  const broken = await serializeActivity(id, [{ ...record, inputs: [] }], key);
  await assert.rejects(parseActivity(broken, id, {}, key), /Invalid saved activity/);
  assert.throws(() => recordActivity(transfer, { hash: INTENT_ID, expiryHeight: '0', fromHeight: '1', inputs: record.inputs }), /Invalid pending/);
  assert.throws(() => recordActivity(transfer, { hash: '0x' + 'a'.repeat(64) }), /Invalid transaction identifier/);
  // A rejected submission is reported after the record exists (coins stay held).
  mock.state.accepted = false;
  const refused = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1.5' });
  let recorded = false;
  await assert.rejects(refused.confirm(async () => { recorded = true; }), /did not accept/);
  assert.equal(recorded, true);
  client.lock();
});

test('resend rule: pending coins stay locked until a scan shows the send expired', async () => {
  const pending = { chain: 'nodus', status: 'pending', inputs: [coin(2, '1').nullifier], expiryHeight: '1090', fromHeight: '1001', hash: INTENT_ID };
  const other = { chain: 'ethereum', status: 'pending', inputs: [coin(5, '1').nullifier] };
  for (const status of ['pending', 'unknown', 'included', 'abandoned', 'confirmed']) assert.deepEqual([...lockedInputs([{ ...pending, status }, other])], pending.inputs, status);
  assert.deepEqual([...lockedInputs([{ ...pending, status: 'expired' }])], []);
  assert.deepEqual(resendInputs(pending), pending.inputs);
  assert.equal(resendInputs({ ...pending, status: 'expired' }), null);
  assert.throws(() => resendInputs({ ...pending, status: 'confirmed' }), /already in the chain/);
  // A new send never offers locked coins to the builder.
  const { mock, client } = await readyClient();
  const locked = lockedInputs([pending]);
  const transfer = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1', nodusLocked: locked });
  assert.deepEqual(mock.state.lastBuild.coins.map(c => c.nullifier), [coin(1, '').nullifier, coin(3, '').nullifier]);
  transfer.cancel();
  // Every coin held by pending sends: refuse with the reason, build nothing.
  const builds = mock.log.filter(entry => entry === 'buildAndSign:start').length;
  await assert.rejects(prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to: RECIPIENT, amount: '1', nodusLocked: new Set(mock.state.coins.map(c => c.nullifier)) }), /held by a pending send/);
  assert.equal(mock.log.filter(entry => entry === 'buildAndSign:start').length, builds);
  client.lock();
});

test('confirmation scan: included / still pending / expired past its expiry block', async () => {
  const { mock, client } = await readyClient();
  const row = { chain: 'nodus', hash: INTENT_ID, fromHeight: '1001', expiryHeight: '1090', status: 'pending' };
  mock.state.scan = { tip: '1005', found: true, height: '1003' };
  const included = await checkNodusActivity(row, { client });
  assert.equal(included.status, 'confirmed'); assert.equal(included.block, '1003');
  assert.deepEqual(mock.state.lastScan, { intentId: INTENT_ID, fromHeight: '1001', toHeight: '1090' });
  mock.state.scan = { tip: '1090', found: false };
  assert.equal((await checkNodusActivity(row, { client })).status, 'pending');
  mock.state.scan = { tip: '1091', found: false };
  assert.equal((await checkNodusActivity(row, { client })).status, 'expired');
  mock.state.scan = { tip: '1200', found: true, height: '1091' };
  await assert.rejects(checkNodusActivity(row, { client }), /invalid status/);
  client.lock();
  await assert.rejects(checkNodusActivity(row, { client }), /not ready/);
});

// The status line after a submission (src/app.js followSubmission) is
// submissionStatus() over the record the tracker updates: it stays on the
// submission text while the scan finds nothing, says "confirmed at block N"
// only after the scan reported the intent included, and says "expired" once
// the tip passes the expiry block. The tracker stops checking a final record.
test('status line after a submission follows the tracker: pending, then confirmed at block N, or expired', async () => {
  const { mock, client } = await readyClient();
  const follow = async (scans) => {
    const row = { chain: 'nodus', hash: INTENT_ID, fromHeight: '1001', expiryHeight: '1090', status: 'pending', note: 'Broadcast submitted; awaiting confirmation.' };
    const lines = []; let checks = 0, stop;
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => { stop(); reject(new Error('the record never resolved')); }, 1000);
      stop = watchActivity(() => [row], () => {
        lines.push(submissionStatus(row, { what: 'Delegation', idLabel: 'Transaction ID' }));
        if (terminal(row.status)) { stop(); clearTimeout(deadline); resolve(); }
      }, { interval: 1, check: (record, options) => { mock.state.scan = scans[Math.min(checks++, scans.length - 1)]; return checkNodusActivity(record, { ...options, client }); } });
    });
    return { row, lines, checks };
  };
  const done = await follow([{ tip: '1002', found: false }, { tip: '1003', found: false }, { tip: '1004', found: true, height: '1003' }]);
  assert.deepEqual(done.lines.slice(0, 2), [null, null], 'no answer of inclusion: the submission text stays');
  assert.equal(done.lines[2], `Delegation confirmed at block 1003 (reported by one Nodus node). Transaction ID ${INTENT_ID}.`);
  assert.equal(done.checks, 3, 'a final record is not checked again');
  const gone = await follow([{ tip: '1050', found: false }, { tip: '1091', found: false }]);
  assert.equal(gone.lines[0], null);
  assert.match(gone.lines[1], /^Delegation expired\. Not included before block 1090; it can no longer be included/);
  assert.doesNotMatch(gone.lines.join(' '), /confirmed/);
  client.lock();
});

test('balance: spendable shown, a read failure is an error never a zero', async () => {
  const { mock, client } = await readyClient();
  mock.state.spendable = '150000000';
  assert.deepEqual(await balances('nodus', FINGERPRINT, undefined, { client }), [{ symbol: 'NODUS', balance: '1.5' }]);
  await assert.rejects(balances('nodus', 'ef'.repeat(64), undefined, { client }), /does not match/);
  mock.state.spendable = '500000000';
  await assert.rejects(balances('nodus', FINGERPRINT, undefined, { client }), /invalid balance/);
  mock.state.spendable = 0;
  await assert.rejects(balances('nodus', FINGERPRINT, undefined, { client }), /invalid balance/);
  client.lock();
  await assert.rejects(balances('nodus', FINGERPRINT, undefined, { client }), /not ready/);
});

// ── genesis claim (0.1.26) ─────────────────────────────────────────────
// The shared mock (test/nodus-mock-module.js) has no claim operations; these
// tests add them to its module object before unlock, with canned answers.
// They prove the wallet-side rules only (validation, fail-closed refusals,
// record-before-submit, tracking) — nothing about the C claim builder.
const OUTPUT_ID = '7'.repeat(128), CLAIM_ID = '6'.repeat(128), NULLIFIER = '5'.repeat(128);
async function claimClient({ withClaim = true } = {}) {
  const mock = createMockNodusModule();
  const claim = {
    status: { found: true, amount: '5000000000000000', tip: '1000', startHeight: '0', endHeight: '18446744073709551615', window: 'open', claimed: 'no-evidence', outputId: OUTPUT_ID },
    tamper: null, accepted: true, message: undefined, submitted: null
  };
  if (withClaim) Object.assign(mock.module, {
    claimStatus: () => { mock.log.push('claimStatus'); return Promise.resolve(claim.status); },
    claimBuild: () => {
      mock.log.push('claimBuild');
      const decoded = { recipient: FINGERPRINT, amount: claim.status.amount, chainId: CHAIN_ID, nullifier: NULLIFIER, outputId: OUTPUT_ID, leafIndex: '0' };
      return Promise.resolve({ bytes: Uint8Array.of(9, 8, 7), claimId: CLAIM_ID, decoded: { ...decoded, ...(claim.tamper || {}) } });
    },
    claimSubmit: ({ bytes }) => { mock.log.push('claimSubmit'); claim.submitted = bytes; return Promise.resolve({ accepted: claim.accepted, message: claim.message }); }
  });
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client, claim };
}

test('claim: a module without the claim operations still connects; every claim call is "not available"', async () => {
  const { client } = await claimClient({ withClaim: false });
  assert.equal(client.state, 'ready'); assert.equal(client.claimable, false);
  await assert.rejects(client.claimStatus(), /not available/);
  await assert.rejects(claimStatus({ client, from: FINGERPRINT }), /not available/);
  await assert.rejects(prepareClaim({ client, from: FINGERPRINT }), /not available/);
  client.lock();
});

test('claim status: parsed strictly; claimable only when found, open and not proven claimed', async () => {
  const { client, claim } = await claimClient();
  assert.equal(client.claimable, true);
  const status = await claimStatus({ client, from: FINGERPRINT });
  assert.equal(status.claimable, true); assert.equal(status.amount, 5000000000000000n); assert.equal(status.amountText, '50000000.0 NODUS');
  await assert.rejects(claimStatus({ client, from: 'ef'.repeat(64) }), /does not match/);
  for (const [change, claimable] of [[{ claimed: 'yes' }, false], [{ claimed: 'unknown' }, true], [{ window: 'not-open' }, false], [{ window: 'closed' }, false]]) {
    claim.status = { ...claim.status, claimed: 'no-evidence', window: 'open', ...change };
    assert.equal((await claimStatus({ client, from: FINGERPRINT })).claimable, claimable, JSON.stringify(change));
  }
  claim.status = { found: false };
  assert.deepEqual(await claimStatus({ client, from: FINGERPRINT }), { found: false, claimable: false, amountText: undefined });
  for (const bad of [{ found: true, amount: '0', tip: '1', startHeight: '0', endHeight: '1', window: 'open', claimed: 'yes', outputId: OUTPUT_ID },
    { found: true, amount: '1', tip: '1', startHeight: '5', endHeight: '1', window: 'open', claimed: 'yes', outputId: OUTPUT_ID },
    { found: true, amount: '1', tip: '1', startHeight: '0', endHeight: '1', window: 'later', claimed: 'yes', outputId: OUTPUT_ID },
    { found: true, amount: '1', tip: '1', startHeight: '0', endHeight: '1', window: 'open', claimed: 'maybe', outputId: OUTPUT_ID },
    { found: true, amount: '1', tip: '1', startHeight: '0', endHeight: '1', window: 'open', claimed: 'yes', outputId: 'x' }, null, {}]) {
    claim.status = bad;
    await assert.rejects(claimStatus({ client, from: FINGERPRINT }), /invalid/, JSON.stringify(bad));
  }
  client.lock();
});

test('claim: review from the decoded claim; any mismatch or a closed / claimed allocation builds or shows nothing', async () => {
  const { mock, client, claim } = await claimClient();
  const transfer = await prepareClaim({ client, from: FINGERPRINT });
  const review = Object.fromEntries(transfer.review);
  assert.equal(transfer.kind, 'claim'); assert.equal(transfer.to, FINGERPRINT); assert.equal(transfer.amount, '50000000.0'); assert.equal(transfer.symbol, 'NODUS');
  assert.equal(review.Amount, '50000000.0 NODUS'); assert.match(review['Paid to'], new RegExp(`^${FINGERPRINT}`)); assert.equal(review['Chain ID'], CHAIN_ID);
  assert.match(review.Note, /only once/);
  transfer.cancel();
  await assert.rejects(transfer.confirm(async () => {}), /already closed/);
  for (const [tamper, pattern] of [
    [{ recipient: 'ef'.repeat(64) }, /does not match your allocation/], [{ amount: '4999999999999999' }, /does not match your allocation/],
    [{ chainId: 'd'.repeat(64) }, /does not match your allocation/], [{ outputId: '8'.repeat(128) }, /does not match your allocation/],
    [{ nullifier: 'zz' }, /invalid claim/], [{ amount: '-1' }, /invalid claim amount/]
  ]) {
    claim.tamper = tamper;
    await assert.rejects(prepareClaim({ client, from: FINGERPRINT }), pattern, JSON.stringify(tamper));
  }
  claim.tamper = null;
  const builds = mock.log.filter(entry => entry === 'claimBuild').length;
  for (const [change, pattern] of [[{ claimed: 'yes' }, /already been claimed/], [{ window: 'not-open', startHeight: '5000' }, /opens at block 5000/], [{ window: 'closed', endHeight: '900' }, /ended at block 900/]]) {
    claim.status = { ...claim.status, claimed: 'no-evidence', window: 'open', startHeight: '0', endHeight: '18446744073709551615', ...change };
    await assert.rejects(prepareClaim({ client, from: FINGERPRINT }), pattern);
  }
  claim.status = { found: false };
  await assert.rejects(prepareClaim({ client, from: FINGERPRINT }), /no allocation/);
  assert.equal(mock.log.filter(entry => entry === 'claimBuild').length, builds, 'nothing built for a refused claim');
  assert.ok(!mock.log.includes('claimSubmit'), 'nothing submitted');
  client.lock();
});

test('claim: record durable before submit, recognised as a claim after storage, locks no coin, tracked to confirmed', async () => {
  const { mock, client, claim } = await claimClient();
  const transfer = await prepareClaim({ client, from: FINGERPRINT });
  let record;
  const hash = await transfer.confirm(async details => {
    assert.ok(!mock.log.includes('claimSubmit'), 'record written before the claim leaves');
    record = recordActivity(transfer, details);
  });
  assert.equal(hash, OUTPUT_ID); assert.deepEqual(claim.submitted, Uint8Array.of(9, 8, 7));
  assert.equal(record.hash, OUTPUT_ID); assert.deepEqual(record.inputs, [OUTPUT_ID]);
  assert.equal(record.fromHeight, '1001'); assert.equal(record.expiryHeight, '1090');
  assert.equal(isClaimRow(record), true);
  assert.deepEqual([...lockedInputs([record])], [], 'a claim record holds no coin');
  assert.throws(() => resendInputs(record), /Not a Nodus send/);
  // The marker survives the encrypted activity store (which keeps only
  // hash / expiryHeight / fromHeight / inputs of a NODUS row).
  const phrase = 'abandon '.repeat(23) + 'art', id = btoa(String.fromCharCode(...new Uint8Array(16).fill(4)));
  const key = await activityKeyFor(phrase, id);
  const [restored] = await parseActivity(await serializeActivity(id, [record], key), id, { nodus: FINGERPRINT }, key);
  assert.equal(isClaimRow(restored), true);
  // A send record is not a claim.
  assert.equal(isClaimRow({ chain: 'nodus', hash: INTENT_ID, inputs: [coin(2, '1').nullifier] }), false);
  // Tracking: found by the created coin id -> confirmed.
  mock.state.scan = { tip: '1005', found: true, height: '1003' };
  const found = await checkNodusActivity(restored, { client });
  assert.equal(found.status, 'confirmed'); assert.match(found.note, /claimed in block 1003/);
  assert.deepEqual(mock.state.lastScan, { intentId: OUTPUT_ID, fromHeight: '1001', toHeight: '1090' });
  // Within the scan window and not found: pending (a claim never "expires").
  mock.state.scan = { tip: '1090', found: false };
  assert.equal((await checkNodusActivity(restored, { client })).status, 'pending');
  // Past the window: the claim state decides.
  mock.state.scan = { tip: '1091', found: false };
  claim.status = { ...claim.status, claimed: 'yes' };
  assert.equal((await checkNodusActivity(restored, { client })).status, 'confirmed');
  claim.status = { ...claim.status, claimed: 'no-evidence' };
  const past = await checkNodusActivity(restored, { client });
  assert.equal(past.status, 'expired'); assert.match(past.note, /never paid out twice/); assert.doesNotMatch(past.note, /coins are free/);
  // A refused claim is reported after its record exists.
  // The module's code-7 wording (0.1.29): a refusal and an unreadable answer
  // share code 7, so the message names both and asserts neither.
  claim.accepted = false; claim.message = 'The Nodus node refused this claim, or its answer could not be read (code 7). If the allocation was claimed before, it is already claimed: check the balance before trying again.';
  const refused = await prepareClaim({ client, from: FINGERPRINT });
  let recorded = false;
  await assert.rejects(refused.confirm(async () => { recorded = true; }), /did not accept this claim\. The Nodus node refused this claim, or its answer could not be read \(code 7\)/);
  assert.equal(recorded, true);
  client.lock();
  await assert.rejects(prepareClaim({ client, from: FINGERPRINT }), /not connected/);
});

// ── Staking (0.1.29) ─────────────────────────────────────────────────────
// The mock module (test/nodus-mock-module.js) has no staking operations; this
// file adds them to the SAME module object before unlock (its factory returns
// that object), so the client sees a staking-capable module. The stand-in
// builder mirrors the shared C builder's rule (ascending nullifier order,
// lock + fee, UNDELEGATE locks nothing) only so the wallet-side checks have
// something consistent to check — the real builder is pinned by
// nodus/tests/test_v2_stake_build.c and the parity tests.
const VAL_A = 'a1'.repeat(64), VAL_B = 'b2'.repeat(64), VAL_C = 'c3'.repeat(64);
const RULES = { minDelegation: '10000000000', selfStake: '1000000000000000', commissionMaxBps: '5000', undelegateLockEpochs: '12', epochLength: '720', maxDelegators: '2048' };
function addStaking(mock) {
  const { module, state } = mock;
  state.validators = [
    { fingerprint: VAL_A, selfStake: RULES.selfStake, delegated: '0', commissionBps: 500, status: 0 },
    { fingerprint: VAL_B, selfStake: RULES.selfStake, delegated: '0', commissionBps: 1000, status: 1 },
    { fingerprint: VAL_C, selfStake: RULES.selfStake, delegated: '0', commissionBps: 250, status: 4 }
  ];
  state.delegations = [];
  state.stakeTamper = null;
  state.coins = [coin(1, '20000000000'), coin(2, '5000000')];
  state.total = state.spendable = '20005000000';
  module.stakingRules = { ...RULES };
  module.validators = async () => ({ truncated: false, validators: state.validators });
  module.delegations = async () => state.delegations;
  module.stakeBuild = async request => {
    state.lastStake = request;
    const lock = request.op === 'undelegate' ? 0n : BigInt(request.amount), need = lock + BigInt(FEE), inputs = [];
    let sum = 0n;
    for (const c of [...request.coins].sort((a, b) => (a.nullifier < b.nullifier ? -1 : 1))) {
      if (sum >= need) break;
      inputs.push(c.nullifier); sum += BigInt(c.amount);
    }
    if (sum < need) throw new Error('Insufficient NODUS balance for this amount plus the network fee.');
    const decoded = {
      op: request.op, validator: request.op === 'stake' ? FINGERPRINT : request.validator, amount: request.amount,
      commissionBps: request.op === 'stake' ? request.commissionBps : '0', fee: FEE, change: (sum - need).toString(),
      expiryHeight: request.expiryHeight, chainId: state.chainId, inputs
    };
    return { envelope: Uint8Array.of(7, 7), intentId: INTENT_ID, decoded: { ...decoded, ...(state.stakeTamper || {}) } };
  };
  return mock;
}
async function stakingClient() {
  const mock = addStaking(createMockNodusModule());
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}

test('staking: a module without the staking operations still connects; every staking call is "not available"', async () => {
  const { client } = await readyClient();
  assert.equal(client.stakeable, false); assert.equal(client.stakingRules, undefined);
  await assert.rejects(client.validators(), /not available/);
  await assert.rejects(stakingOverview({ client, from: FINGERPRINT }), /not available right now/);
  // Staking ops present but rules malformed: not stakeable either.
  const mock = addStaking(createMockNodusModule()); mock.module.stakingRules = { ...RULES, minDelegation: '0100' };
  const odd = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await odd.unlock({ seed: new Uint8Array(32), fingerprint: FINGERPRINT });
  assert.equal(odd.stakeable, false);
  client.lock(); odd.lock();
});

test('staking overview: validators and delegations parsed strictly and joined; lock period from the module rules', async () => {
  const { mock, client } = await stakingClient();
  assert.equal(client.stakeable, true); assert.deepEqual(client.stakingRules, RULES);
  mock.state.delegations = [{ validator: VAL_A, amount: '20000000000', block: '12' }, { validator: 'dd'.repeat(64), amount: '10000000000', block: '9' }];
  const view = await stakingOverview({ client, from: FINGERPRINT });
  assert.equal(view.validators.length, 3);
  assert.deepEqual(view.validators.map(v => [v.status, v.acceptsDelegation]), [['active', true], ['retiring', false], ['eligible', true]]);
  assert.equal(view.delegations[0].canUndelegate, true); assert.equal(view.delegations[1].canUndelegate, false);
  assert.equal(view.ownValidator, undefined);
  assert.equal(view.lockText, '12 epochs (12 × 720 = 8640 blocks)');
  // This wallet listed as a bonded validator -> ownValidator; UNSTAKED -> not.
  mock.state.validators = [...mock.state.validators, { fingerprint: FINGERPRINT, selfStake: RULES.selfStake, delegated: '0', commissionBps: 0, status: 0 }];
  assert.equal((await stakingOverview({ client, from: FINGERPRINT })).ownValidator.fingerprint, FINGERPRINT);
  mock.state.validators[3] = { ...mock.state.validators[3], status: 2 };
  assert.equal((await stakingOverview({ client, from: FINGERPRINT })).ownValidator, undefined);
  // Malformed answers are refused, never shown.
  for (const bad of [
    { ...mock.state.validators[0], fingerprint: 'A1'.repeat(64) }, { ...mock.state.validators[0], status: 5 },
    { ...mock.state.validators[0], commissionBps: 10001 }, { ...mock.state.validators[0], selfStake: '-1' }
  ]) {
    mock.state.validators = [bad];
    await assert.rejects(stakingOverview({ client, from: FINGERPRINT }), /invalid validator (list|stake)/);
  }
  mock.state.validators = [{ fingerprint: VAL_A, selfStake: '1', delegated: '0', commissionBps: 0, status: 0 }];
  mock.state.delegations = [{ validator: VAL_A, amount: '0', block: '1' }];
  await assert.rejects(stakingOverview({ client, from: FINGERPRINT }), /invalid delegation list/);
  mock.state.delegations = [{ validator: VAL_A, amount: '1', block: '1' }, { validator: VAL_A, amount: '2', block: '1' }];
  await assert.rejects(stakingOverview({ client, from: FINGERPRINT }), /invalid delegation list/);
  await assert.rejects(stakingOverview({ client, from: RECIPIENT }), /does not match/);
  client.lock();
});

test('staking overview: a validator\'s delegator slots — the count when the node reports it, null (unknown, never 0) when not', async () => {
  const { mock, client } = await stakingClient();
  assert.equal((await stakingOverview({ client, from: FINGERPRINT })).rules.maxDelegators, 2048n);
  mock.state.validators = [
    { ...mock.state.validators[0], delegators: 17 },
    { ...mock.state.validators[1], delegators: -1 },
    { ...mock.state.validators[2] }
  ];
  const view = await stakingOverview({ client, from: FINGERPRINT });
  assert.deepEqual(view.validators.map(v => v.delegators), [17, null, null]);
  mock.state.validators = [{ ...mock.state.validators[0], delegators: 0 }];
  assert.equal((await stakingOverview({ client, from: FINGERPRINT })).validators[0].delegators, 0);
  for (const bad of [-2, 1.5, '3']) {
    mock.state.validators = [{ fingerprint: VAL_A, selfStake: RULES.selfStake, delegated: '0', commissionBps: 0, status: 0, delegators: bad }];
    await assert.rejects(stakingOverview({ client, from: FINGERPRINT }), /invalid validator list/, String(bad));
  }
  client.lock();
});

test('delegate: a NEW delegation to a validator whose slots are full is refused before any build; a top-up is not', async () => {
  const { mock, client } = await stakingClient();
  mock.state.validators = [{ ...mock.state.validators[0], delegators: 2048 }, { ...mock.state.validators[2], delegators: -1 }];
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_A, amount: '100' }), /most delegators it can take \(2048\/2048\)/);
  assert.equal(mock.state.lastStake, undefined, 'nothing was built');
  // an unknown count (older node): the chain decides, the wallet does not refuse
  const unknown = await prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_C, amount: '100' });
  unknown.cancel();
  // an existing delegator adding more: exempt, as on the chain
  mock.state.delegations = [{ validator: VAL_A, amount: '10000000000', block: '5' }];
  const topUp = await prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_A, amount: '1' });
  assert.equal(topUp.to, VAL_A);
  topUp.cancel();
  client.lock();
});

test('delegate: the chain rules that need the listed state are checked first; the review comes from the signed read-back', async () => {
  const { mock, client } = await stakingClient();
  // below the minimum for a NEW delegation, a validator that is leaving, an unknown one
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_A, amount: '99.99999999' }), /at least 100\.0 NODUS/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_B, amount: '100' }), /does not accept delegations now \(Leaving\)/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: 'ee'.repeat(64), amount: '100' }), /not in the current validator list/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: 'x', amount: '100' }), /Choose a validator/);
  assert.equal(mock.state.lastStake, undefined, 'nothing was built');
  // a top-up of an existing delegation may be any amount >= 1 raw
  mock.state.delegations = [{ validator: VAL_C, amount: '10000000000', block: '5' }];
  const topUp = await prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_C, amount: '0.5' });
  assert.equal(topUp.kind, 'delegate'); assert.equal(topUp.to, VAL_C);
  topUp.cancel();
  // a new delegation: the request, the locked coin left out, the review
  const locked = new Set([coin(2, '1').nullifier]);
  const t = await prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_A, amount: '100', locked });
  assert.deepEqual(mock.state.lastStake, { op: 'delegate', validator: VAL_A, amount: '10000000000', commissionBps: '0', expiryHeight: '1090', coins: [coin(1, '20000000000')] });
  const review = Object.fromEntries(t.review);
  assert.equal(review.Action, 'Delegate NODUS'); assert.equal(review.Validator, VAL_A);
  assert.equal(review['Validator commission'], '5%'); assert.equal(review.Amount, '100.0 NODUS');
  assert.equal(review['Change back to you'], '99.99999 NODUS'); assert.match(review.Note, /locked for 12 epochs/);
  assert.equal(review['Valid until block'], '1090'); assert.equal(review['Chain ID'], CHAIN_ID);
  // confirm: the record is durable before the envelope is submitted
  let details;
  mock.log.length = 0;
  assert.equal(await t.confirm(async d => { details = d; assert.ok(!mock.log.includes('submit:start')); }), INTENT_ID);
  assert.deepEqual(details, { hash: INTENT_ID, expiryHeight: '1090', fromHeight: '1001', inputs: [coin(1, '1').nullifier] });
  assert.deepEqual([...mock.state.submitted], [7, 7]);
  await assert.rejects(t.confirm(async () => {}), /already closed/);
  // the record keeps its action for this tab, and holds its coins like a send
  const record = recordActivity(t, details);
  assert.equal(record.kind, 'delegate'); assert.equal(record.to, VAL_A);
  assert.ok(lockedInputs([record]).has(coin(1, '1').nullifier));
  // a read-back that differs from the request shows nothing
  for (const tamper of [{ validator: VAL_C }, { amount: '10000000001' }, { op: 'undelegate' }, { expiryHeight: '1091' }, { chainId: 'f'.repeat(64) }, { inputs: [coin(2, '1').nullifier] }, { change: '1' }]) {
    mock.state.stakeTamper = tamper;
    await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_A, amount: '100' }), /does not match your request|may not use|does not add up/, JSON.stringify(tamper));
  }
  mock.state.stakeTamper = null;
  // a refusal by the network is reported after the record exists
  mock.state.accepted = false;
  const refused = await prepareStake({ client, from: FINGERPRINT, kind: 'delegate', validator: VAL_A, amount: '100' });
  let recorded = false;
  await assert.rejects(refused.confirm(async () => { recorded = true; }), /did not accept this transaction/);
  assert.equal(recorded, true);
  client.lock();
});

test('undelegate: only an existing delegation, at most its amount, never leaving dust; the funding pays the fee only', async () => {
  const { mock, client } = await stakingClient();
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'undelegate', validator: VAL_A, amount: '1' }), /no delegation with this validator/);
  mock.state.delegations = [{ validator: VAL_A, amount: '15000000000', block: '5' }, { validator: 'dd'.repeat(64), amount: '10000000000', block: '5' }];
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'undelegate', validator: VAL_A, amount: '150.00000001' }), /at most 150\.0 NODUS/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'undelegate', validator: VAL_A, amount: '100' }), /leave at least 100\.0 NODUS/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'undelegate', validator: 'dd'.repeat(64), amount: '100' }), /cannot be withdrawn from here/);
  const t = await prepareStake({ client, from: FINGERPRINT, kind: 'undelegate', validator: VAL_A, amount: '150' });
  assert.equal(mock.state.lastStake.op, 'undelegate'); assert.equal(mock.state.lastStake.amount, '15000000000');
  const review = Object.fromEntries(t.review);
  assert.equal(review.Action, 'Undelegate NODUS'); assert.equal(review['Amount returned to you'], '150.0 NODUS');
  assert.match(review.Lock, /separate coin/); assert.match(review.Lock, /12 epochs \(12 × 720 = 8640 blocks\)/);
  // lock 0: one input covers the fee alone (inputs = fee + change)
  assert.equal(review['Change back to you'], '199.99999 NODUS');
  const partial = await prepareStake({ client, from: FINGERPRINT, kind: 'undelegate', validator: VAL_A, amount: '50' });
  assert.equal(partial.amount, '50.0');
  client.lock();
});

test('stake (become a validator): exactly the self-bond, commission 0..50%, refused when already a validator', async () => {
  const { mock, client } = await stakingClient();
  mock.state.coins = [coin(4, '1000000100000000')];
  mock.state.total = mock.state.spendable = '1000000100000000';
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'stake', commissionBps: '5001' }), /at most 50%/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'stake', commissionBps: '12.5' }), /between 0% and 50%/);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'stake' }), /between 0% and 50%/);
  const t = await prepareStake({ client, from: FINGERPRINT, kind: 'stake', commissionBps: '1250', amount: '5' });
  assert.deepEqual({ ...mock.state.lastStake, coins: undefined }, { op: 'stake', validator: '', amount: RULES.selfStake, commissionBps: '1250', expiryHeight: '1090', coins: undefined });
  const review = Object.fromEntries(t.review);
  assert.equal(review.Action, 'Become a validator'); assert.equal(review.Bond, '10000000.0 NODUS'); assert.equal(review.Commission, '12.5%');
  assert.match(review['Bond returns to'], /your own address/); assert.match(review.Important, /no way to unstake/);
  assert.equal(t.to, FINGERPRINT); assert.equal(t.kind, 'stake');
  t.cancel();
  // already a validator (any status but unstaked): refused before any build
  mock.state.lastStake = undefined;
  mock.state.validators.push({ fingerprint: FINGERPRINT, selfStake: RULES.selfStake, delegated: '0', commissionBps: 0, status: 4 });
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'stake', commissionBps: '0' }), /already a validator/);
  assert.equal(mock.state.lastStake, undefined);
  await assert.rejects(prepareStake({ client, from: FINGERPRINT, kind: 'unstake' }), /Unknown staking action/);
  client.lock();
});
