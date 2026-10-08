// NODUS account history (0.1.78, src/nodus/history.js + the client's
// addrHistory): the node's dnac_addr_history page is checked, every row kind
// reads as plain words, this tab's own records are shown once, coverage is
// said honestly (from_height, a node not indexing, a failed read), and the
// signed envelope's wire id stays in this tab only (the saved Activity
// format is unchanged). Against the TEST-ONLY mock module
// (test/nodus-mock-module.js): proves the wallet-side rules, not the node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAddrHistory, nodusHistoryRow, nodusHistoryStatus, localRowsToShow, nodusUnits, NODUS_HISTORY_KINDS, NODUS_HISTORY_LIMIT, BOUNDARY_POS } from '../src/nodus/history.js';
import { HISTORY_LIMIT, historySupported } from '../src/history.js';
import { createNodusClient } from '../src/nodus/client.js';
import { recordActivity } from '../src/activity.js';
import { serializeActivity, parseActivity, activityKeyFor } from '../src/activity-storage.js';
import { prepare } from '../src/adapters/nodus.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, INTENT_ID } from './nodus-mock-module.js';

const NATIVE = '0'.repeat(128), TOKEN = '7c'.repeat(64), PEER = 'cd'.repeat(64), VAL = 'ee'.repeat(64);
const WIRE = n => n.toString(16).padStart(128, '0');
const BOUNDARY = BOUNDARY_POS.toString();
// One entry in the module's JSON form (send-module.js addrHistory).
const entry = (h, i, q, kind, more = {}) => ({ h: String(h), i: String(i), q: String(q), kind, amount: '0', token: NATIVE, fee: '0', peer: '', wire: i === BOUNDARY ? '' : WIRE(h * 10 + q + 1), ts: String(1790000000 + h), ...more });
const page = (entries, more = {}) => ({ enabled: true, from_height: '100', entries, ...more });

// Every kind the node writes (nodus_witness_addr_index.h :147-159, "name"
// and "evm_deposit" nodus_witness_addr_index.c), newest first.
const ALL_KINDS = [
  entry(131, 0, 0, 'evm_deposit', { amount: '10000000000', fee: '19388' }),  // EVM deposit, fee on it
  entry(130, BOUNDARY, 1, 'release', { amount: '1000000000000' }),           // graduation
  entry(130, BOUNDARY, 0, 'payout', { amount: '250000000' }),
  entry(129, 0, 0, 'release', { amount: '500000000' }),                      // EVM withdraw / redeem
  entry(128, 0, 0, 'fee', { fee: '19388' }),                                 // e.g. an EVM call
  entry(127, 0, 0, 'name', { amount: '10000000000', fee: '10000' }),
  entry(126, 0, 0, 'validator_update', { fee: '10000' }),
  entry(125, 0, 0, 'unstake', { fee: '10000' }),
  entry(124, 0, 0, 'undelegate', { amount: '300000000', peer: VAL, fee: '10000' }),
  entry(123, 0, 0, 'delegate', { amount: '300000000', peer: VAL, fee: '10000' }),
  entry(122, 0, 0, 'stake', { amount: '1000000000000', fee: '10000' }),
  entry(121, 1, 0, 'claim', { amount: '5000000000000000' }),
  entry(120, 0, 0, 'token_create', { amount: '1000', token: TOKEN, peer: PEER }),
  entry(119, 0, 0, 'burn', { amount: '100000000', fee: '10000' }),
  entry(118, 0, 1, 'spend_in', { amount: '250000000', peer: PEER }),
  entry(118, 0, 0, 'spend_out', { amount: '100000000', peer: PEER, fee: '10000' }),
];

test('the wallet page size is the other networks\' HISTORY_LIMIT, and NODUS is never a cached provider history', () => {
  assert.equal(NODUS_HISTORY_LIMIT, HISTORY_LIMIT);
  // src/history.js caches only its providers (persistHistory / parseHistory):
  // the node's rows are never written to the device, they are read again.
  assert.equal(historySupported('nodus'), false);
});

test('parseAddrHistory: a well-formed page of every kind becomes bigints', () => {
  const p = parseAddrHistory(page(ALL_KINDS));
  assert.equal(p.enabled, true); assert.equal(p.fromHeight, 100n);
  assert.deepEqual([...new Set(p.entries.map(e => e.kind))].sort(), [...NODUS_HISTORY_KINDS].sort());
  const first = p.entries.at(-1);
  assert.deepEqual(first, { h: 118n, i: 0n, q: 0n, kind: 'spend_out', amount: 100000000n, token: NATIVE, fee: 10000n, peer: PEER, wire: WIRE(1181), ts: 1790000118n });
});

test('parseAddrHistory refuses anything outside the nodus.h shape', () => {
  const bad = (entries, more, why) => assert.throws(() => parseAddrHistory(page(entries, more)), /invalid account history/, why);
  bad([entry(1, 0, 0, 'mint')], {}, 'an unknown kind');
  bad([{ ...entry(1, 0, 0, 'fee'), extra: '1' }], {}, 'an extra key');
  bad([(({ ts, ...rest }) => rest)(entry(1, 0, 0, 'fee'))], {}, 'a missing key');
  bad([entry(1, 0, 0, 'spend_in', { peer: 'CD'.repeat(64) })], {}, 'an upper-case peer');
  bad([entry(1, 0, 0, 'spend_in', { peer: 'cd' })], {}, 'a short peer');
  bad([entry(1, 0, 0, 'fee', { token: '00' })], {}, 'a short token');
  bad([entry(1, 0, 0, 'fee', { wire: '' })], {}, 'an item row without a wire id');
  bad([entry(1, BOUNDARY, 0, 'payout', { wire: WIRE(1) })], {}, 'a boundary row with a wire id');
  bad([entry(1, 3, 0, 'payout')], {}, 'a payout that is not a boundary row');
  bad([entry(1, 0, 0, 'fee'), entry(2, 0, 0, 'fee')], {}, 'not newest first');
  bad([entry(1, 0, 0, 'fee'), entry(1, 0, 0, 'fee')], {}, 'a repeated position');
  bad([entry(1, 0, 0, 'fee', { amount: '18446744073709551616' })], {}, 'an amount above u64');
  bad([entry(1, 0, 0, 'fee', { amount: '01' })], {}, 'a leading zero');
  bad([entry(1, 0, 0, 'fee', { amount: 5 })], {}, 'a number instead of a decimal string');
  bad([entry(1, '4294967296', 0, 'fee')], {}, 'a position above u32');
  bad([], { enabled: 'yes' }, 'enabled not a boolean');
  bad([], { from_height: '-1' }, 'a bad from_height');
  bad([], { count: '0' }, 'an extra top-level key');
  assert.throws(() => parseAddrHistory(page([entry(2, 0, 0, 'fee'), entry(1, 0, 0, 'fee')]), { limit: 1 }), /invalid/, 'more rows than asked for');
  assert.throws(() => parseAddrHistory(null), /invalid/);
});

test('every kind reads as plain words, with amount, counterparty, fee, block and time', () => {
  const names = new Map([[PEER, 'alice']]);
  const rows = parseAddrHistory(page(ALL_KINDS)).entries.map(e => nodusHistoryRow(e, { names }));
  const by = Object.fromEntries(rows.map(r => [r.key, r]));
  const text = r => [r.title, r.sign + r.amount, r.detail];
  assert.deepEqual(text(by['118:0:0']), ['Sent', '−1.0 NODUS', `to alice (${PEER.slice(0, 8)}…${PEER.slice(-6)}) · fee 0.0001 NODUS`]);
  assert.deepEqual(text(by['118:0:1']), ['Received', '+2.5 NODUS', `from alice (${PEER.slice(0, 8)}…${PEER.slice(-6)})`]);
  assert.deepEqual(text(by['119:0:0']), ['Burned', '−1.0 NODUS', 'fee 0.0001 NODUS']);
  // a token row: no symbol registry in the wallet -> raw units + short token id
  assert.deepEqual(text(by['120:0:0']), ['Token created', `+1000 units of token ${TOKEN.slice(0, 8)}…${TOKEN.slice(-6)}`, `created by alice (${PEER.slice(0, 8)}…${PEER.slice(-6)})`]);
  assert.deepEqual(text(by['121:1:0']), ['Claimed', '+50000000.0 NODUS', '']);
  assert.deepEqual(text(by['122:0:0']), ['Staked', '10000.0 NODUS', 'fee 0.0001 NODUS · bond held while you are a witness']);
  assert.deepEqual(text(by['123:0:0']), ['Delegated', '3.0 NODUS', `to witness ${VAL.slice(0, 8)}…${VAL.slice(-6)} · fee 0.0001 NODUS`]);
  assert.deepEqual(text(by['124:0:0']), ['Undelegated', '3.0 NODUS', `from witness ${VAL.slice(0, 8)}…${VAL.slice(-6)} · fee 0.0001 NODUS`]);
  // unstake / witness update move no amount: the title stands alone
  assert.deepEqual(text(by['125:0:0']), ['Unstaked', '', 'fee 0.0001 NODUS']);
  assert.deepEqual(text(by['126:0:0']), ['Witness update', '', 'fee 0.0001 NODUS']);
  assert.deepEqual(text(by['127:0:0']), ['Chain name registered', '−100.0 NODUS', 'fee 0.0001 NODUS']);
  // a fee-only row (e.g. a contract call without a value, or a deposit
  // indexed by an older node) shows the fee as its amount, and says nothing
  // more
  assert.deepEqual(text(by['128:0:0']), ['Fee', '−0.00019388 NODUS', 'network fee']);
  // a release WITH a wire id is the smart-contract release, not a stake
  assert.deepEqual(text(by['129:0:0']), ['Moved back from smart contracts', '+5.0 NODUS', '']);
  // a smart-contract deposit: the amount locked into the reserve leaves
  // this address, the fee rides on the same row
  assert.deepEqual(text(by['131:0:0']), ['Moved to smart contracts','−100.0 NODUS', 'fee 0.00019388 NODUS']);
  assert.deepEqual(text(by[`130:${BOUNDARY}:0`]), ['Reward payout', '+2.5 NODUS', '']);
  assert.deepEqual(text(by[`130:${BOUNDARY}:1`]), ['Stake released', '+10000.0 NODUS', '']);
  // height and block time (ms) from the row; boundary rows carry no id
  assert.equal(by['118:0:0'].height, '118'); assert.equal(by['118:0:0'].time, 1790000118000);
  assert.equal(by[`130:${BOUNDARY}:0`].wire, ''); assert.equal(by['118:0:0'].wire, WIRE(1181));
  // without a known name the counterparty is the short address only
  assert.equal(nodusHistoryRow(parseAddrHistory(page([ALL_KINDS.at(-1)])).entries[0]).detail, `to ${PEER.slice(0, 8)}…${PEER.slice(-6)} · fee 0.0001 NODUS`);
  assert.equal(nodusUnits(1n), '0.00000001'); assert.equal(nodusUnits(0n), '0.0');
});

test('the status line says whose answer it is and how far back it reaches', () => {
  const full = parseAddrHistory(page([], { from_height: '3151' }));
  assert.equal(nodusHistoryStatus({ page: full, readAt: 'now' }), `Newest ${NODUS_HISTORY_LIMIT} entries as reported by one Nodus node, read now. History from block 3151: this node keeps nothing older.`);
  assert.equal(nodusHistoryStatus({ page: parseAddrHistory(page([], { from_height: '1' })) }), `Newest ${NODUS_HISTORY_LIMIT} entries as reported by one Nodus node.`);
  assert.equal(nodusHistoryStatus({ page: parseAddrHistory(page([], { from_height: '0' })) }), 'This Nodus node keeps no account history yet. Your sends from this wallet are listed above.');
  assert.equal(nodusHistoryStatus({ page: parseAddrHistory(page([], { from_height: '0', enabled: false })) }), 'This Nodus node keeps no account history. Your sends from this wallet are listed above.');
  assert.match(nodusHistoryStatus({ page: parseAddrHistory(page([], { from_height: '50', enabled: false })) }), /not recording new entries right now, so the newest ones may be missing/);
  assert.equal(nodusHistoryStatus({ error: 'The Nodus node is busy; try again in a moment.' }), 'Account history could not be read from the Nodus node: The Nodus node is busy; try again in a moment. Your sends from this wallet are listed above.');
  assert.equal(nodusHistoryStatus({ reading: true }), 'Reading account history from one Nodus node…');
  assert.equal(nodusHistoryStatus({}), 'Account history has not been read yet.');
});

test('this tab\'s records: shown once — by wire id, or by the confirmed block; everything else stays', () => {
  const p = parseAddrHistory(page([entry(140, 0, 0, 'fee', { wire: WIRE(9), fee: '1' }), entry(120, 0, 0, 'spend_out', { amount: '1', peer: PEER, wire: WIRE(8) })]));
  const local = [
    { hash: 'a'.repeat(128), status: 'pending', wire: WIRE(9) },                // (a) pending here, listed by the node
    { hash: 'b'.repeat(128), status: 'confirmed', block: '120' },               // (b) reloaded (no wire), re-confirmed at 120
    { hash: 'c'.repeat(128), status: 'pending' },                               // reloaded, not confirmed yet
    { hash: 'd'.repeat(128), status: 'confirmed', block: '90' },                // below anything the node lists
    { hash: 'e'.repeat(128), status: 'expired', wire: WIRE(7) },                // never applied
    { hash: 'f'.repeat(128), status: 'failed', block: '120' },                  // only 'confirmed' is matched by height
  ];
  assert.deepEqual(localRowsToShow(local, p).map(r => r.hash[0]), ['c', 'd', 'e', 'f']);
  // no node page (failed read, index off on an older module): every record
  assert.deepEqual(localRowsToShow(local, null), local);
  // a FULL page may be cut inside its oldest height: a record AT that height
  // stays; above it, it is shown by the node
  const fullPage = parseAddrHistory(page([entry(140, 0, 0, 'fee', { wire: WIRE(9), fee: '1' }), entry(120, 0, 0, 'fee', { wire: WIRE(8), fee: '1' })]), { limit: 2 });
  assert.deepEqual(localRowsToShow([{ hash: 'x', status: 'confirmed', block: '120' }, { hash: 'y', status: 'confirmed', block: '140' }], fullPage, { limit: 2 }).map(r => r.hash), ['x']);
});

async function readyClient(mutate = module => module) {
  const mock = createMockNodusModule();
  const client = createNodusClient({ factory: async () => mutate(mock.module), setInterval: () => 1, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}

test('client.addrHistory: queued like every call, request checked, page checked', async () => {
  const { mock, client } = await readyClient();
  assert.equal(client.historyReadable, true);
  mock.state.history = page(ALL_KINDS);
  const p = await client.addrHistory();
  assert.deepEqual(mock.state.lastHistory, { limit: NODUS_HISTORY_LIMIT });
  assert.equal(p.entries.length, ALL_KINDS.length); assert.equal(p.fromHeight, 100n);
  // the mock still answers the 16-row page: ask for at least that many (a
  // page longer than the request is refused — tested just below)
  await client.addrHistory({ before: { h: '118', i: '0', q: '1' }, limit: 20 });
  assert.deepEqual(mock.state.lastHistory, { before: { h: '118', i: '0', q: '1' }, limit: 20 });
  await assert.rejects(client.addrHistory({ limit: 10 }), /invalid account history/);
  await assert.rejects(client.addrHistory({ limit: 101 }), /Invalid account history request/);
  await assert.rejects(client.addrHistory({ limit: 0 }), /Invalid account history request/);
  await assert.rejects(client.addrHistory({ before: { h: '1', i: '4294967296', q: '0' } }), /Invalid account history request/);
  await assert.rejects(client.addrHistory({ before: { h: 1, i: '0', q: '0' } }), /Invalid account history request/);
  // a malformed page from the module is refused, never shown as empty
  mock.state.history = page([entry(1, 0, 0, 'mint')]);
  await assert.rejects(client.addrHistory(), /invalid account history/);
  // the module's refusal (an older node, index answer unreadable) passes through
  mock.state.historyError = new Error('This Nodus node did not return an account history (an older node, or an unreadable answer; rc=7).');
  await assert.rejects(client.addrHistory(), /did not return an account history/);
  assert.equal(mock.state.overlap, false, 'one export at a time');
  client.lock();
  await assert.rejects(client.addrHistory(), /not available|locked|not ready/);
});

test('a module without addrHistory still unlocks; history is "not available"', async () => {
  const { client } = await readyClient(module => { const { addrHistory, ...rest } = module; return rest; });
  assert.equal(client.state, 'ready');
  assert.equal(client.historyReadable, false);
  await assert.rejects(client.addrHistory(), /not available in this wallet version/);
});

test('the wire id of a send stays in this tab: recorded in memory, never saved', async () => {
  const { mock, client } = await readyClient();
  mock.state.wireId = WIRE(42);
  const t = await prepare({ client, from: FINGERPRINT, to: RECIPIENT, amount: '1' });
  let details;
  await t.send(async d => { details = d; });
  assert.equal(details.hash, INTENT_ID); assert.equal(details.wire, WIRE(42));
  const record = recordActivity({ chain: 'nodus', from: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.0' }, details);
  assert.equal(record.wire, WIRE(42));
  // the saved Activity format is unchanged: no wire written, none read back
  const id = btoa(String.fromCharCode(...new Uint8Array(16).fill(3)));
  const key = await activityKeyFor('test phrase', id);
  const saved = await parseActivity(await serializeActivity(id, [record], key), id, { nodus: FINGERPRINT }, key);
  assert.equal(saved.length, 1); assert.equal('wire' in saved[0], false);
  // a module without a wire id: no `wire` at all (never invented)
  mock.state.wireId = null;
  const u = await prepare({ client, from: FINGERPRINT, to: RECIPIENT, amount: '1' });
  let plain;
  await u.send(async d => { plain = d; });
  assert.equal('wire' in plain, false);
  // a malformed wire id from the module is ignored, not recorded
  assert.equal('wire' in recordActivity({ chain: 'nodus', from: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.0' }, { ...details, wire: 'zz' }), false);
});
