// Account histories kept on the device for a saved wallet, for the networks that used to be read and thrown away:
// Soqucoin, QTC, Algorand, XION, Splendor (rows, per selected network), CKB (extension rows) and NODUS (the node's page).
// What this proves (src/history.js checkHistoryRows, src/activity-storage.js serializeHistory / parseHistory,
// src/nodus/history.js nodusPageToSaved / nodusPageFromSaved):
//   - the rows each reader writes (the XION and Splendor rows come out of the real parsers, the others are written here in the
//     reader's row shape, line numbers in src/history.js) pass the saved-row check unchanged and come back from the encrypted record
//     with their network id;
//   - saved rows are untrusted: a row of another chain, another symbol, a status or peer the reader never writes, a malformed
//     hash or amount, or more rows than the reader returns, refuses the whole record ("Invalid saved history.");
//   - a network id the chain does not have (Soqucoin has only mainnet), or on a chain that has none (Ethereum), refuses it;
//   - the NODUS page survives the encrypted record as the same bigint page and is checked again by parseAddrHistory on load
//     (an unsorted page, an unknown kind or an extra key refuses it); an Ethereum record without any of the new chains still opens.
// What it does not prove: that src/app.js writes nothing for a typed-words wallet (persistHistory returns before the write when
// there is no saved wallet's history key; that file needs a DOM and is covered by the browser run), nor the extension holders
// (extension/test/history-kept-background.test.js and nodus-background.test.js).
// Compile flags / environment: none. Leaves nothing behind (no storage, no network).
// Falsely passes if: a fixture were produced by the code under test (the bad rows are the good row with one field changed, the
// good rows are hand-written or come from the readers' own parsers), or the record were refused for a wrong key (every bad case
// is the same call as a good case that passes in the same test).
import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '@scure/base';
import { checkHistoryRows, historySupported, historyKept } from '../src/history.js';
import { parseXionHistory } from '../src/pq/xion-history.js';
import { parseSplendorHistory } from '../src/pq/splendor-history.js';
import { serializeHistory, parseHistory, historyKeyFor } from '../src/activity-storage.js';
import { parseAddrHistory } from '../src/nodus/history.js';

const id = Buffer.alloc(16, 5).toString('base64'), phrase = 'abandon '.repeat(23) + 'art', NOW = 1794665000000;
const hex = (byte, n = 32) => byte.repeat(n);
const xionAccount = byte => bech32.encode('xion', bech32.toWords(Uint8Array.from({ length: 20 }, () => byte)));
const splendorAccount = byte => 'SQ:' + hex(byte);

const own = xionAccount(1), other = xionAccount(2);
const xionRows = parseXionHistory([{ txs: [{ body: { messages: [{ '@type': '/cosmos.bank.v1beta1.MsgSend', from_address: other, to_address: own, amount: [{ denom: 'uxion', amount: '1500000' }] }] } }],
  tx_responses: [{ txhash: hex('AB'), code: '0', timestamp: '2026-11-14T10:00:00Z' }] }, { txs: [], tx_responses: [] }], own);
const splendorRows = parseSplendorHistory({ address: splendorAccount('11'), transactions: [{ kind: 'transfer', from: splendorAccount('22'), to: splendorAccount('11'), hash: hex('cd'), amount: '1500000000000000000', status: '1', timestamp: '1790000000' }] }, splendorAccount('11'));
const rowOf = (chain, over) => ({ chain, hash: hex('a1'), time: 1790000000000, dir: 'out', symbol: chain.toUpperCase(), amount: '0.5', peer: '', status: 'confirmed', ...over });
// Hand-written in the reader's row shape: src/pq/soqu-history.js:36, src/pq/qtc.js:86, src/pq/algorand.js:84-85.
const GOOD = {
  soqucoin: [rowOf('soqucoin', { symbol: 'SOQ', amount: '12.34567891' })],
  qtc: [rowOf('qtc', { symbol: 'QTC', dir: 'in', amount: '7' })],
  algorand: [rowOf('algorand', { hash: 'AB'.repeat(26), symbol: 'ALGO', dir: 'self', amount: '0' }), rowOf('algorand', { hash: 'CD'.repeat(26), symbol: 'ALGO', amount: '1.000001', peer: 'A'.repeat(58) })],
  xion: xionRows,
  splendor: splendorRows,
};
const kinds = { soqucoin: 'mainnet', qtc: 'testnet', algorand: 'mainnet', xion: 'testnet', splendor: 'mainnet' };

test('the readers\' own rows pass the saved-row check unchanged', () => {
  assert.equal(xionRows.length, 1); assert.equal(splendorRows.length, 1);   // the real parsers produced a row to check
  for (const [chain, rows] of Object.entries(GOOD)) assert.deepEqual(checkHistoryRows(chain, rows), rows, chain);
});

test('every kept chain comes back from the encrypted record with its network id; a record without one still opens', async () => {
  const key = await historyKeyFor(phrase, id);
  for (const [chain, rows] of Object.entries(GOOD)) {
    const record = { address: 'addr-' + chain, readAt: NOW, rows };
    const back = await parseHistory(await serializeHistory(id, { [chain]: { ...record, networkId: kinds[chain] } }, key), id, key, NOW);
    assert.deepEqual(back[chain], { ...record, networkId: kinds[chain] }, chain);
    const plain = await parseHistory(await serializeHistory(id, { [chain]: record }, key), id, key, NOW);
    assert.equal(Object.hasOwn(plain[chain], 'networkId'), false, `${chain}: the extension's per-network key carries no network id`);
  }
});

// PROVES: a zero amount is kept only where a reader writes one: Algorand (a self or zero-amount payment,
// src/pq/algorand.js:80-85) and a CKB self row (net flow 0, src/pq/ckb-history.js); Soqucoin, QTC, XION and Splendor
// never write zero (their readers leave equal flows out or accept positive amounts only), so a saved zero there is refused.
// ENVIRONMENT: none. LEAVES BEHIND: nothing. FALSE PASS: GOOD rows hand-written in the readers' shape for these chains.
test('a saved zero amount is accepted only from the readers that write one', () => {
  const algorandZero = { ...GOOD.algorand[0], dir: 'self', amount: '0', peer: '' };
  assert.deepEqual(checkHistoryRows('algorand', [algorandZero]), [algorandZero]);
  const ckbSelf = { hash: `0x${'ab'.repeat(32)}`, dir: 'self', amount: '0', symbol: 'CKB', status: 'committed', time: 1794665000000 };
  assert.deepEqual(checkHistoryRows('ckb', [ckbSelf]), [ckbSelf]);
  for (const dir of ['in', 'out']) assert.throws(() => checkHistoryRows('ckb', [{ ...ckbSelf, dir }]), /Invalid saved history/, dir);
});

test('saved rows are untrusted: anything the reader never writes refuses the record', async () => {
  const key = await historyKeyFor(phrase, id);
  const bads = {
    soqucoin: [{ chain: 'qtc' }, { symbol: 'SOQX' }, { peer: 'a' }, { status: 'failed' }, { dir: 'self' }, { hash: hex('A1') }, { amount: '1.50' }, { amount: '1e3' }, { amount: '0' }, { time: 0 }, { time: 1.5 }],
    qtc: [{ chain: 'soqucoin' }, { symbol: 'SOQ' }, { peer: 'a' }, { status: 'failed' }, { hash: 'x' }, { amount: '0' }],
    algorand: [{ hash: hex('a1') }, { symbol: 'ALGOS' }, { peer: 'abc' }, { status: 'failed' }, { amount: '0.0000001' }, { dir: 'sideways' }],
    xion: [{ chain: 'splendor' }, { symbol: 'SPLD' }, { peer: '' }, { peer: other.toUpperCase() }, { peer: 'xion1' + 'q'.repeat(38) }, { status: 'pending' }, { hash: hex('a1', 31) }, { amount: '0' }],
    splendor: [{ chain: 'xion' }, { symbol: 'XION' }, { peer: xionAccount(1) }, { status: 'pending' }, { amount: '-1' }, { amount: '0' }, { hash: hex('G1') }],
  };
  for (const [chain, list] of Object.entries(bads)) {
    const good = GOOD[chain][0];
    assert.deepEqual(checkHistoryRows(chain, [good]), [good]);
    for (const over of list) assert.throws(() => checkHistoryRows(chain, [{ ...good, ...over }]), /Invalid saved history/, `${chain} ${JSON.stringify(over)}`);
    assert.throws(() => checkHistoryRows(chain, [null]), /Invalid saved history/);
    assert.throws(() => checkHistoryRows(chain, 'rows'), /Invalid saved history/);
    // Through the encrypted record, as a loaded file arrives.
    const back = await parseHistory(await serializeHistory(id, { [chain]: { address: 'a', readAt: NOW, rows: [{ ...good, ...list[0] }] } }, key), id, key, NOW).catch(error => error);
    assert.match(back.message, /Invalid saved history/, chain);
  }
  // Soqucoin returns at most SOQU_HISTORY_LIMIT (20) rows; the others at most HISTORY_LIMIT (50).
  const soq = GOOD.soqucoin[0];
  assert.equal(checkHistoryRows('soqucoin', Array.from({ length: 20 }, () => soq)).length, 20);
  assert.throws(() => checkHistoryRows('soqucoin', Array.from({ length: 21 }, () => soq)), /Invalid saved history/);
  assert.equal(checkHistoryRows('qtc', Array.from({ length: 50 }, () => GOOD.qtc[0])).length, 50);
  assert.throws(() => checkHistoryRows('qtc', Array.from({ length: 51 }, () => GOOD.qtc[0])), /Invalid saved history/);
});

test('a network id the chain does not have, or a chain with none, refuses the record', async () => {
  const key = await historyKeyFor(phrase, id), seal = (chain, networkId, rows) => serializeHistory(id, { [chain]: { address: 'a', readAt: NOW, rows, networkId } }, key);
  await parseHistory(await seal('soqucoin', 'mainnet', GOOD.soqucoin), id, key, NOW);
  for (const networkId of ['testnet', 'regtest', 'constructor']) await assert.rejects(parseHistory(await seal('soqucoin', networkId, GOOD.soqucoin), id, key, NOW), /Invalid saved history/, networkId);
  await parseHistory(await seal('splendor', 'testnet', GOOD.splendor), id, key, NOW);
  await assert.rejects(parseHistory(await seal('splendor', 'devnet', GOOD.splendor), id, key, NOW), /Invalid saved history/);
  const eth = { chain: 'ethereum', hash: '0x' + hex('a1'), time: 1, dir: 'in', symbol: 'ETH', amount: '1.0', peer: '', status: 'confirmed' };
  assert.deepEqual((await parseHistory(await seal('ethereum', undefined, [eth]), id, key, NOW)).ethereum.rows, [eth]);
  // serializeHistory writes a network id only for a chain that has networks, so the Ethereum record above carries none.
  assert.equal(Object.hasOwn((await parseHistory(await seal('ethereum', 'mainnet', [eth]), id, key, NOW)).ethereum, 'networkId'), false);
});

test('CKB rows (extension only) are kept in the reader\'s own shape; the web wallet still reads no CKB history', async () => {
  const key = await historyKeyFor(phrase, id);
  const row = { hash: '0x' + hex('ab'), dir: 'in', amount: '61', symbol: 'CKB', status: 'committed', time: 1790000000000 };
  assert.equal(historySupported('ckb'), false);   // src/app.js shows no Refresh and reads nothing for it
  assert.equal(historyKept('ckb'), true);
  assert.deepEqual(checkHistoryRows('ckb', [row]), [row]);
  for (const over of [{ status: 'confirmed' }, { symbol: 'CKBX' }, { hash: hex('ab') }, { dir: 'x' }, { amount: '61.0' }, { time: -1 }, { time: 1e16 }])
    assert.throws(() => checkHistoryRows('ckb', [{ ...row, ...over }]), /Invalid saved history/, JSON.stringify(over));
  assert.throws(() => checkHistoryRows('ckb', Array.from({ length: 21 }, () => row)), /Invalid saved history/);
  const back = await parseHistory(await serializeHistory(id, { ckb: { address: 'ckb1', readAt: NOW, rows: [row] } }, key), id, key, NOW);
  assert.deepEqual(back.ckb.rows, [row]);
  assert.equal(historyKept('nodus'), false);       // NODUS has its own entry, not rows
  assert.equal(historyKept('bsc'), false);
});

const WIRE_ENTRY = (h, over = {}) => ({ h: String(h), i: '0', q: '0', kind: 'spend_in', amount: '100000000', token: '0'.repeat(128), fee: '0', peer: hex('ab', 64), wire: hex('cd', 64), ts: '1790000000', ...over });
test('the NODUS page is kept as the node answered it and checked again on load', async () => {
  const key = await historyKeyFor(phrase, id);
  const page = parseAddrHistory({ enabled: true, from_height: '5', entries: [WIRE_ENTRY(30), WIRE_ENTRY(29, { kind: 'burn', peer: '', wire: hex('ef', 64), amount: '7' })] });
  assert.equal(typeof page.entries[0].h, 'bigint');
  const text = await serializeHistory(id, { nodus: { address: hex('11', 64), readAt: NOW, page } }, key);   // JSON.stringify would throw on a bigint
  const back = await parseHistory(text, id, key, NOW);
  assert.deepEqual(back.nodus, { address: hex('11', 64), readAt: NOW, page });
  // The same page and rows of another chain in one record.
  const both = await parseHistory(await serializeHistory(id, { nodus: { address: hex('11', 64), readAt: NOW, page }, qtc: { address: 'q', readAt: NOW, rows: GOOD.qtc, networkId: 'mainnet' } }, key), id, key, NOW);
  assert.deepEqual(Object.keys(both).sort(), ['nodus', 'qtc']);
  // An empty page (a node that keeps no history) is a page too.
  const empty = parseAddrHistory({ enabled: false, from_height: '0', entries: [] });
  assert.deepEqual((await parseHistory(await serializeHistory(id, { nodus: { address: hex('11', 64), readAt: NOW, page: empty } }, key), id, key, NOW)).nodus.page, empty);
});

test('a saved NODUS page that parseAddrHistory would refuse refuses the record', async () => {
  const key = await historyKeyFor(phrase, id);
  const sealed = entries => serializeHistory(id, { nodus: { address: hex('11', 64), readAt: NOW, page: { enabled: true, fromHeight: 1n, entries } } }, key);
  const ok = parseAddrHistory({ enabled: true, from_height: '1', entries: [WIRE_ENTRY(30), WIRE_ENTRY(29)] }).entries;
  await parseHistory(await sealed(ok), id, key, NOW);
  await assert.rejects(parseHistory(await sealed([ok[1], ok[0]]), id, key, NOW), /Invalid saved history/, 'heights must descend');
  await assert.rejects(parseHistory(await sealed([{ ...ok[0], kind: 'invented' }]), id, key, NOW), /Invalid saved history/);
  await assert.rejects(parseHistory(await sealed([{ ...ok[0], wire: '' }]), id, key, NOW), /Invalid saved history/, 'a non-boundary row needs its wire id');
  await assert.rejects(parseHistory(await sealed(Array.from({ length: 51 }, (_, i) => ({ ...ok[0], h: BigInt(100 - i) }))), id, key, NOW), /Invalid saved history/, 'more than the page size');
});
