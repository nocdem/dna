// Account history parsers (src/history.js): provider data is untrusted —
// only well-formed transfers of THIS address in the wallet's listed assets
// are kept; symbols and decimals come from the wallet's own config.
import test from 'node:test';
import assert from 'node:assert/strict';
import { TronWeb } from 'tronweb';
import { parseBlockscout, parseTronGrid, parseSolanaTransaction, parseCellframeHistory, checkHistoryRows, mergeHistory, HISTORY_LIMIT } from '../src/history.js';
import { CHAINS } from '../src/config.js';

const ME = '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb', me = ME.toLowerCase(), OTHER = '0x' + '12'.repeat(20);
const h = n => '0x' + n.toString(16).padStart(64, '0');

test('ethereum: native and listed-token transfers of this address, everything else dropped', () => {
  const native = { result: [
    { hash: h(1), timeStamp: '1790000000', from: OTHER, to: me, value: '1500000000000000000', isError: '0' },
    { hash: h(2), timeStamp: '1790000100', from: me, to: OTHER, value: '1', isError: '1' },
    { hash: h(3), timeStamp: '1790000200', from: me, to: OTHER, value: '0' },                 // contract call
    { hash: h(4), timeStamp: '1790000300', from: OTHER, to: OTHER, value: '5' },              // not ours
    { hash: 'x', timeStamp: '1790000400', from: OTHER, to: me, value: '5' },                  // bad hash
    { hash: h(6), timeStamp: '1790000500', from: OTHER, to: me, value: '-5' },                // bad value
  ] };
  const usdt = CHAINS.ethereum.tokens.find(t => t.symbol === 'USDT');
  const tokens = { result: [
    { hash: h(7), timeStamp: '1790000600', from: OTHER, to: me, value: '2500000', contractAddress: usdt.address.toLowerCase(), tokenSymbol: 'FAKE', tokenDecimal: '18' },
    { hash: h(8), timeStamp: '1790000700', from: OTHER, to: me, value: '9', contractAddress: '0x' + '99'.repeat(20) },   // unlisted token
  ] };
  const rows = parseBlockscout(native, tokens, ME);
  assert.deepEqual(rows.map(r => [r.hash, r.dir, r.symbol, r.amount, r.status]), [
    [h(7), 'in', 'USDT', '2.5', 'confirmed'],
    [h(2), 'out', 'ETH', '0.000000000000000001', 'failed'],
    [h(1), 'in', 'ETH', '1.5', 'confirmed'],
  ]);
  assert.equal(rows[2].peer, OTHER);
});

test('tron: TRX TransferContract and listed TRC20 only', () => {
  const meT = 'TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7', otherT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
  const native = { data: [
    { txID: 'a'.repeat(64), block_timestamp: 1790000000000, ret: [{ contractRet: 'SUCCESS' }], raw_data: { contract: [{ type: 'TransferContract', parameter: { value: { owner_address: TronWeb.address.toHex(otherT), to_address: TronWeb.address.toHex(meT), amount: 2000000 } } }] } },
    { txID: 'b'.repeat(64), block_timestamp: 1790000001000, raw_data: { contract: [{ type: 'TriggerSmartContract', parameter: { value: {} } }] } },
  ] };
  const tokens = { data: [
    { transaction_id: 'c'.repeat(64), block_timestamp: 1790000002000, from: meT, to: otherT, value: '1000000', token_info: { address: CHAINS.tron.tokens[0].address, decimals: 2, symbol: 'X' } },
    { transaction_id: 'd'.repeat(64), block_timestamp: 1790000003000, from: meT, to: otherT, value: '1', token_info: { address: meT } },   // unlisted contract
  ] };
  const rows = parseTronGrid(native, tokens, meT);
  assert.deepEqual(rows.map(r => [r.hash[0], r.dir, r.symbol, r.amount]), [['c', 'out', CHAINS.tron.tokens[0].symbol, '1.0'], ['a', 'in', 'TRX', '2.0']]);
});

test('solana: the balance change of this account without the fee, and listed token changes', () => {
  const meS = 'vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg', other = '54uJifihfpmTjCGperSxWaZmEHzGFpsaKKEiiGL1fmTs';
  const usdc = CHAINS.solana.tokens.find(t => t.symbol === 'USDC');
  const tx = { blockTime: 1790000000, meta: { err: null, fee: 5000, preBalances: [1000000000, 0], postBalances: [899995000, 100000000],
    preTokenBalances: [{ owner: meS, mint: usdc.address, uiTokenAmount: { amount: '3000000', decimals: 6 } }],
    postTokenBalances: [{ owner: meS, mint: usdc.address, uiTokenAmount: { amount: '1000000', decimals: 6 } }] },
    transaction: { message: { accountKeys: [{ pubkey: meS }, { pubkey: other }], instructions: [{ program: 'system', parsed: { type: 'transfer', info: { source: meS, destination: other, lamports: 100000000 } } }] } } };
  const rows = parseSolanaTransaction('5'.repeat(88), tx, meS);
  assert.deepEqual(rows.map(r => [r.dir, r.symbol, r.amount, r.peer]), [['out', 'SOL', '0.1', other], ['out', 'USDC', '2.0', '']]);
  assert.deepEqual(parseSolanaTransaction('5'.repeat(88), { ...tx, blockTime: 'x' }, meS), []);
});

test('cellframe: CPUNK recv / send rows; other tokens and malformed rows dropped', () => {
  const addr = 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps';
  const data = { type: 2, result: [[{ addr }, { limit: 1000 },
    { status: 'ACCEPTED', hash: '0x' + 'AB'.repeat(32), tx_created: 'Wed, 22 Oct 2025 20:17:27 +0000', data: [{ tx_type: 'recv', recv_datoshi: '1000000000000000000', token: 'CPUNK', source_address: addr }] },
    { status: 'ACCEPTED', hash: '0x' + 'CD'.repeat(32), tx_created: 'Wed, 22 Oct 2025 20:18:27 +0000', data: [{ tx_type: 'recv', recv_datoshi: '1', token: 'CELL' }] },
    { status: 'DECLINED', hash: '0x' + 'EF'.repeat(32), tx_created: 'Wed, 22 Oct 2025 20:19:27 +0000', data: [{ tx_type: 'send', send_datoshi: '5', token: 'CPUNK', destination_address: 'not-an-address' }] },
  ]] };
  const rows = parseCellframeHistory(data, addr);
  assert.deepEqual(rows.map(r => [r.hash.slice(0, 4), r.dir, r.amount, r.status, r.peer === addr]), [['0xef', 'out', '0.000000000000000005', 'failed', false], ['0xab', 'in', '1.0', 'confirmed', true]]);
});

test('saved rows are checked again; merge keeps one row per transfer, newest first, capped', () => {
  const r = { chain: 'ethereum', hash: h(1), time: 1, dir: 'in', symbol: 'ETH', amount: '1.0', peer: OTHER.slice(2), status: 'confirmed' };
  assert.deepEqual(checkHistoryRows('ethereum', [r]), [r]);
  for (const bad of [{ ...r, symbol: 'FAKE' }, { ...r, dir: 'up' }, { ...r, amount: '1e5' }, { ...r, peer: '<b>' }, { ...r, hash: 'x' }, { ...r, chain: 'tron' }])
    assert.throws(() => checkHistoryRows('ethereum', [bad]), /Invalid saved history/);
  assert.throws(() => checkHistoryRows('bsc', []), /Invalid saved history/);
  const many = Array.from({ length: HISTORY_LIMIT + 5 }, (_, i) => ({ ...r, hash: h(i + 10), time: i + 10 }));
  const merged = mergeHistory([r], [{ ...r, status: 'failed' }, ...many]);
  assert.equal(merged.length, HISTORY_LIMIT); assert.equal(merged[0].time, HISTORY_LIMIT + 14);
  assert.equal(mergeHistory([r], [{ ...r, status: 'failed' }]).length, 1);
  assert.equal(mergeHistory([r], [{ ...r, status: 'failed' }])[0].status, 'failed');
});
