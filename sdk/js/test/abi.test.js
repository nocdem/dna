// ABI through the SDK (the wallet's codec, web-wallet/src/evm/abi.js,
// re-exported unchanged) with 32-byte addresses (decision
// 2026-10-04-nodus-evm-domain.md item 3).
// What it proves:
//   - an address whose high 12 bytes are non-zero survives encode -> decode
//     in a call, a tuple, an array and an indexed event topic, as the whole
//     32-byte word;
//   - NEGATIVE CONTROL: the same address with its high 12 bytes zeroed (what
//     a 20-byte / Ethereum codec would keep) encodes to different bytes and
//     decodes to a different address; a 40-hex (20-byte) address is refused,
//     never padded;
//   - the selector and topic are upstream Solidity's (transfer(address,
//     uint256) = 0xa9059cbb, Transfer(address,address,uint256) = 0xddf252ad…);
//   - the example token's ABI (nodus/tools/evm/examples/out/NodusToken.abi.json)
//     loads.
// Requires: `npm ci` in web-wallet/ (the codec's imports). No network, no wasm.
// How it can lie: the codec is checked against itself plus the two pinned
// upstream constants; byte agreement with the Nodus solc is NOT tested here
// (shared/evm/tests/test_example_token.c executes the compiled token).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Interface, parseAddress, toChecksumAddress, selectorOf, topicOf, decodeLog } from '../src/index.js';

const HIGH = 'ff' + 'ee'.repeat(11) + '12'.repeat(20);           // high 12 bytes non-zero
const MASKED = '00'.repeat(12) + HIGH.slice(24);                  // what a 20-byte codec keeps
const ABI = JSON.parse(readFileSync(new URL('../../../nodus/tools/evm/examples/out/NodusToken.abi.json', import.meta.url), 'utf8'));
const hex = b => Buffer.from(b).toString('hex');

test('a high-byte 32-byte address round-trips whole through a call', () => {
  const i = new Interface(ABI);
  const data = i.encodeFunctionData('transfer', [`0x${HIGH}`, 5n]);
  assert.equal(hex(data.subarray(0, 4)), 'a9059cbb');
  assert.equal(hex(data.subarray(4, 36)), HIGH, 'the address word is the full 32 bytes');
  const [to, value] = i.decodeFunctionData('transfer', `0x${hex(data)}`);
  assert.equal(parseAddress(to), HIGH);
  assert.equal(to, toChecksumAddress(HIGH));
  assert.equal(value, 5n);
});

test('negative control: the 20-byte-masked address is a different value and different bytes', () => {
  const i = new Interface(ABI);
  const full = i.encodeFunctionData('transfer', [`0x${HIGH}`, 5n]);
  const masked = i.encodeFunctionData('transfer', [`0x${MASKED}`, 5n]);
  assert.notEqual(hex(full), hex(masked));
  assert.notEqual(parseAddress(i.decodeFunctionData('transfer', `0x${hex(full)}`)[0]), MASKED);
  assert.notEqual(parseAddress(i.decodeFunctionData('transfer', `0x${hex(masked)}`)[0]), HIGH);
  assert.throws(() => parseAddress(`0x${HIGH.slice(24)}`), /20-byte Ethereum address/);
  assert.throws(() => i.encodeFunctionData('transfer', [`0x${HIGH.slice(24)}`, 5n]), /20-byte/);
});

test('tuples and arrays of high-byte addresses round-trip', () => {
  const i = new Interface([{ type: 'function', name: 'f', stateMutability: 'pure', inputs: [
    { name: 'list', type: 'address[]' },
    { name: 'pair', type: 'tuple', components: [{ name: 'a', type: 'address' }, { name: 'n', type: 'uint64' }] }
  ], outputs: [] }]);
  const other = '01' + '00'.repeat(30) + '02';
  const data = i.encodeFunctionData('f', [[`0x${HIGH}`, `0x${other}`], { a: `0x${HIGH}`, n: 7n }]);
  const [list, pair] = i.decodeFunctionData('f', `0x${hex(data)}`);
  assert.deepEqual(list.map(parseAddress), [HIGH, other]);
  assert.equal(parseAddress(pair[0]), HIGH);
  assert.equal(pair[1], 7n);
});

test('an indexed address topic holds all 32 bytes and decodes back (decodeLog)', () => {
  const i = new Interface(ABI);
  assert.equal(selectorOf('transfer(address,uint256)'), '0xa9059cbb');
  assert.equal(topicOf('Transfer(address,address,uint256)'), '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef');
  const topics = i.encodeEventTopics('Transfer', [`0x${HIGH}`, null]);
  assert.equal(topics[1], `0x${HIGH}`);
  const log = {
    topics: [topics[0].slice(2), HIGH, MASKED],
    data: (10n ** 18n).toString(16).padStart(64, '0')
  };
  const ev = decodeLog(ABI, log);
  assert.equal(ev.name, 'Transfer');
  assert.equal(parseAddress(ev.args[0].value), HIGH);
  assert.equal(parseAddress(ev.args[1].value), MASKED);
  assert.notEqual(parseAddress(ev.args[1].value), HIGH);
  assert.equal(ev.args[2].value, 10n ** 18n);
});
