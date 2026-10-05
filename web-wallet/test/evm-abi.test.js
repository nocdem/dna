// Smart contracts — the Solidity ABI codec with 32-byte addresses
// (src/evm/abi.js).
// What it proves:
//   - every function selector, error selector, event topic and canonical
//     signature of a sample contract equals what the Nodus solc printed for
//     it (test/fixtures/evm-solc-vectors.json, from test/fixtures/
//     evm-sample.sol — `solc --abi --hashes`);
//   - the encoding equals an independent encoder (ethers 6 AbiCoder) byte for
//     byte, with every `address` given to ethers as `uint256` — the Nodus
//     solc's rule 1/2 (nodus/tools/evm/solc/README.md: an address is the full
//     32-byte word, cleanup is the identity);
//   - an address whose upper 12 bytes are not zero survives encode -> decode
//     unchanged (no 160-bit mask anywhere);
//   - decoding is strict (dirty uint8 / bool / bytes4 / int16 words, bad
//     offsets, truncated data are refused);
//   - revert data: Error(string), Panic(uint256) and a custom error of the ABI;
//   - logs: indexed address / uint and an indexed string (its keccak) decode;
//   - red-team 1 F10 — decoding is bounded: aliased-offset bombs (many heads
//     at one large string; many outer heads at one large inner array) are
//     refused by the decoded-byte / decoded-value budgets while the input
//     stays small; a fixed-length array whose heads do not fit the data is
//     refused before its elements are allocated; type nesting, type text
//     length and static head size are bounded at parse time with checked
//     arithmetic; values inside the bounds still decode.
// Requires nothing beyond `npm ci`. How it can lie: ethers is independent of
// this codec but not of the ABI spec text both follow; the solc vectors pin
// signatures and selectors, not encodings (the compiler prints no encoding
// without running code).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AbiCoder, keccak256, toUtf8Bytes } from 'ethers';
import { Interface, decodeRevert, encodeSequence, decodeSequence, parseParam, typeString, ABI_MAX_DEPTH, ABI_MAX_ELEMENTS, ABI_MAX_DECODED_BYTES } from '../src/evm/abi.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/evm-solc-vectors.json', import.meta.url), 'utf8'));
const iface = new Interface(vectors.abi);
const coder = AbiCoder.defaultAbiCoder();
const hex = b => Buffer.from(b).toString('hex');
// two addresses with non-zero upper bytes (a 20-byte mask would change them)
const A1 = '0x' + 'f1'.repeat(12) + '0123456789abcdef0123456789abcdef01234567';
const A2 = '0x80' + '00'.repeat(30) + '01';
const asUint = a => BigInt(a);
const ethersTypes = types => types.map(t => t.replaceAll('address', 'uint256'));

test('selectors, error selectors, event topics and signatures equal the Nodus solc output', () => {
  const fns = Object.entries(vectors.functions);
  assert.equal(iface.functions.length, fns.length);
  for (const [sel, sig] of fns) {
    const f = iface.getFunction(sig);
    assert.equal(f.signature, sig);
    assert.equal(f.selector, `0x${sel}`, sig);
  }
  for (const [sel, sig] of Object.entries(vectors.errors)) assert.equal(iface.errors.find(e => e.signature === sig)?.selector, `0x${sel}`, sig);
  for (const [topic, sig] of Object.entries(vectors.events)) assert.equal(iface.events.find(e => e.signature === sig)?.topic, `0x${topic}`, sig);
});

test('encoding equals ethers with address = uint256 (scalars, bytes, string)', () => {
  const f = iface.getFunction('mixed');
  const args = [255, -300, true, '0xdeadbeef', '0x0102030405', 'héllo, Nodus'];
  const ours = iface.encodeFunctionData(f, args);
  const theirs = coder.encode(ethersTypes(f.inputs.map(typeString)), args);
  assert.equal(`0x${hex(ours.subarray(4))}`, theirs);
  assert.equal(`0x${hex(ours.subarray(0, 4))}`, f.selector);
  const back = iface.decodeFunctionData(f, ours);
  assert.deepEqual(back, [255n, -300n, true, '0xdeadbeef', '0x0102030405', 'héllo, Nodus']);
});

test('encoding equals ethers with address = uint256 (transfer, fixed and dynamic arrays)', () => {
  const t = iface.getFunction('transfer');
  assert.equal(`0x${hex(iface.encodeFunctionData(t, [A1, 10n ** 18n]).subarray(4))}`, coder.encode(ethersTypes(['address', 'uint256']), [asUint(A1), 10n ** 18n]));
  const a = iface.getFunction('arrays');
  const ours = iface.encodeFunctionData(a, [[1n, 2n], [A1, A2, A1]]);
  assert.equal(`0x${hex(ours.subarray(4))}`, coder.encode(ethersTypes(a.inputs.map(typeString)), [[1n, 2n], [A1, A2, A1].map(asUint)]));
  const back = iface.decodeFunctionData(a, ours);
  assert.deepEqual(back[0], [1n, 2n]);
  assert.deepEqual(back[1].map(x => x.toLowerCase()), [A1, A2, A1].map(x => x.toLowerCase()));
});

test('encoding equals ethers with address = uint256 (nested tuples with dynamic members)', () => {
  const n = iface.getFunction('nested');
  const tag = '0x' + 'ab'.repeat(32);
  const deep = [[[A1, 5n], [A2, 6n]], 'a note', tag];
  const pairs = [[A2, 1n], [A1, 2n]];
  const ours = iface.encodeFunctionData(n, [deep, pairs]);
  const theirs = coder.encode(ethersTypes(n.inputs.map(typeString)), [[[[asUint(A1), 5n], [asUint(A2), 6n]], 'a note', tag], [[asUint(A2), 1n], [asUint(A1), 2n]]]);
  assert.equal(`0x${hex(ours.subarray(4))}`, theirs);
  // a tuple may also be given as an object keyed by its component names
  const byName = iface.encodeFunctionData(n, [{ pairs: [{ who: A1, amount: 5n }, { who: A2, amount: 6n }], note: 'a note', tag }, [{ who: A2, amount: 1n }, { who: A1, amount: 2n }]]);
  assert.equal(hex(byName), hex(ours));
  // outputs: the Deep tuple
  const out = encodeSequence(n.outputs, [deep]);
  const [decoded] = iface.decodeFunctionResult(n, out);
  assert.equal(decoded[0][0][0].toLowerCase(), A1.toLowerCase());
  assert.equal(decoded[0][1][1], 6n);
  assert.equal(decoded[1], 'a note');
  assert.equal(decoded[2], tag);
});

test('a full 32-byte address is never masked', () => {
  const node = parseParam({ type: 'address' });
  const enc = encodeSequence([node], [A1]);
  assert.equal(`0x${hex(enc)}`, A1);
  assert.equal(decodeSequence([node], enc)[0].toLowerCase(), A1);
  // every 256-bit word is an address (rule 2: no value is rejected)
  assert.equal(decodeSequence([node], new Uint8Array(32).fill(0xff))[0].toLowerCase(), '0x' + 'f'.repeat(64));
  assert.throws(() => encodeSequence([node], ['0x' + '12'.repeat(20)]), /20-byte/);
});

test('decoding is strict', () => {
  const word = (v) => { const b = new Uint8Array(32); b[31] = v & 0xff; b[30] = (v >> 8) & 0xff; return b; };
  assert.throws(() => decodeSequence([parseParam({ type: 'uint8' })], word(256)), /high bits/);
  assert.throws(() => decodeSequence([parseParam({ type: 'bool' })], word(2)), /0 or 1/);
  const b4 = new Uint8Array(32); b4[0] = 1; b4[4] = 1;
  assert.throws(() => decodeSequence([parseParam({ type: 'bytes4' })], b4), /padding/);
  const i16 = new Uint8Array(32); i16[31] = 0x00; i16[30] = 0x80;   // 0x8000 positive: outside int16
  assert.throws(() => decodeSequence([parseParam({ type: 'int16' })], i16), /sign-extended/);
  assert.throws(() => decodeSequence([parseParam({ type: 'uint256' })], new Uint8Array(31)), /too short/);
  const badOffset = word(0); badOffset[31] = 0x40;                 // string at offset 64 of a 32-byte buffer
  assert.throws(() => decodeSequence([parseParam({ type: 'string' })], badOffset), /outside|short/);
  const longLen = new Uint8Array(64); longLen[31] = 0x20; longLen[63] = 0xff;   // length 255, no data
  assert.throws(() => decodeSequence([parseParam({ type: 'bytes' })], longLen), /outside/);
  const badUtf8 = coder.encode(['bytes'], ['0xff']);
  assert.throws(() => decodeSequence([parseParam({ type: 'string' })], Buffer.from(badUtf8.slice(2), 'hex')), /UTF-8/);
});

test('revert reasons: Error(string), Panic(uint256), a custom error, empty', () => {
  const err = '0x08c379a0' + coder.encode(['string'], ['not owner']).slice(2);
  assert.deepEqual(decodeRevert(err), { kind: 'error', message: 'not owner' });
  const panic = '0x4e487b71' + coder.encode(['uint256'], [0x11n]).slice(2);
  assert.deepEqual(decodeRevert(panic), { kind: 'panic', code: 0x11n, message: 'arithmetic overflow or underflow' });
  const custom = `0x${vectors.errors && Object.keys(vectors.errors)[0]}` + coder.encode(['uint256', 'uint256'], [asUint(A1), 7n]).slice(2);
  const r = iface.decodeRevert(custom);
  assert.equal(r.kind, 'custom'); assert.equal(r.name, 'NotAllowed');
  assert.equal(r.args[0].value.toLowerCase(), A1); assert.equal(r.args[1].value, 7n);
  assert.deepEqual(decodeRevert('0x'), { kind: 'empty' });
  assert.equal(decodeRevert('0x12345678').kind, 'unknown');
});

test('logs: indexed addresses and an indexed string decode; filters encode', () => {
  const moved = iface.events.find(e => e.name === 'Moved');
  const log = { topics: [moved.topic, A1, A2], data: coder.encode(['uint256'], [42n]) };
  const parsed = iface.parseLog(log);
  assert.equal(parsed.name, 'Moved');
  assert.equal(parsed.args[0].value.toLowerCase(), A1);
  assert.equal(parsed.args[1].value.toLowerCase(), A2);
  assert.equal(parsed.args[2].value, 42n);
  const noted = iface.events.find(e => e.name === 'Noted');
  const topicHash = keccak256(toUtf8Bytes('greeting'));
  const p2 = iface.parseLog({ topics: [noted.topic, topicHash], data: coder.encode(['bytes', 'int16'], ['0xaa', -2]) });
  assert.deepEqual(p2.args.map(a => a.value), [{ hash: topicHash }, '0xaa', -2n]);
  assert.deepEqual(iface.encodeEventTopics('Moved', [A1, null]), [moved.topic, A1.toLowerCase(), null]);
  assert.deepEqual(iface.encodeEventTopics('Noted', ['greeting']), [noted.topic, topicHash]);
  assert.equal(iface.parseLog({ topics: ['0x' + '00'.repeat(32)], data: '0x' }), null);
});

test('deploy data is bytecode followed by the encoded constructor arguments', () => {
  const code = '0x6080604052';
  const init = iface.encodeDeploy(code, [A1, 1000n]);
  assert.equal(`0x${hex(init)}`, code + coder.encode(['uint256', 'uint256'], [asUint(A1), 1000n]).slice(2));
  assert.ok(iface.constructorEntry.payable);
  assert.throws(() => iface.encodeDeploy('0x', []), /empty/);
});

test('input checks: ranges, lengths, overloads, unsupported types', () => {
  const f = iface.getFunction('mixed');
  assert.throws(() => iface.encodeFunctionData(f, [256, 0, true, '0x00000000', '0x', '']), /uint8/);
  assert.throws(() => iface.encodeFunctionData(f, [0, 32768, true, '0x00000000', '0x', '']), /int16/);
  assert.throws(() => iface.encodeFunctionData(f, [0, 0, 1, '0x00000000', '0x', '']), /bool/);
  assert.throws(() => iface.encodeFunctionData(f, [0, 0, true, '0x000000', '0x', '']), /bytes4/);
  assert.throws(() => iface.encodeFunctionData(f, [0, 0, true]), /expected 6/);
  assert.throws(() => iface.getFunction('nothere'), /no function/);
  const over = new Interface([{ type: 'function', name: 'f', inputs: [{ type: 'uint256' }] }, { type: 'function', name: 'f', inputs: [{ type: 'address' }] }]);
  assert.throws(() => over.getFunction('f'), /overloaded/);
  assert.equal(over.getFunction('f(address)').signature, 'f(address)');
  assert.throws(() => parseParam({ type: 'function' }), /not supported/);
  assert.throws(() => parseParam({ type: 'uint7' }), /bad integer/);
  assert.equal(typeString(parseParam({ type: 'uint' })), 'uint256');
});

// ── red-team 1 F10: bounded decoding ─────────────────────────────────────
const w = v => BigInt(v).toString(16).padStart(64, '0');
const bytesOf = hex => Uint8Array.from(Buffer.from(hex, 'hex'));

test('F10: aliased offsets — many heads at one large string — trip the decoded-byte budget', () => {
  const N = 1000, LEN = 65536;
  // string[]: head -> 32; len N; N heads all = N × 32 (relative to the
  // array body); ONE string of LEN bytes there
  const hex = w(32) + w(N) + w(N * 32).repeat(N) + w(LEN) + '61'.repeat(LEN);
  const data = bytesOf(hex);
  assert.ok(data.length < 128 * 1024, 'the input stays small');
  assert.ok(N * LEN > ABI_MAX_DECODED_BYTES, 'what it describes is not');
  assert.throws(() => decodeSequence([parseParam({ type: 'string[]' })], data), /more bytes than allowed/);
  // the same layout with few heads decodes (aliasing itself is legal ABI)
  const small = bytesOf(w(32) + w(3) + w(96).repeat(3) + w(2) + '6162' + '00'.repeat(30));
  assert.deepEqual(decodeSequence([parseParam({ type: 'string[]' })], small)[0], ['ab', 'ab', 'ab']);
});

test('F10: aliased offsets — many outer heads at one large inner array — trip the decoded-value budget', () => {
  const N = 400;
  // uint256[][]: head -> 32; outer len N; N heads all = N × 32; ONE inner
  // array of N words there: N × (N + 1) values from ~26 KB
  const hex = w(32) + w(N) + w(N * 32).repeat(N) + w(N) + w(7).repeat(N);
  const data = bytesOf(hex);
  assert.ok(N * (N + 1) > ABI_MAX_ELEMENTS);
  assert.throws(() => decodeSequence([parseParam({ type: 'uint256[][]' })], data), /more values than allowed/);
});

test('F10: a fixed-length array whose heads do not fit the data is refused before allocation', () => {
  assert.throws(() => decodeSequence([parseParam({ type: 'uint8[100000]' })], new Uint8Array(64)), /array length outside the data/);
  // static array of a dynamic type: 50 000 heads, 64 bytes of data
  assert.throws(() => decodeSequence([parseParam({ type: 'string[50000]' })], bytesOf(w(32) + w(0))), /array length outside the data/);
  // a dynamic array length far beyond any budget is refused before Number()
  assert.throws(() => decodeSequence([parseParam({ type: 'uint256[]' })], bytesOf(w(32) + 'f'.repeat(64))), /array length outside the data/);
  // an array of empty tuples has a zero-size head: only the value budget bounds it
  const empty = parseParam({ type: 'tuple[]', components: [] });
  assert.throws(() => decodeSequence([empty], bytesOf(w(32) + w(ABI_MAX_ELEMENTS + 1))), /array length outside the data|more values than allowed/);
  assert.deepEqual(decodeSequence([empty], bytesOf(w(32) + w(2))), [[[], []]]);
});

test('F10: types are bounded at parse time (nesting, text, head size with checked arithmetic)', () => {
  assert.throws(() => parseParam({ type: `uint256${'[]'.repeat(ABI_MAX_DEPTH + 1)}` }), /nested too deeply/);
  assert.doesNotThrow(() => parseParam({ type: `uint256${'[]'.repeat(ABI_MAX_DEPTH)}` }));
  let deep = { type: 'uint256' };
  for (let i = 0; i < ABI_MAX_DEPTH + 1; i++) deep = { type: 'tuple', components: [deep] };
  assert.throws(() => parseParam(deep), /nested too deeply/);
  assert.throws(() => parseParam({ type: `uint256${'[1]'.repeat(400)}` }), /too long|nested too deeply/);
  assert.throws(() => parseParam({ type: 'uint256[1000000]' }), /too large/);
  assert.throws(() => parseParam({ type: 'uint256[65536][65536]' }), /too large/);
  assert.throws(() => parseParam({ type: 'uint256[9007199254740993]' }), /bad array length/);
  assert.throws(() => parseParam({ type: 'uint8[2]x' }), /bad type/);
  // a large but bounded static type still parses and keeps its exact head size
  const node = parseParam({ type: 'uint8[1000][16]' });
  assert.equal(node.head, 1000 * 16 * 32);
  // an ABI entry's parameters are parsed one by one (Array#map passes an
  // index as a second argument — it must not count as nesting depth)
  const many = Array.from({ length: ABI_MAX_DEPTH + 5 }, () => ({ type: 'uint256[]' }));
  assert.doesNotThrow(() => new Interface([{ type: 'function', name: 'g', inputs: many }]));
});
