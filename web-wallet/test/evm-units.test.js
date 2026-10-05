// Smart contracts — value units (src/evm/units.js).
// What it proves: 1 raw NODUS unit = 10^10 wei (design
// docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §5, operator
// decision k1 #3), a withdrawal moves whole raw units only and the rest stays
// (never rounded), 18-decimal formatting and strict parsing, the 32-byte
// value word. Requires nothing beyond `npm ci`. How it can lie: the expected
// values are written here from the decision's numbers; it does not show the
// node uses the same q (the C side pins DNA_EVM_Q == NODUS_RT_EVM_Q by a
// _Static_assert in crypto/nodus-send-wasm.c).
import test from 'node:test';
import assert from 'node:assert/strict';
import { WEI_PER_RAW, rawToWei, weiToRaw, formatUnits, parseUnits, formatWei, parseWei, formatRaw, parseRaw, weiToWord, wordToWei } from '../src/evm/units.js';

test('one raw unit is 10^10 wei; 1 NODUS (10^8 raw) is 10^18 wei', () => {
  assert.equal(WEI_PER_RAW, 10_000_000_000n);
  assert.equal(rawToWei(1n), 10n ** 10n);
  assert.equal(rawToWei('100000000'), 10n ** 18n);
  assert.equal(rawToWei(2n ** 64n - 1n), (2n ** 64n - 1n) * 10n ** 10n);
  assert.throws(() => rawToWei(2n ** 64n), /out of range/);
  assert.throws(() => rawToWei(-1n), /out of range/);
  assert.throws(() => rawToWei('1.5'), /Invalid/);
});

test('wei -> raw keeps the remainder; nothing is rounded', () => {
  assert.deepEqual(weiToRaw(10n ** 18n), { raw: 10n ** 8n, rest: 0n });
  assert.deepEqual(weiToRaw(10n ** 10n - 1n), { raw: 0n, rest: 10n ** 10n - 1n });
  assert.deepEqual(weiToRaw(3n * 10n ** 10n + 7n), { raw: 3n, rest: 7n });
  assert.throws(() => weiToRaw(2n ** 256n), /out of range/);
});

test('formatting and strict parsing', () => {
  assert.equal(formatWei(10n ** 18n), '1');
  assert.equal(formatWei(15n * 10n ** 17n), '1.5');
  assert.equal(formatWei(1n), '0.000000000000000001');
  assert.equal(formatWei(0n), '0');
  assert.equal(formatRaw(150000000n), '1.5');
  assert.equal(formatUnits(1234n, 0), '1234');
  assert.equal(parseWei('1.5'), 15n * 10n ** 17n);
  assert.equal(parseWei('0.000000000000000001'), 1n);
  assert.equal(parseRaw('0.00000001'), 1n);
  assert.equal(parseRaw('184467440737.09551615'), 2n ** 64n - 1n);
  assert.equal(parseUnits('7', 0), 7n);
  for (const bad of ['', '-1', '1e3', '01', '1.', '.5', '1,5', ' ', '0x10']) assert.throws(() => parseWei(bad), Error, bad);
  assert.throws(() => parseRaw('0.000000001'), /decimal places/);
  assert.throws(() => parseRaw('184467440737.09551616'), /out of range/);
});

test('the value word is the 32-byte big-endian u256', () => {
  assert.equal(weiToWord(0n), '0'.repeat(64));
  assert.equal(weiToWord(10n ** 18n), '0000000000000000000000000000000000000000000000000de0b6b3a7640000');
  assert.equal(weiToWord(2n ** 256n - 1n), 'f'.repeat(64));
  assert.equal(wordToWei(weiToWord(123456789n)), 123456789n);
  assert.throws(() => weiToWord(2n ** 256n), /out of range/);
  assert.throws(() => wordToWei('F'.repeat(64)), /Invalid/);
});
