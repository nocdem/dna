// Smart contracts — addresses (src/evm/address.js).
// What it proves:
//   - the 64-digit checksum equals the Nodus solc's own (vectors produced by
//     that compiler: test/fixtures/evm-solc-vectors.json "checksums") and an
//     independent keccak (ethers.keccak256) applied to the README rule;
//   - parsing accepts one-case forms and correct checksums, refuses a wrong
//     checksum, a 20-byte Ethereum address and wrong lengths;
//   - an account's EVM address is SHA3-512(ML-DSA-87 public key)[0..32]
//     (design §2), equal to the first 64 hex of its fingerprint — checked
//     against node:crypto's SHA3-512 (an independent implementation);
//   - the ticket system address is SHA3-512("NDS.EVMWITHDRAW.v1")[0..32]
//     (design §5), same independent hash.
// Requires nothing beyond `npm ci`. How it can lie: the public key used is
// random bytes, not an ML-DSA-87 key; the address rule does not look inside
// the key, so this does not change what is proven.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { keccak256 } from 'ethers';
import { toChecksumAddress, parseAddress, isAddress, evmAddressFromFingerprint, evmAddressFromPublicKey, EVM_WITHDRAW_ADDRESS } from '../src/evm/address.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/evm-solc-vectors.json', import.meta.url), 'utf8'));

function referenceChecksum(hex64) {
  const lower = hex64.toLowerCase();
  const hash = keccak256(Buffer.from(lower, 'ascii')).slice(2);
  return `0x${[...lower].map((c, i) => (/[a-f]/.test(c) && parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c)).join('')}`;
}

test('checksum: the Nodus solc vectors and the README rule agree', () => {
  assert.ok(vectors.checksums.length >= 3);
  for (const { input, checksummed } of vectors.checksums) {
    assert.equal(toChecksumAddress(input), checksummed, input);
    assert.equal(referenceChecksum(input.slice(2)), checksummed, input);
    assert.equal(parseAddress(checksummed), checksummed.slice(2).toLowerCase());
  }
  for (let i = 0; i < 32; i++) {
    const hex = randomBytes(32).toString('hex');
    assert.equal(toChecksumAddress(hex), referenceChecksum(hex));
  }
});

test('parsing: one-case forms pass, a wrong checksum and 20-byte addresses are refused', () => {
  const good = vectors.checksums[0].checksummed;
  const lower = good.slice(2).toLowerCase();
  assert.equal(parseAddress(`0x${lower}`), lower);
  assert.equal(parseAddress(`0x${lower.toUpperCase()}`), lower);
  assert.equal(parseAddress(lower), lower);
  assert.equal(parseAddress(`  ${good}  `), lower);
  // flip the case of one letter: a typing error
  const at = [...good].findIndex((c, i) => i > 1 && /[a-fA-F]/.test(c));
  const typo = good.slice(0, at) + (good[at] === good[at].toUpperCase() ? good[at].toLowerCase() : good[at].toUpperCase()) + good.slice(at + 1);
  assert.throws(() => parseAddress(typo), /typing error/);
  assert.throws(() => parseAddress('0x' + 'ab'.repeat(20)), /20-byte Ethereum address/);
  assert.throws(() => parseAddress('0x' + 'ab'.repeat(31)), /64 hex/);
  assert.throws(() => parseAddress('0x' + 'ab'.repeat(33)), /64 hex/);
  assert.throws(() => parseAddress('0x' + 'g'.repeat(64)), /64 hex/);
  assert.equal(isAddress(typo), false);
  assert.equal(isAddress(good), true);
});

test('an account address is SHA3-512(public key)[0..32] = the fingerprint prefix', () => {
  const pk = new Uint8Array(randomBytes(2592));
  const fp = createHash('sha3-512').update(pk).digest('hex');
  assert.equal(evmAddressFromPublicKey(pk), fp.slice(0, 64));
  assert.equal(evmAddressFromFingerprint(fp), fp.slice(0, 64));
  assert.throws(() => evmAddressFromPublicKey(new Uint8Array(2591)), /public key/);
  assert.throws(() => evmAddressFromFingerprint(fp.toUpperCase()), /Nodus address/);
  assert.throws(() => evmAddressFromFingerprint(fp.slice(0, 126)), /Nodus address/);
});

test('the ticket system address is SHA3-512("NDS.EVMWITHDRAW.v1")[0..32]', () => {
  const expected = createHash('sha3-512').update(Buffer.from('NDS.EVMWITHDRAW.v1', 'ascii')).digest('hex').slice(0, 64);
  assert.equal(EVM_WITHDRAW_ADDRESS, expected);
});
