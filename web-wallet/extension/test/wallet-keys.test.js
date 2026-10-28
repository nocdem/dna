import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SLIP10Node } from '@metamask/key-tree';
import { getAddressDecoder } from '@solana/kit';
import { TronWeb } from 'tronweb';
import { sha3_512 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { deriveWallet, disposeWallet } from '../../src/keys.js';
import { nodusSigningSeed, deriveNodusAddress } from '../../src/nodus/derive.js';
import { deriveCpunkAddress } from '../../src/cpunk/derive.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { createWalletKeys } from '../src/background/wallet-keys.js';

// Node >=22.14; existing WASM artifacts only, offline, no persistent output.
// Phrases/native Nodus outputs: test/nodus-address.test.js; external address
// literals: test/wallet.test.js. CPUNK comparison uses the web-wallet function;
// WASM injection follows test/cpunk-derive.test.js (its fixtures have 12 words).
const { vectors } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url)));
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const nodusWasmBytes = readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url));
const options = { cpunkWasmBytes };
const phrase = vectors[0].phrase;

// Proves Nodus vector parity, CPUNK hand-over and independent key-tree parity; CPUNK still shares its reference function and cannot detect a defect inside that function.
test('web-wallet hand-over agrees with existing vectors and the snap key-tree paths', async () => {
  for (const { phrase, address } of vectors) {
    const lockCoordinator = createLockCoordinator();
    let handedSeed, nodusAddress;
    const keys = createWalletKeys({ lockCoordinator, consumeNodusSeed: async seed => {
      handedSeed = seed;
      const expected = nodusSigningSeed(phrase);
      try { assert.equal(seed.length, 32); assert.deepEqual(seed, expected); } finally { expected.fill(0); }
      // Test consumer only: src/nodus/derive.js:36-48, replaced by package 6's module.
      const { instance } = await WebAssembly.instantiate(nodusWasmBytes, {});
      try {
        instance.exports._initialize?.();
        const memory = new Uint8Array(instance.exports.memory.buffer);
        memory.set(seed, instance.exports.nodus_input());
        assert.equal(instance.exports.nodus_derive(), 0);
        const offset = instance.exports.nodus_output();
        nodusAddress = bytesToHex(sha3_512(memory.subarray(offset, offset + 2592)));
      } finally { new Uint8Array(instance.exports.memory.buffer).fill(0); }
    } });
    const expected = deriveWallet(phrase);
    try {
      await lockCoordinator.unlock(() => keys.unlock(phrase, options));
      const addresses = keys.getAddresses(), solana = keys.getSolanaKeypair(), tronKey = keys.getTronPrivateKey();
      assert.equal(addresses.solana, expected.addresses.solana);
      assert.equal(addresses.tron, expected.addresses.tron);
      assert.deepEqual(solana.secretKey, expected.solana.secretKey);
      assert.equal(tronKey, expected.tronPrivateKey);
      const solanaNode = await SLIP10Node.fromDerivationPath({ curve: 'ed25519', derivationPath: [`bip39:${phrase}`, "slip10:44'", "slip10:501'", "slip10:0'", "slip10:0'"] });
      const tronNode = await SLIP10Node.fromDerivationPath({ curve: 'secp256k1', derivationPath: [`bip39:${phrase}`, "bip32:44'", "bip32:195'", "bip32:0'", 'bip32:0', 'bip32:0'] });
      try {
        assert.deepEqual(solana.secretKey.subarray(0, 32), solanaNode.privateKeyBytes);
        assert.equal(addresses.solana, getAddressDecoder().decode(solanaNode.publicKeyBytes.slice(1)));
        assert.equal(tronKey, bytesToHex(tronNode.privateKeyBytes));
        assert.equal(addresses.tron, TronWeb.address.fromPrivateKey(bytesToHex(tronNode.privateKeyBytes)));
      } finally { solanaNode.privateKeyBytes.fill(0); tronNode.privateKeyBytes.fill(0); }
      assert.equal(nodusAddress, address);
      assert.equal(nodusAddress, await deriveNodusAddress(phrase, { wasmBytes: nodusWasmBytes }));
      assert.equal(addresses.cpunk, await deriveCpunkAddress(phrase, { wasmBytes: cpunkWasmBytes }));
      if (phrase === vectors[0].phrase) {
        assert.equal(addresses.solana, '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx');
        assert.equal(addresses.tron, 'TEfhiqsW1SdN44DeHrAWVmbyr8ZbvChrtS');
      }
      assert.ok(handedSeed.every(byte => byte === 0));
      await lockCoordinator.lock();
      assert.ok(solana.secretKey.every(byte => byte === 0));
    } finally { disposeWallet(expected); await lockCoordinator.lock(); }
  }
});

// Proves all accessors reject before unlock and after disposal, including retained access functions; testing only the coordinator would miss unguarded key access.
test('all key access is refused on startup and after lock', async () => {
  const lockCoordinator = createLockCoordinator();
  let seed;
  const keys = createWalletKeys({ lockCoordinator, consumeNodusSeed: value => { seed = value; } });
  const accessors = [keys.getAddresses, keys.getEvmWallet, keys.getSolanaKeypair, keys.getTronPrivateKey];
  for (const access of accessors) assert.throws(access, /locked/i);
  await lockCoordinator.unlock(() => keys.unlock(phrase, options));
  const secretKey = keys.getSolanaKeypair().secretKey;
  assert.ok(secretKey.some(byte => byte !== 0)); assert.ok(seed.every(byte => byte === 0));
  assert.deepEqual(await lockCoordinator.lock(), []);
  assert.ok(secretKey.every(byte => byte === 0));
  for (const access of accessors) assert.throws(access, /locked/i);
});

// Proves the seed is wiped even on consumer failure and no partial wallet survives; a success-only consumer would miss the finally branch.
test('consumer failure zeroes the Nodus seed and disposes the wallet', async () => {
  const lockCoordinator = createLockCoordinator();
  let seed;
  const keys = createWalletKeys({ lockCoordinator, consumeNodusSeed: value => { seed = value; throw new Error('consumer failure'); } });
  await assert.rejects(lockCoordinator.unlock(() => keys.unlock(phrase, options)), /consumer failure/);
  assert.equal(lockCoordinator.isLocked, true);
  assert.equal(seed.length, 32); assert.ok(seed.every(byte => byte === 0));
  assert.throws(keys.getSolanaKeypair, /locked/i); assert.throws(keys.getTronPrivateKey, /locked/i);
});

// Proves lock aborts an in-flight hand-over, wipes its seed and prevents late publication; immediate consumers cannot exercise the race.
test('lock while the Nodus consumer waits cannot resurrect the keys', async () => {
  const lockCoordinator = createLockCoordinator();
  let seed, signal, entered, release;
  const waiting = new Promise(resolve => { entered = resolve; });
  const keys = createWalletKeys({ lockCoordinator, consumeNodusSeed: async (value, context) => {
    seed = value; signal = context.signal; entered(); await new Promise(resolve => { release = resolve; });
  } });
  const unlocking = lockCoordinator.unlock(() => keys.unlock(phrase, options));
  const rejected = assert.rejects(unlocking, /locked/i);
  await waiting;
  try {
    await lockCoordinator.lock();
    assert.equal(signal.aborted, true); assert.ok(seed.every(byte => byte === 0));
  } finally { release(); }
  await rejected;
  assert.throws(keys.getSolanaKeypair, /locked/i); assert.throws(keys.getTronPrivateKey, /locked/i);
});

// Proves CPUNK loading failure disposes already derived keys; a consumer-only failure would not cover the second asynchronous boundary.
test('CPUNK failure leaves no accessible wallet keys', async () => {
  const lockCoordinator = createLockCoordinator();
  let seed;
  const keys = createWalletKeys({ lockCoordinator, consumeNodusSeed: value => { seed = value; } });
  await assert.rejects(lockCoordinator.unlock(() => keys.unlock(phrase, { cpunkWasmBytes: new Uint8Array() })), WebAssembly.CompileError);
  assert.ok(seed.every(byte => byte === 0));
  assert.throws(keys.getSolanaKeypair, /locked/i); assert.throws(keys.getTronPrivateKey, /locked/i);
});
