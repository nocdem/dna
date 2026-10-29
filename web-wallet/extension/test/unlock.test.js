import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getAddress, getBytes, verifyMessage } from 'ethers';
import { VAULT_KEY, encryptVault, parseVault } from '../../src/vault.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { createVaultStore } from '../src/background/vault-store.js';
import { createKeyring } from '../src/background/keyring.js';
import { createWalletKeys } from '../src/background/wallet-keys.js';
import { createUnlock } from '../src/background/unlock.js';
import { createAutoLockAlarm, AUTO_LOCK_TIMEOUT_ALARM } from '../src/background/auto-lock-alarm.js';

// Node >=22.14, pinned packages, existing CPUNK WASM; no network or persistent output.
// Public phrase/password pattern from extension/test/vault-store.test.js and test/vault.test.js.
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-test-password-123';
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
function memoryStorage(initial = {}) {
  const values = structuredClone(initial), writes = [];
  return {
    values, writes,
    async get(key) { return key === null ? structuredClone(values) : Object.hasOwn(values, key) ? { [key]: values[key] } : {}; },
    async set(items) { writes.push(structuredClone(items)); Object.assign(values, structuredClone(items)); },
  };
}
function setup(storage, consumeNodusSeed = () => {}) {
  const lockCoordinator = createLockCoordinator();
  const vaultStore = createVaultStore({ storage, lockCoordinator });
  const walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed });
  const keyring = createKeyring({ lockCoordinator, getWallet: walletKeys.getEvmWallet });
  const unlock = createUnlock({ vaultStore, lockCoordinator, keyring, walletKeys });
  return { lockCoordinator, vaultStore, keyring, walletKeys, unlock };
}
async function assertOnlyVault(storage, value) {
  assert.deepEqual(await storage.get(null), { [VAULT_KEY]: value });
  for (const write of storage.writes) {
    assert.deepEqual(Object.keys(write), [VAULT_KEY]);
    parseVault(write[VAULT_KEY]);
    assert.ok(!JSON.stringify(write).includes(phrase)); assert.ok(!JSON.stringify(write).includes(password));
  }
}

// Proves create/import/unlock/sign/lock persist only the original web vault; a final-only snapshot could miss temporary keyring-vault or phrase writes.
test('the sole persisted value remains the web-wallet vault through create, import and signing', async () => {
  for (const imported of [false, true]) {
    const storage = memoryStorage();
    let seed;
    const { lockCoordinator, vaultStore, keyring, walletKeys, unlock } = setup(storage, value => { seed = value; });
    let value;
    if (imported) {
      value = JSON.stringify(JSON.parse(await encryptVault(phrase, password)), null, 2);
      await vaultStore.importVault(value);
    } else {
      await vaultStore.create(password, phrase); value = storage.values[VAULT_KEY];
    }
    await assertOnlyVault(storage, value);
    const result = await unlock(password, { cpunkWasmBytes });
    assert.equal(result.id, parseVault(value).id);
    assert.deepEqual(Object.keys(result).sort(), ['addresses', 'id']);
    assert.equal(JSON.stringify(result).includes(phrase), false);
    assert.equal(result.addresses.ethereum, '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
    assert.equal(result.addresses.ethereum, result.addresses.bsc);
    assert.equal(result.addresses.solana, walletKeys.getAddresses().solana);
    assert.ok(seed.every(byte => byte === 0));
    const signature = await keyring.signPersonalMessage({ from: result.addresses.ethereum, data: '0x1234' });
    assert.equal(verifyMessage(getBytes('0x1234'), signature), getAddress(result.addresses.ethereum));
    await assertOnlyVault(storage, value);
    assert.deepEqual(await lockCoordinator.lock(), []);
    await assertOnlyVault(storage, value);
    assert.equal(storage.writes.length, 1);
    await assert.rejects(keyring.getAccounts(), /locked/i);
    assert.throws(walletKeys.getSolanaKeypair, /locked/i); assert.throws(walletKeys.getTronPrivateKey, /locked/i);
    const restarted = setup(storage);
    assert.equal(restarted.lockCoordinator.isLocked, true);
    await assert.rejects(restarted.keyring.getAccounts(), /locked/i);
    assert.throws(restarted.walletKeys.getSolanaKeypair, /locked/i);
  }
});

// Proves the wrapper drops the vault result's phrase reference after both success and failure; checking only its returned object would miss a retained authentication object.
test('the phrase hand-over is cleared on success and on consumer failure', async () => {
  for (const fails of [false, true]) {
    const lockCoordinator = createLockCoordinator();
    const walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed: () => { if (fails) throw new Error('consumer failure'); } });
    const keyring = createKeyring({ lockCoordinator, getWallet: walletKeys.getEvmWallet });
    const authenticated = { phrase, id: 'public-test-id' };
    // Authentication seam mock only; integration above uses real PBKDF2/AES-GCM.
    const vaultStore = { unlock: () => lockCoordinator.unlock(async () => authenticated) };
    const unlock = createUnlock({ vaultStore, lockCoordinator, keyring, walletKeys });
    try {
      if (fails) await assert.rejects(unlock(password, { cpunkWasmBytes }), /consumer failure/);
      else assert.equal((await unlock(password, { cpunkWasmBytes })).id, authenticated.id);
      assert.equal(authenticated.phrase, null);
      if (fails) {
        assert.equal(lockCoordinator.isLocked, true);
        await assert.rejects(keyring.getAccounts(), /locked/i);
      }
    } finally { await lockCoordinator.lock(); }
  }
});

// Proves failed authentication leaves every holder locked and never consumes a seed; checking only the password error could hide partial activation.
test('a wrong vault password leaves all holders locked', async () => {
  const storage = memoryStorage(); let calls = 0;
  const { vaultStore, unlock, lockCoordinator, keyring, walletKeys } = setup(storage, () => { calls++; });
  await vaultStore.create(password, phrase);
  await assert.rejects(unlock('wrong-public-password-123', { cpunkWasmBytes }), /password|unlock/i);
  assert.equal(calls, 0); assert.equal(lockCoordinator.isLocked, true);
  await assert.rejects(keyring.getAccounts(), /locked/i);
  assert.throws(walletKeys.getTronPrivateKey, /locked/i);
});

// Proves a lock during injected-consumer work rolls back the EVM holder too; checking only the wallet-keys module could miss the joined unlock path.
test('lock during the joined unlock cannot reactivate either holder', async () => {
  const storage = memoryStorage(); let release, entered, seed;
  const waiting = new Promise(resolve => { entered = resolve; });
  const { vaultStore, unlock, lockCoordinator, keyring, walletKeys } = setup(storage, async value => {
    seed = value; entered(); await new Promise(resolve => { release = resolve; });
  });
  await vaultStore.create(password, phrase);
  const unlocking = unlock(password, { cpunkWasmBytes }), rejected = assert.rejects(unlocking, /locked/i);
  await waiting;
  try { await lockCoordinator.lock(); } finally { release(); }
  await rejected;
  assert.equal(lockCoordinator.isLocked, true); assert.ok(seed.every(byte => byte === 0));
  await assert.rejects(keyring.getAccounts(), /locked/i);
  assert.throws(walletKeys.getSolanaKeypair, /locked/i); assert.throws(walletKeys.getTronPrivateKey, /locked/i);
});

// Proves the real alarm joins the same holders with no interface open; a direct manual-lock-only test would miss alarm wiring.
test('background inactivity lock revokes the derived keys and EVM signer', async () => {
  const storage = memoryStorage();
  const { vaultStore, unlock, lockCoordinator, keyring, walletKeys } = setup(storage);
  let onAlarm;
  const alarms = { async clear() {}, async create() {}, onAlarm: { addListener(fn) { onAlarm = fn; } } };
  await createAutoLockAlarm({ storage, alarms, lockCoordinator });
  await vaultStore.create(password, phrase);
  const { addresses } = await unlock(password, { cpunkWasmBytes });
  const secret = walletKeys.getSolanaKeypair().secretKey;
  const pendingAccess = Promise.resolve().then(() => walletKeys.getTronPrivateKey());
  const rejected = assert.rejects(pendingAccess, /locked/i);
  await onAlarm({ name: AUTO_LOCK_TIMEOUT_ALARM });
  await rejected;
  assert.ok(secret.every(byte => byte === 0));
  await assert.rejects(keyring.signPersonalMessage({ from: addresses.ethereum, data: '0x1234' }), /locked/i);
  assert.throws(walletKeys.getSolanaKeypair, /locked/i); assert.throws(walletKeys.getTronPrivateKey, /locked/i);
});

// Proves the nested vault unlock cannot expose a partially initialized signer; checking only after the joined unlock resolves would miss early signing.
test('keys remain inaccessible until the entire joined unlock succeeds', async () => {
  const storage = memoryStorage(); let release, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  const { vaultStore, unlock, lockCoordinator, keyring, walletKeys } = setup(storage, async () => {
    entered(); await new Promise(resolve => { release = resolve; });
  });
  await vaultStore.create(password, phrase);
  const unlocking = unlock(password, { cpunkWasmBytes });
  await waiting;
  try {
    await assert.rejects(keyring.getAccounts(), /locked/i);
    await assert.rejects(keyring.signPersonalMessage({ from: '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb', data: '0x1234' }), /locked/i);
    assert.throws(walletKeys.getSolanaKeypair, /locked/i);
    assert.throws(walletKeys.getTronPrivateKey, /locked/i);
    await assert.rejects(unlock(password, { cpunkWasmBytes }), /pending/);
  } finally { release(); }
  try {
    const { addresses } = await unlocking;
    const signature = await keyring.signPersonalMessage({ from: addresses.ethereum, data: '0x1234' });
    assert.equal(verifyMessage(getBytes('0x1234'), signature), addresses.ethereum);
    assert.ok(walletKeys.getTronPrivateKey());
  } finally { await lockCoordinator.lock(); }
});
