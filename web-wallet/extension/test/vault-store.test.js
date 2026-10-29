import test from 'node:test';
import assert from 'node:assert/strict';
import { VAULT_KEY, ACTIVITY_KEY, BALANCES_KEY, HISTORY_KEY, ADDRESS_BOOK_KEY, encryptVault, decryptVault, parseVault } from '../../src/vault.js';
import { validateNodusPhrase } from '../../src/recovery.js';
import { createVaultStore } from '../src/background/vault-store.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { activityKeyFor, serializeActivity, parseActivity } from '../../src/activity-storage.js';

// Public fixture from web-wallet/test/vault.test.js; encryption uses the real vault parameters.
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-test-password-123';
function memoryStorage(initial = {}) {
  const values = structuredClone(initial), writes = [];
  return {
    values, writes,
    async get(key) { return key === null ? structuredClone(values) : Object.hasOwn(values, key) ? { [key]: values[key] } : {}; },
    async set(items) { writes.push(structuredClone(items)); Object.assign(values, structuredClone(items)); },
    async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; },
  };
}
async function assertOnlyVault(storage, value) {
  assert.deepEqual(await storage.get(null), { [VAULT_KEY]: value });
  for (const write of storage.writes) {
    assert.deepEqual(Object.keys(write), [VAULT_KEY]);
    assert.equal(typeof write[VAULT_KEY], 'string');
    parseVault(write[VAULT_KEY]);
    assert.ok(!JSON.stringify(write).includes(phrase));
    assert.ok(!JSON.stringify(write).includes(password));
  }
}

// Proves phrase creation, unlock and lock persist one real vault; checking only the final snapshot could miss transient secret writes.
test('create from a phrase, unlock and lock keep only the web-wallet vault value', async () => {
  const storage = memoryStorage(), lockCoordinator = createLockCoordinator();
  const store = createVaultStore({ storage, lockCoordinator });
  const created = await store.create(password, `  ${phrase.toUpperCase()}  `);
  assert.equal(created.phrase, phrase);
  const value = storage.values[VAULT_KEY];
  assert.equal(created.id, parseVault(value).id);
  assert.equal((await decryptVault(value, password)).phrase, phrase);
  await assertOnlyVault(storage, value);
  assert.deepEqual(await store.unlock(password), created);
  lockCoordinator.assertUnlocked();
  await assertOnlyVault(storage, value);
  await lockCoordinator.lock();
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  await assertOnlyVault(storage, value);
  assert.equal(storage.writes.length, 1);
});

// Package I: real password derivation and id preservation; populate every
// cache bucket before delete. No flags/network/artifacts. An empty fixture
// would falsely pass deletion while missing the per-network records.
test('change password preserves vault id and delete locks and removes every wallet bucket', async () => {
  const storage = memoryStorage(), lockCoordinator = createLockCoordinator(), store = createVaultStore({ storage, lockCoordinator });
  const original = await store.create(password, phrase), newer = 'public-new-password-456';
  const activity = await serializeActivity(original.id, [], await activityKeyFor(phrase, original.id)); storage.values[ACTIVITY_KEY] = activity;
  await store.changePassword(password, newer);
  await assert.rejects(store.unlock(password));
  assert.equal((await store.unlock(newer)).id, original.id);
  assert.equal(storage.values[ACTIVITY_KEY], activity);
  assert.deepEqual(await parseActivity(storage.values[ACTIVITY_KEY], original.id, {}, await activityKeyFor(phrase, original.id)), []);
  for (const key of [BALANCES_KEY, HISTORY_KEY, ADDRESS_BOOK_KEY, `${ACTIVITY_KEY}.solana.devnet`, `${HISTORY_KEY}.tron.nile`]) storage.values[key] = 'public encrypted fixture';
  storage.values.unrelated = 'keep';
  await store.deleteVault(); assert.equal(lockCoordinator.isLocked, true);
  assert.deepEqual(storage.values, { unrelated: 'keep' });
});

// Proves the existing generator produces an accepted 24-word phrase; a nonempty-string check could accept an invalid mnemonic.
test('create without a supplied phrase uses a new 24-word web-wallet phrase', async () => {
  const storage = memoryStorage(), lockCoordinator = createLockCoordinator();
  const store = createVaultStore({ storage, lockCoordinator });
  const created = await store.create(password);
  assert.equal(validateNodusPhrase(created.phrase), created.phrase);
  assert.equal(created.phrase.split(' ').length, 24);
  const value = storage.values[VAULT_KEY];
  assert.equal((await decryptVault(value, password)).phrase, created.phrase);
  assert.ok(!value.includes(created.phrase));
  await assertOnlyVault(storage, value);
});

// Proves migration preserves the original JSON and password across restart; re-encrypting with this implementation could hide incompatibility.
test('import a saved web-wallet value unchanged, unlock it and lock it', async () => {
  const value = JSON.stringify(JSON.parse(await encryptVault(phrase, password)), null, 2);
  const storage = memoryStorage(), first = createLockCoordinator();
  await createVaultStore({ storage, lockCoordinator: first }).importVault(value);
  await assertOnlyVault(storage, value);
  const lockCoordinator = createLockCoordinator(), store = createVaultStore({ storage, lockCoordinator });
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  assert.deepEqual(await store.unlock(password), { phrase, id: parseVault(value).id });
  lockCoordinator.assertUnlocked();
  await assertOnlyVault(storage, value);
  await lockCoordinator.lock();
  await assertOnlyVault(storage, value);
  assert.equal(storage.writes.length, 1);
});

// Proves a real wrong password cannot unlock or rewrite storage; rejection for a missing vault would falsely pass a generic rejects check.
test('wrong password leaves a saved wallet locked and unchanged', async () => {
  const value = await encryptVault(phrase, password), storage = memoryStorage({ [VAULT_KEY]: value });
  const lockCoordinator = createLockCoordinator(), store = createVaultStore({ storage, lockCoordinator });
  await assert.rejects(store.unlock('incorrect-password-123'), /Incorrect password/);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  await assertOnlyVault(storage, value);
  assert.equal(storage.writes.length, 0);
  assert.equal((await store.unlock(password)).phrase, phrase);
});

// Proves length, checksum and new-password checks precede persistence; testing only malformed words would miss valid 12-word phrases.
test('invalid phrases and weak new passwords do not write a vault', async () => {
  const storage = memoryStorage(), lockCoordinator = createLockCoordinator();
  const store = createVaultStore({ storage, lockCoordinator });
  for (const invalid of ['', 'abandon '.repeat(23) + 'abandon', 'abandon '.repeat(11) + 'about', 'unknown '.repeat(24), null]) {
    await assert.rejects(store.create(password, invalid), /phrase/);
  }
  for (const invalid of ['short', 'passwordwallet1!', 'a'.repeat(1025)]) await assert.rejects(store.create(invalid, phrase));
  assert.deepEqual(await storage.get(null), {});
  assert.equal(storage.writes.length, 0);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
});

// Proves the vault parser rejects incompatible imports before replacing a good value; accepting only broken JSON would miss schema/parameter bypasses.
test('invalid saved vault imports leave the existing vault intact', async () => {
  const value = await encryptVault(phrase, password), vault = parseVault(value);
  const storage = memoryStorage({ [VAULT_KEY]: value }), lockCoordinator = createLockCoordinator();
  const store = createVaultStore({ storage, lockCoordinator });
  const invalid = [null, vault, 'not json', '{}', ' '.repeat(6001), JSON.stringify({ ...vault, recoveryPhrase: phrase })];
  for (const field of ['version', 'iterations', 'cipher', 'kdf', 'iv', 'salt', 'id', 'ciphertext']) invalid.push(JSON.stringify({ ...vault, [field]: 0 }));
  for (const text of invalid) await assert.rejects(store.importVault(text));
  await assertOnlyVault(storage, value);
  assert.equal(storage.writes.length, 0);
});

// Proves missing storage cannot authenticate; testing a wrong password alone would never exercise the missing-value branch.
test('unlock without a saved vault fails while locked', async () => {
  const storage = memoryStorage(), lockCoordinator = createLockCoordinator();
  await assert.rejects(createVaultStore({ storage, lockCoordinator }).unlock(password), /No saved wallet/);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  assert.deepEqual(await storage.get(null), {});
});

// Proves a lock during an awaited vault read cancels unlock; a sequential unlock-then-lock test could miss stale completion reopening signing.
test('manual lock invalidates an unlock already reading the saved vault', async () => {
  const value = await encryptVault(phrase, password), storage = memoryStorage({ [VAULT_KEY]: value });
  let release, reading;
  const entered = new Promise(resolve => { reading = resolve; });
  storage.get = () => new Promise(resolve => { release = () => resolve({ [VAULT_KEY]: value }); reading(); });
  const lockCoordinator = createLockCoordinator(), store = createVaultStore({ storage, lockCoordinator });
  const unlocking = store.unlock(password);
  const rejected = assert.rejects(unlocking, /locked/);
  await entered;
  await lockCoordinator.lock();
  release();
  await rejected;
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  assert.equal(storage.writes.length, 0);
});

// Proves unlock waits for replacement storage to settle; instantly-resolving set() would hide authentication against the old vault during import.
test('unlock does not read an old vault while a replacement write is pending', async () => {
  const previous = await encryptVault(phrase, password), replacement = await encryptVault(phrase, password);
  const storage = memoryStorage({ [VAULT_KEY]: previous }), lockCoordinator = createLockCoordinator();
  const store = createVaultStore({ storage, lockCoordinator }), set = storage.set.bind(storage), get = storage.get.bind(storage);
  let release, entered, reads = 0;
  const writing = new Promise(resolve => { entered = resolve; });
  storage.set = async items => { entered(); await new Promise(resolve => { release = resolve; }); await set(items); };
  storage.get = async key => { reads++; return get(key); };
  const importing = store.importVault(replacement);
  await writing;
  const unlocking = store.unlock(password);
  assert.equal(reads, 0);
  release();
  await importing;
  assert.equal((await unlocking).id, parseVault(replacement).id);
  assert.equal(storage.values[VAULT_KEY], replacement);
  assert.equal(reads, 1);
});
