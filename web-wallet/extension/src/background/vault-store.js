import { VAULT_KEY, parseVault, encryptVault, decryptVault } from '../../../src/vault.js';
import { newPhrase } from '../../../src/keys.js';
import { validateNodusPhrase } from '../../../src/recovery.js';

// The only persisted phrase store is the existing web-wallet JSON string.
// Transport of the saved vault value is deferred by the approved plan (GAP-8).
export function createVaultStore({ storage, lockCoordinator }) {
  let saving = Promise.resolve();

  async function importVault(value) {
    const vault = parseVault(value);
    const result = saving.then(async () => {
      await lockCoordinator.lock();
      await storage.set({ [VAULT_KEY]: value });
      return { id: vault.id };
    });
    saving = result.catch(() => {});
    return result;
  }

  async function create(password, phrase = newPhrase()) {
    phrase = validateNodusPhrase(phrase);
    const value = await encryptVault(phrase, password);
    const saved = await importVault(value);
    return { ...saved, phrase };
  }

  async function unlock(password) {
    return lockCoordinator.unlock(async () => {
      await saving;
      const saved = await storage.get(VAULT_KEY);
      if (saved[VAULT_KEY] === undefined) throw new Error('No saved wallet.');
      const { phrase, id } = await decryptVault(saved[VAULT_KEY], password);
      return { phrase: validateNodusPhrase(phrase), id };
    });
  }

  // No password, phrase or derived key is retained by this store. Callers own
  // unlocked material and register its disposal with the shared coordinator.
  return { create, importVault, unlock };
}
