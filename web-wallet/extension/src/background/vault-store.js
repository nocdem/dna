import { VAULT_KEY, ACTIVITY_KEY, BALANCES_KEY, HISTORY_KEY, ADDRESS_BOOK_KEY, parseVault, encryptVault, decryptVault } from '../../../src/vault.js';
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
  function changePassword(oldPassword, newPassword, { assertCurrent = () => {}, validate = () => {}, changed = () => {} } = {}) {
    const job = saving.catch(() => {}).then(async () => {
      let opened;
      try {
        assertCurrent(); const saved = await storage.get(VAULT_KEY); assertCurrent();
        opened = await decryptVault(saved[VAULT_KEY], oldPassword); assertCurrent(); validate(opened, saved[VAULT_KEY]);
        const value = await encryptVault(opened.phrase, newPassword, opened.id); assertCurrent();
        const latest = await storage.get(VAULT_KEY); assertCurrent();
        if (latest[VAULT_KEY] !== saved[VAULT_KEY]) throw new Error('Wallet storage changed. Unlock again before changing its password.');
        await storage.set({ [VAULT_KEY]: value }); changed(saved[VAULT_KEY], value); assertCurrent();
        return { id: opened.id };
      } finally { if (opened) opened.phrase = null; oldPassword = newPassword = null; }
    }); saving = job.catch(() => {}); return job;
  }
  function deleteVault() {
    const job = saving.catch(() => {}).then(async () => {
      // Extension has no temporary session: delete begins with its ONE lock.
      await lockCoordinator.lock();
      const saved = await storage.get(null);
      const roots = [VAULT_KEY, ACTIVITY_KEY, BALANCES_KEY, HISTORY_KEY, ADDRESS_BOOK_KEY];
      const keys = Object.keys(saved).filter(key => roots.includes(key) ||
        [ACTIVITY_KEY, HISTORY_KEY].some(root => key.startsWith(`${root}.`)));
      await storage.remove(keys);
    }); saving = job.catch(() => {}); return job;
  }
  return { create, importVault, unlock, changePassword, deleteVault };
}
