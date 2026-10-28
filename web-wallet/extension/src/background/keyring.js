import { KeyringController } from '@metamask/keyring-controller';
import { Messenger } from '@metamask/messenger';
import * as passworder from '@metamask/browser-passworder';
import { validateNodusPhrase } from '../../../src/recovery.js';

// Pinned wallet-17.1.0 initialization/instances/keyring-controller/encryptor.js:
// keyFromPasswordFactory, with 600,000 iterations from keyring-controller.js:11.
// Restore uses keyFromPassword/exportKey, then importKey/encryptWithKey.
const encryptor = {
  ...passworder,
  keyFromPassword(password, salt, exportable, options) {
    return passworder.keyFromPassword(password, salt, exportable, options ?? {
      algorithm: 'PBKDF2', params: { iterations: 600_000 },
    });
  },
};

export function createKeyring({ lockCoordinator, messenger }) {
  let controller = null, restoringController = null, accessGuard = null, generation = 0, restoring = false;

  async function lock() {
    generation++;
    const previous = controller;
    controller = null; accessGuard = null;
    for (const candidate of new Set([previous, restoringController])) {
      if (candidate?.state.isUnlocked) await candidate.setLocked();
    }
  }
  lockCoordinator.register('keyring', { lock });

  async function unlock(phrase, password, { assertReady } = {}) {
    if (restoring || controller) throw new Error('Lock the wallet before unlocking again.');
    phrase = validateNodusPhrase(phrase);
    const started = generation;
    // ADAPTATION: approved plan §3.5:388-406 (Q-27, one persisted vault).
    // The controller and its messenger are private, freshly constructed, never
    // hydrated from storage or registered in a persistent/backup store, and no
    // stateChanged subscriber writes their state. Stock restore DOES encrypt a
    // vault in memory (keyring-controller 28.1.0 KeyringController.js:296-298,
    // 413-424, 1672-1700, 1977-1987); the real encryptor above is not bypassed.
    // Only the three guarded actions below cross this boundary; getState and
    // the stock export/mutation actions stay on the private messenger.
    const candidate = new KeyringController({
      messenger: new Messenger({ namespace: 'KeyringController' }), encryptor,
    });
    restoring = true;
    restoringController = candidate;
    try {
      // The stock HD builder is eth-hd-keyring 15.0.0 (controller :138-143).
      // Restore fixes numberOfAccounts to 1 (:413-424), hence child index 0.
      await candidate.createNewVaultAndRestore(password, phrase);
      if (generation !== started) throw new Error('Wallet is locked.');
      const accounts = await candidate.getAccounts();
      if (generation !== started) throw new Error('Wallet is locked.');
      if (accounts.length !== 1) throw new Error('Expected one HD account.');
      controller = candidate; accessGuard = assertReady;
      return accounts;
    } finally {
      phrase = null; password = null;
      restoring = false; restoringController = null;
      // A lock may finish before restore has reached its unlocked state.
      // Dispose that late completion instead of publishing a revived holder.
      if (controller !== candidate && candidate.state.isUnlocked) await candidate.setLocked();
    }
  }

  function assertCurrent(candidate, started) {
    lockCoordinator.assertUnlocked();
    if (!candidate || candidate !== controller || started !== generation) throw new Error('Wallet is locked.');
    accessGuard?.();
  }

  async function call(method, args) {
    const candidate = controller, started = generation;
    assertCurrent(candidate, started);
    // The controller awaits keyring lookup before signing (:828-890). Check
    // again on completion so queued results cannot escape after lock/re-unlock.
    try { return await candidate[method](...args); }
    finally { assertCurrent(candidate, started); }
  }

  const actions = {
    signPersonalMessage: (...args) => call('signPersonalMessage', args),
    signTypedMessage: (...args) => call('signTypedMessage', args),
    signTransaction: (...args) => call('signTransaction', args),
  };
  if (messenger) {
    for (const [name, handler] of Object.entries(actions)) {
      messenger.registerActionHandler(`KeyringController:${name}`, handler);
    }
  }
  // setLocked clears the stock keyrings (:766-778); dropping the private
  // controller also drops its in-memory vault. Dependency/GC copies cannot be
  // proved erased (plan §3.5:418-420, HD keyring :364-376).
  return { unlock, getAccounts: () => call('getAccounts', []), ...actions };
}
