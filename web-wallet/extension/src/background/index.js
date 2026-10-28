import { createVaultStore } from './vault-store.js';
import { createLockCoordinator } from './lock.js';
import { createAutoLockAlarm } from './auto-lock-alarm.js';
import { createKeyring } from './keyring.js';
import { createWalletKeys } from './wallet-keys.js';
import { createUnlock } from './unlock.js';

// Approved plan §3.5:388-435; packages 1-2 own the vault, key custody and shared lock.
// Startup constructs fresh locked holders; only vault-store and auto-lock-alarm receive persistent storage.
export async function createBackground({ storage = chrome.storage.local, alarms = chrome.alarms } = {}) {
  const lockCoordinator = createLockCoordinator();
  const vaultStore = createVaultStore({ storage, lockCoordinator });
  const keyring = createKeyring({ lockCoordinator });
  let walletKeys = null, unlock = null;

  // wallet-keys.js:5-6, 43-44, 69-70: package 6 supplies the real Nodus seed consumer
  // and registers its own lock holder. No seed is discarded by a stand-in consumer.
  function attachWalletKeys(consumeNodusSeed) {
    if (walletKeys) throw new Error('Wallet keys are already attached.');
    walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed });
    unlock = createUnlock({ vaultStore, lockCoordinator, keyring, walletKeys });
    return { walletKeys, unlock };
  }

  const autoLockAlarm = await createAutoLockAlarm({ storage, alarms, lockCoordinator });
  return {
    vaultStore, lockCoordinator, autoLockAlarm, keyring, attachWalletKeys,
    get walletKeys() { return walletKeys; },
    get unlock() { return unlock; },
  };
}

// The request engine, trusted-port classification and approval routing are package 4.
export const background = createBackground();
