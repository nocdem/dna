import { createVaultStore } from './vault-store.js';
import { createLockCoordinator } from './lock.js';
import { createAutoLockAlarm } from './auto-lock-alarm.js';
import { createKeyring } from './keyring.js';
import { createWalletKeys } from './wallet-keys.js';
import { createUnlock } from './unlock.js';
import { Messenger } from '@metamask/messenger';
import { rpcErrors } from '@metamask/rpc-errors';
import { createPersistedStore } from './store.js';
import { createApprovals } from './approvals.js';
import { createPermissions } from './permissions.js';
import { createRequestEngine } from './engine.js';

// Approved plan §3.5:388-435; packages 1-2 own the vault, key custody and shared lock.
// Startup constructs fresh locked holders. Store composition receives only controller metadata, never key custody.
export async function createBackground({ storage = chrome.storage.local, alarms = chrome.alarms,
  runtime = chrome.runtime, windows = chrome.windows, tabs = globalThis.chrome?.tabs } = {}) {
  const lockCoordinator = createLockCoordinator();
  const vaultStore = createVaultStore({ storage, lockCoordinator });
  const keyring = createKeyring({ lockCoordinator });
  const messenger = new Messenger({ namespace: 'Background' });
  const store = await createPersistedStore({ storage, messenger });
  const uiPorts = new Set(), alarmListeners = [];
  let walletKeys = null, unlock = null, permissions = null, engine = null;

  // metamask-controller.js:6121-6143: lock/unlock do not emit accountsChanged; permissions retain public account grants.
  // Plan §3.5:407-421 retains package 1's one lock and package 2's guarded signing operations.

  const autoLockAlarm = await createAutoLockAlarm({ storage, lockCoordinator, alarms: {
    clear: (...args) => alarms.clear(...args), create: (...args) => alarms.create(...args),
    onAlarm: { addListener(listener) { alarmListeners.push(listener); alarms.onAlarm.addListener(listener); } },
  } });
  const approvals = createApprovals({ messenger, runtime, windows, tabs, getUiState: () => ({
    // Port: background.ts:857-861 counts only popup ports; :907-916 tracks fullscreen tabs separately.
    popupCount: [...uiPorts].filter(port => port.name === 'popup').length,
    tabIds: new Set([...uiPorts].filter(port => port.name === 'fullscreen').map(port => port.sender?.tab?.id).filter(id => id !== undefined)),
  }) });
  permissions = createPermissions({ messenger, approvals, store, runtime,
    getNetworkState: options => engine.getNetworkState(options) });

  // wallet-keys.js:5-6, 43-44, 69-70: package 6 supplies the real Nodus seed consumer
  // and registers its own lock holder. No seed is discarded by a stand-in consumer.
  function attachWalletKeys(consumeNodusSeed) {
    if (walletKeys) throw new Error('Wallet keys are already attached.');
    walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed });
    const unlockKeys = createUnlock({ vaultStore, lockCoordinator, keyring, walletKeys });
    unlock = async (password, options) => {
      try {
        const result = await unlockKeys(password, options);
        permissions.setAccounts(await keyring.getAccounts());
        // ADAPTATION: dispatch T-5/security finding on a4f77b206; plan §3.5:422-435.
        // Reference app-state-controller.ts:1225-1261 re-arms on interface activity;
        // re-arm after successful unlock too, even after expiry with every UI closed.
        const activity = autoLockAlarm.openTrustedInterface();
        try { await activity.activity(); } finally { activity.close(); }
        lockCoordinator.assertUnlocked();
        return result;
      } catch (error) { await lockCoordinator.lock(); throw error; }
      finally { password = null; }
    };
    return { walletKeys, unlock };
  }

  // Port: metamask-controller.js:2755-2757, 2963-2964, 3166-3168, 3278-3284, 3482-3495.
  // Plan §16 step 4 / dispatch 4a: expose background approval operations; screens belong to 4b.
  const trustedApi = {
    getState: () => ({ isUnlocked: !lockCoordinator.isLocked,
      // Port: metamask-controller.js:2378-2384 flattens controller UI state, including subject metadata.
      ...permissions.controller.state, ...approvals.controller.state, ...permissions.alertController.state, ...permissions.subjectMetadataController.state }),
    // Port: metamask-controller.js:2523-2525; background.ts:698-700 supplies the tracked request tabs.
    getRequestAccountTabIds: () => engine.requestAccountTabIds,
    approvePermissionsRequest: request => permissions.acceptPermissionsRequest(request),
    rejectPermissionsRequest: id => permissions.controller.rejectPermissionsRequest(id),
    resolvePendingApproval: (id, value) => approvals.controller.acceptRequest(id, value),
    rejectPendingApproval: id => approvals.reject(id),
    setLocked: () => lockCoordinator.lock(),
    submitPasswordOrEncryptionKey: ({ password }) => {
      // ADAPTATION: plan §3.5 uses the web-wallet password vault; no second keyring/encryption-key unlock path.
      if (!unlock) throw rpcErrors.resourceUnavailable('Wallet key consumers are not attached.');
      return unlock(password);
    },
  };
  engine = createRequestEngine({ runtime, permissions, approvals, autoLockAlarm, trustedApi, getUiPorts: () => uiPorts });
  const onPermissionsChanged = () => { void engine.notifyAccountsChanged(); };
  messenger.subscribe('PermissionController:stateChange', onPermissionsChanged);
  // Plan §3.5:388-406: deliberately exclude the private KeyringController from composition and backups.
  store.registerControllers({ PermissionController: permissions.controller, ApprovalController: approvals.controller,
    AlertController: permissions.alertController, SubjectMetadataController: permissions.subjectMetadataController });
  await store.flush();
  return {
    vaultStore, lockCoordinator, autoLockAlarm, keyring, attachWalletKeys, store, permissions, approvals, engine,
    lock: () => lockCoordinator.lock(),
    get walletKeys() { return walletKeys; },
    get unlock() { return unlock; },
    async destroy() {
      engine.destroy(); approvals.destroy(); store.destroy(); permissions.subjectMetadataController.destroy(); permissions.controller.destroy(); permissions.alertController.destroy();
      messenger.unsubscribe('PermissionController:stateChange', onPermissionsChanged);
      for (const listener of alarmListeners) alarms.onAlarm.removeListener(listener);
      await store.flush();
    },
  };
}

// Port: background.ts:796-984: the service-worker entry installs runtime.onConnect during background initialization.
export const background = createBackground();
