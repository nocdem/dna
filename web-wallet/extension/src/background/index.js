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
import { createEvm } from './evm.js';
import { createNodus } from './nodus.js';
import { createSolanaTron } from './solana-tron.js';
import { createNetworks } from './networks.js';
import { PermissionsRequestNotFoundError } from '@metamask/permission-controller';
import { VAULT_KEY, decryptVault, validateNewPassword } from '../../../src/vault.js';
import { validateNodusPhrase } from '../../../src/recovery.js';

// Approved plan §3.5:388-435; packages 1-2 own the vault, key custody and shared lock.
// Startup constructs fresh locked holders. Store composition receives only controller metadata, never key custody.
export async function createBackground({ storage = chrome.storage.local, alarms = chrome.alarms,
  runtime = chrome.runtime, windows = chrome.windows, tabs = globalThis.chrome?.tabs, nodusOptions = {}, consumeNodusSeed } = {}) {
  const lockCoordinator = createLockCoordinator();
  const vaultStore = createVaultStore({ storage, lockCoordinator });
  const messenger = new Messenger({ namespace: 'Background' });
  const store = await createPersistedStore({ storage, messenger });
  const uiPorts = new Set(), alarmListeners = [];
  let walletKeys = null, unlock = null, permissions = null, engine = null;
  let chainHandlers;
  const networks = createNetworks({ messenger, store, onChanged: chain => chainHandlers?.[chain]?.networkChanged() });
  const getWallet = () => {
    lockCoordinator.assertUnlocked();
    if (!walletKeys) throw new Error('Wallet is locked.');
    return walletKeys.getEvmWallet();
  };
  const keyring = createKeyring({ lockCoordinator, getWallet });
  let restoring = Promise.resolve();
  const uiSubscriptions = new Map();

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
  const nodus = createNodus({ ...nodusOptions, storage, lockCoordinator, getAddresses: () => walletKeys.getAddresses(),
    getPermittedAccounts: origin => permissions.getNodusAccounts(origin), approvals });
  permissions = createPermissions({ messenger, approvals, store, runtime,
    getNetworkState: options => engine.getNetworkState(options), getNodusAccount: () => nodus.getAccount() });
  const evm = createEvm({ messenger, store, approvals, permissions, lockCoordinator, getWallet, keyring,
    onNetworkChanged: (client, readMetadata) => engine.attachNetworkClient(client, readMetadata) });

  // The real background consumer derives and checks the web-wallet identity.
  function attachWalletKeys(consumeNodusSeed) {
    if (walletKeys) throw new Error('Wallet keys are already attached.');
    walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed });
    const unlockKeys = createUnlock({ vaultStore, lockCoordinator, walletKeys });
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
        // src/app.js:1159-1173: begin quarantine reconciliation after unlock,
        // even when there are no readable pending rows or open history page.
        void nodus.reconcileQuarantine();
        return result;
      } catch (error) { await lockCoordinator.lock(); throw error; }
      finally { password = null; }
    };
    return { walletKeys, unlock };
  }
  attachWalletKeys(consumeNodusSeed ?? nodus.consumeNodusSeed);
  const { solana, tron } = chainHandlers = createSolanaTron({ lockCoordinator, getWalletKeys: () => walletKeys,
    getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });

  // Port: metamask-controller.js:2755-2757, 2963-2964, 3166-3168, 3278-3284, 3482-3495.
  // Plan §16 step 4 / dispatch 4a: expose background approval operations; screens belong to 4b.
  const trustedApi = {
    // Port: metamask-controller.js:2378-2384; plan §3.5/§7 replaces keyring vault/preferences with web-wallet storage.
    getState: async () => {
      const saved = await storage.get(VAULT_KEY), account = permissions.getSelectedAccount().address;
      const isUnlocked = !lockCoordinator.isLocked;
      return { isInitialized: Boolean(saved[VAULT_KEY]), isUnlocked,
        accounts: account ? [account] : [],
        addresses: isUnlocked && walletKeys ? { ethereum: account, bsc: account, ...walletKeys.getAddresses() } : {},
        preferences: { autoLockTimeLimit: autoLockAlarm.minutes },
        networks: networks.getState(),
        evm: evm.getState(),
        nodus: nodus.getState(),
        // Port: metamask-controller.js:2378-2384 flattens controller UI state, including subject metadata.
        ...permissions.controller.state, ...approvals.controller.state, ...permissions.alertController.state, ...permissions.subjectMetadataController.state };
    },
    // Port: legacy-background-api-service.ts:4449-4500 (UTF-8 restore, serialized creation, clear permissions).
    // ADAPTATION: plan Q-27 uses only vaultStore's web-wallet vault; key derivation stays in submitPasswordOrEncryptionKey.
    createNewVaultAndRestore(password, encodedSeedPhrase) {
      const operation = restoring.then(async () => {
        let phrase, saved, bytes;
        try {
          if (!Array.isArray(encodedSeedPhrase) || encodedSeedPhrase.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw rpcErrors.invalidParams('Expected recovery phrase bytes.');
          bytes = Uint8Array.from(encodedSeedPhrase);
          phrase = validateNodusPhrase(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          validateNewPassword(password);
          permissions.controller.clearState(); permissions.setAccounts([]);
          saved = await vaultStore.create(password, phrase);
          await store.flush();
        } finally { bytes?.fill(0); if (saved) saved.phrase = null; encodedSeedPhrase?.fill?.(0); phrase = null; password = null; }
      });
      restoring = operation.catch(() => {});
      return operation;
    },
    // Port: metamask-controller.js:2546-2548; legacy-background-api-service.ts:1385-1392;
    // keyring-controller 28.1.0 KeyringController.js:520-528 requires unlocked state and fresh password verification.
    // ADAPTATION: Q-27 authenticates the one web vault. The shared coordinator also invalidates an export spanning lock.
    async getSeedPhrase(password) {
      let authenticated, bytes;
      try {
        await lockCoordinator.unlock(async () => {
          lockCoordinator.assertUnlocked();
          const saved = await storage.get(VAULT_KEY);
          lockCoordinator.assertUnlocked();
          authenticated = await decryptVault(saved[VAULT_KEY], password);
          lockCoordinator.assertUnlocked();
          bytes = new TextEncoder().encode(authenticated.phrase);
        });
        lockCoordinator.assertUnlocked();
        return [...bytes];
      } finally { bytes?.fill(0); if (authenticated) authenticated.phrase = null; password = null; }
    },
    // Port: metamask-controller.js:2824-2826; preferences-controller.ts:1011-1019.
    // ADAPTATION: plan §3.5:422-435 keeps only the dispatched web-wallet auto-lock preference and persistence result.
    setPreference(preference, value) {
      if (preference !== 'autoLockTimeLimit') throw rpcErrors.invalidParams('Unsupported preference.');
      return autoLockAlarm.setMinutes(value);
    },
    // Port: metamask-controller.js:3274-3276; legacy-background-api-service.ts:2000-2017.
    // Same PermissionController revocation used by permissions.js's wallet_revokePermissions handler.
    async removePermissionsFor(subjects) {
      try { permissions.controller.revokePermissions(subjects); }
      catch (error) { if (!(error instanceof PermissionsRequestNotFoundError)) throw error; }
      await store.flush();
    },
    // Port: metamask-controller.js:4839-4844; lib/MessengerSubscriptions.ts:31-58, 68-85;
    // shared/constants/messages.ts:17. Only public approval/permission events cross the trusted UI boundary.
    // ADAPTATION: engine.js owns streams; share the bounded subscriptions across trusted UI ports, disposed with this background.
    messengerSubscribe(event) {
      if (!['ApprovalController:stateChange', 'PermissionController:stateChange', 'EvmController:stateChange', 'NetworksController:stateChange'].includes(event)) throw rpcErrors.invalidParams('Unsupported UI event.');
      const subscription = uiSubscriptions.get(event);
      if (subscription) { subscription.count++; return; }
      const listener = (...payload) => {
        for (const port of uiPorts) {
          try { port.postMessage({ name: 'controller', data: { jsonrpc: '2.0', method: 'messengerSubscription', params: [event, payload] } }); }
          catch { /* A closing page cannot receive the public state notification. */ }
        }
      };
      uiSubscriptions.set(event, { listener, count: 1 }); messenger.subscribe(event, listener);
    },
    messengerUnsubscribe(event) {
      const subscription = uiSubscriptions.get(event);
      if (!subscription) throw rpcErrors.invalidParams('No active UI subscription.');
      if (--subscription.count === 0) { messenger.unsubscribe(event, subscription.listener); uiSubscriptions.delete(event); }
    },
    // Port: metamask-controller.js:2523-2525; background.ts:698-700 supplies the tracked request tabs.
    getRequestAccountTabIds: () => engine.requestAccountTabIds,
    approvePermissionsRequest: request => permissions.acceptPermissionsRequest(request),
    rejectPermissionsRequest: id => permissions.controller.rejectPermissionsRequest(id),
    resolvePendingApproval: (id, value) => approvals.controller.acceptRequest(id, value),
    rejectPendingApproval: id => approvals.reject(id),
    getEvmBalances: chain => evm.getBalances(chain),
    setChainNetwork: (chain, network) => networks.select(chain, network),
    // Package 7a: wallet-only methods on the authenticated controller stream
    // (engine.js setupTrustedCommunication); no Solana/Tron site routing.
    getSolanaBalances: () => solana.getBalances(),
    prepareSolanaSend: fields => solana.prepareSend(fields),
    confirmSolanaSend: id => solana.confirmSend(id),
    cancelSolanaSend: id => solana.cancelSend(id),
    getSolanaHistory: options => solana.getHistory(options),
    getTronBalances: () => tron.getBalances(),
    prepareTronSend: fields => tron.prepareSend(fields),
    confirmTronSend: id => tron.confirmSend(id),
    cancelTronSend: id => tron.cancelSend(id),
    getTronHistory: options => tron.getHistory(options),
    prepareEvmSend: fields => evm.prepareSend(fields),
    confirmEvmSend: id => evm.confirmSend(id),
    cancelEvmSend: id => evm.cancelSend(id),
    selectEvmNetwork: chain => evm.selectNetwork(chain),
    setEvmEndpoint: (chain, endpoint) => evm.setEndpoint(chain, endpoint),
    getNodusBalances: () => nodus.getBalances(),
    getCpunkBalance: () => nodus.getCpunkBalance(),
    prepareNodusSend: fields => nodus.prepareSend(fields),
    readNodusContract: fields => nodus.readContract(fields),
    prepareNodusContract: fields => nodus.prepareContract(fields),
    confirmNodusSend: id => nodus.confirmSend(id),
    cancelNodusSend: id => nodus.cancelSend(id),
    getNodusHistory: () => nodus.getHistory(),
    getNodusLocalHistory: () => nodus.getLocalHistory(),
    discardNodusActivity: () => nodus.discardActivity(),
    resubmitNodusSend: hash => nodus.resubmit(hash),
    setLocked: () => lockCoordinator.lock(),
    submitPasswordOrEncryptionKey: ({ password }) => {
      // ADAPTATION: plan §3.5 uses the web-wallet password vault; no second keyring/encryption-key unlock path.
      if (!unlock) throw rpcErrors.resourceUnavailable('Wallet key consumers are not attached.');
      return unlock(password);
    },
  };
  engine = createRequestEngine({ runtime, permissions, approvals, autoLockAlarm, trustedApi, getUiPorts: () => uiPorts, evm, nodus });
  engine.attachNetworkClient(evm.client, () => evm.client.metadata);
  const onPermissionsChanged = () => { void engine.notifyAccountsChanged(); };
  messenger.subscribe('PermissionController:stateChange', onPermissionsChanged);
  // Only public network/permission/approval state enters composition; ethers custody stays in walletKeys.
  store.registerControllers({ PermissionController: permissions.controller, ApprovalController: approvals.controller,
    AlertController: permissions.alertController, SubjectMetadataController: permissions.subjectMetadataController, EvmController: evm.controller,
    NetworksController: networks.controller });
  await store.flush();
  return {
    vaultStore, lockCoordinator, autoLockAlarm, keyring, attachWalletKeys, store, permissions, approvals, engine, evm, nodus, solana, tron, networks,
    lock: () => lockCoordinator.lock(),
    get walletKeys() { return walletKeys; },
    get unlock() { return unlock; },
    async destroy() {
      for (const [event, { listener }] of uiSubscriptions) messenger.unsubscribe(event, listener);
      uiSubscriptions.clear();
      await lockCoordinator.lock();
      engine.destroy(); approvals.destroy(); store.destroy(); evm.destroy(); networks.controller.destroy(); permissions.subjectMetadataController.destroy(); permissions.controller.destroy(); permissions.alertController.destroy();
      messenger.unsubscribe('PermissionController:stateChange', onPermissionsChanged);
      for (const listener of alarmListeners) alarms.onAlarm.removeListener(listener);
      await store.flush();
    },
  };
}

// Port: background.ts:796-984: the service-worker entry installs runtime.onConnect during background initialization.
export const background = createBackground();
