import { extensionCapabilitiesFor } from '../constants/capabilities.js';
import { createVaultStore } from './vault-store.js';
import { createLockCoordinator } from './lock.js';
import { createAutoLockAlarm } from './auto-lock-alarm.js';
import { createTransactionNotifications } from './transaction-notifications.js';
import { createIncomingNotifications } from './incoming-notifications.js';
import { createKeyring } from './keyring.js';
import { createWalletKeys } from './wallet-keys.js';
import { createUnlock } from './unlock.js';
import { Messenger } from '@metamask/messenger';
import { rpcErrors } from '@metamask/rpc-errors';
import { createPersistedStore } from './store.js';
import { createApprovals } from './approvals.js';
import { createPermissions } from './permissions.js';
import { createConnectedSites } from './connected-sites.js';
import { createPrivacyConsent } from './privacy-consent.js';
import { createRequestEngine } from './engine.js';
import { createEvm } from './evm.js';
import { createNodus } from './nodus.js';
import { createSwap } from './swap.js';
import { createConnect } from './connect.js';
import { createSplendor } from './splendor.js';
import { createAsentum } from './asentum.js';
import { createIxios } from './ixios.js';
import { createXion } from './xion.js';
import { createCkb } from './ckb.js';
import { createQtc } from './qtc.js';
import { prepareQtcGatewayReview } from '../../../src/pq/qtc-gateway-controller.js';
import { createQtcGatewayTransport } from '../../../src/pq/qtc-gateway.js';
import { createSoqucoin } from './soqucoin.js';
import { createAlgorand } from './algorand.js';
import { createSolanaTron } from './solana-tron.js';
import { createNetworks } from './networks.js';
import { PermissionsRequestNotFoundError } from '@metamask/permission-controller';
import { VAULT_KEY, decryptVault, validateNewPassword } from '../../../src/vault.js';
import { sitesKeyFor, SITES_KEY } from '../../../src/activity-storage.js';
import { validateNodusPhrase } from '../../../src/recovery.js';
import { readPrices as readWalletPrices } from '../../../src/portfolio.js';
import { PQ_NETWORKS, pqNetwork } from '../../../src/pq/networks.js';

// Runtime ports carry JSON values. Keep the web wallet's arbitrary-precision
// values as decimal strings; no derived key or built envelope is a result.
const publicResult = async value => JSON.parse(JSON.stringify(await value, (_key, item) => typeof item === 'bigint' ? item.toString() : item));

// Approved plan §3.5:388-435; packages 1-2 own the vault, key custody and shared lock.
// Startup constructs fresh locked holders. Store composition receives only controller metadata, never key custody.
export async function createBackground({ storage = chrome.storage.local, alarms = chrome.alarms,
  runtime = chrome.runtime, windows = chrome.windows, tabs = globalThis.chrome?.tabs,
  notifications = globalThis.chrome?.notifications, notificationStorage = globalThis.chrome?.storage?.session,
  sessionStorage = globalThis.chrome?.storage?.session,
  nodusOptions = {}, consumeNodusSeed, readPrices = readWalletPrices } = {}) {
  const lockCoordinator = createLockCoordinator();
  const invalidateWallet = () => {
    for (const port of uiPorts) try { port.postMessage({ name: 'controller', data: { jsonrpc: '2.0', method: 'connectStateChanged', params: [] } }); }
    catch { /* a closing interface cannot receive the invalidation */ }
  };
  const connect = createConnect({ storage, onChange: () => invalidateWallet() });
  const vaultStore = createVaultStore({ storage, lockCoordinator, deleteHistory: id => connect.deleteHistory(id) });
  const messenger = new Messenger({ namespace: 'Background' });
  const store = await createPersistedStore({ storage, messenger });
  const uiPorts = new Set(), alarmListeners = [];
  const backgroundAlarms = {
    clear: (...args) => alarms.clear(...args), create: (...args) => alarms.create(...args),
    onAlarm: {
      addListener(listener) { alarmListeners.push(listener); },
      removeListener(listener) { const index = alarmListeners.indexOf(listener); if (index !== -1) alarmListeners.splice(index, 1); },
    },
  };
  let walletKeys = null, unlock = null, permissions = null, engine = null;
  let chainHandlers, evm, incomingNotifications, connectedSites;
  const privacyConsent = createPrivacyConsent({ storage });
  // The data notice must be agreed to before the extension handles user data (plan section 2.7).
  const assertConsent = async () => {
    if (!await privacyConsent.isGiven()) throw rpcErrors.resourceUnavailable('Read and agree to the data notice first.');
  };
  const networks = createNetworks({ messenger, store, onChanged: chain => chainHandlers?.[chain]?.networkChanged() });
  const getWallet = () => {
    lockCoordinator.assertUnlocked();
    if (!walletKeys) throw new Error('Wallet is locked.');
    return walletKeys.getEvmWallet();
  };
  const keyring = createKeyring({ lockCoordinator, getWallet });
  let restoring = Promise.resolve();
  const uiSubscriptions = new Map();
  const transactionNotifications = notifications && notificationStorage
    ? await createTransactionNotifications({ storage: notificationStorage, notifications, runtime, alarms: backgroundAlarms }) : null;

  // metamask-controller.js:6121-6143: lock/unlock do not emit accountsChanged; permissions retain public account grants.
  // Plan §3.5:407-421 retains package 1's one lock and package 2's guarded signing operations.

  const autoLockAlarm = await createAutoLockAlarm({ storage, lockCoordinator, alarms: backgroundAlarms });
  const approvals = createApprovals({ messenger, runtime, windows, tabs, getUiState: () => ({
    // Port: background.ts:857-861 counts only popup ports; :907-916 tracks fullscreen tabs separately.
    popupCount: [...uiPorts].filter(port => port.name === 'popup').length,
    tabIds: new Set([...uiPorts].filter(port => port.name === 'fullscreen').map(port => port.sender?.tab?.id).filter(id => id !== undefined)),
  }) });
  const nodus = createNodus({ ...nodusOptions, storage, lockCoordinator, getAddresses: () => walletKeys.getAddresses(), getPqAddresses: () => walletKeys.getPqAddresses(),
    onActivityChanged: (rows, options) => { void transactionNotifications?.observe(rows, options).catch(() => {}); },
    onLock: () => { void incomingNotifications?.stop().catch(() => {}); evm?.lock(); connectedSites?.clear(); },
    getWords: () => walletKeys.getRecoveryPhrase(), onClient: client => { walletKeys?.replaceNodusClient(client); connect.ready(client); },
    onIdentified: detail => connect.open(detail), onClientClosing: client => connect.close(client), onSent: detail => connect.sent(detail),
    onStateChanged() {
      // Only trusted UI ports receive this invalidation. They fetch public
      // state themselves; client objects and keys never enter the event.
      for (const port of uiPorts) try { port.postMessage({ name: 'controller', data: { jsonrpc: '2.0', method: 'walletStateChanged', params: [] } }); }
      catch { /* a closing interface cannot receive the invalidation */ }
    },
    getPermittedAccounts: origin => permissions.getNodusAccounts(origin), approvals });
  permissions = createPermissions({ messenger, approvals, runtime,
    getNetworkState: options => engine.getNetworkState(options), getNodusAccount: () => nodus.getAccount(),
    rememberRevocation: (origin, names) => connectedSites.rememberRevocation(origin, names) });
  connectedSites = createConnectedSites({ storage, sessionStorage, controller: permissions.controller, messenger });
  evm = createEvm({ messenger, store, approvals, permissions, lockCoordinator, getWallet, keyring,
    getActivity: chain => nodus.chainActivity(chain),
    onNetworkChanged: (client, readMetadata) => engine.attachNetworkClient(client, readMetadata) });

  // The real background consumer derives and checks the web-wallet identity.
  function attachWalletKeys(consumeNodusSeed) {
    if (walletKeys) throw new Error('Wallet keys are already attached.');
    walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed });
    const unlockKeys = createUnlock({ vaultStore, lockCoordinator, walletKeys });
    unlock = async (password, options) => {
      try {
        const result = await unlockKeys(password, options);
        // Opening the wallet again resets every network choice (networks.js resetToDefaults).
        await networks.resetToDefaults();
        permissions.setAccounts(await keyring.getAccounts());
        // The sealed connected-sites list opens with a key from the unlocked wallet (plan section 2.6).
        await connectedSites.load({ id: result.id, key: await sitesKeyFor(walletKeys.getRecoveryPhrase(), result.id) });
        lockCoordinator.assertUnlocked();
        permissions.settleWaitingAccountRequests();
        // ADAPTATION: dispatch T-5/security finding on a4f77b206; plan §3.5:422-435.
        // Reference app-state-controller.ts:1225-1261 re-arms on interface activity;
        // re-arm after successful unlock too, even after expiry with every UI closed.
        const activity = autoLockAlarm.openTrustedInterface();
        try { await activity.activity(); } finally { activity.close(); }
        lockCoordinator.assertUnlocked();
        // Local identity verification and every holder's derivation have
        // completed. Network availability must not gate receiving addresses.
        nodus.startNetwork();
        // src/app.js:1159-1173: begin quarantine reconciliation after unlock,
        // even when there are no readable pending rows or open history page.
        void nodus.reconcileQuarantine();
        void incomingNotifications?.start().catch(() => {});
        return result;
      } catch (error) { await lockCoordinator.lock(); throw error; }
      finally { password = null; }
    };
    return { walletKeys, unlock };
  }
  attachWalletKeys(consumeNodusSeed ?? nodus.consumeNodusSeed);
  const { solana, tron } = chainHandlers = createSolanaTron({ lockCoordinator, getWalletKeys: () => walletKeys,
    getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  const algorand = createAlgorand({ lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.algorand = algorand;
  const soqucoin = createSoqucoin({ storage, lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.soqucoin = soqucoin;
  const splendor = createSplendor({ storage, lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.splendor = splendor;
  const asentum = createAsentum({ storage, lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.asentum = asentum;
  const xion = createXion({ storage, lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.xion = xion;
  const ckb = createCkb({ storage, lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.ckb = ckb;
  const qtc = createQtc({ storage, transportKind: 'gateway', prepare: prepareQtcGatewayReview, getTransport: id => createQtcGatewayTransport(id), lockCoordinator, getWalletKeys: () => walletKeys, getActivity: (chain, network) => nodus.chainActivity(chain, network), getNetwork: chain => networks.get(chain) });
  chainHandlers.qtc = qtc;
  const ixios = createIxios({ storage, lockCoordinator, getWalletKeys: () => walletKeys, getActivity: () => nodus.chainActivity('ixios', 'mainnet') });
  chainHandlers.ixios = ixios;
  incomingNotifications = notifications ? await createIncomingNotifications({ alarms: backgroundAlarms, notifications, runtime,
    lockCoordinator, networks, nodus, evm, solana, tron }) : null;

  // Port: metamask-controller.js:2755-2757, 2963-2964, 3166-3168, 3278-3284, 3482-3495.
  // Plan §16 step 4 / dispatch 4a: expose background approval operations; screens belong to 4b.
  const trustedApi = {
    getConnectState: () => { lockCoordinator.assertUnlocked(); return connect.getState(); },
    async connectAction(epoch, action, fields) {
      lockCoordinator.assertUnlocked();
      const result = await connect.action(epoch, action, fields);
      lockCoordinator.assertUnlocked(); return result;
    },
    // Port: metamask-controller.js:2378-2384; plan §3.5/§7 replaces keyring vault/preferences with web-wallet storage.
    getState: async () => {
      const saved = await storage.get(VAULT_KEY), account = permissions.getSelectedAccount().address;
      const isUnlocked = !lockCoordinator.isLocked;
      const selectedNetworks = networks.getState();
      const pqAddresses = isUnlocked && walletKeys ? walletKeys.getPqAddresses?.() || {} : {};
      const pqErrors = isUnlocked && walletKeys ? walletKeys.getPqErrors?.() || {} : {};
      const selectedPqAddresses = Object.fromEntries(Object.keys(PQ_NETWORKS).map(chain => [chain,
        pqAddresses[chain]?.[pqNetwork(chain, selectedNetworks[chain]).id]]));
      return { isInitialized: Boolean(saved[VAULT_KEY]), isUnlocked,
        privacyConsent: await privacyConsent.isGiven(), connectedSitesError: connectedSites.getError(),
        accounts: account ? [account] : [],
        addresses: isUnlocked && walletKeys ? { ethereum: account, bsc: account, ...walletKeys.getAddresses(), ...selectedPqAddresses } : {},
        pqAddresses, pqErrors,
        preferences: { autoLockTimeLimit: autoLockAlarm.minutes },
        networks: selectedNetworks,
        evm: evm.getState(),
        nodus: nodus.getState(),
        // Port: metamask-controller.js:2378-2384 flattens controller UI state.
        ...permissions.controller.state, ...approvals.controller.state };
    },
    // Port: legacy-background-api-service.ts:4449-4500 (UTF-8 restore, serialized creation, clear permissions).
    // ADAPTATION: plan Q-27 uses only vaultStore's web-wallet vault; key derivation stays in submitPasswordOrEncryptionKey.
    createNewVaultAndRestore(password, encodedSeedPhrase) {
      const operation = restoring.then(async () => {
        let phrase, saved, bytes;
        try {
          await assertConsent();
          if (!Array.isArray(encodedSeedPhrase) || encodedSeedPhrase.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw rpcErrors.invalidParams('Expected recovery phrase bytes.');
          bytes = Uint8Array.from(encodedSeedPhrase);
          phrase = validateNodusPhrase(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          validateNewPassword(password);
          // A restore replaces the wallet and clears its permissions; the sealed connected-sites record of the
          // replaced wallet goes with them (plan section 2.6), after any change already queued for it.
          await connectedSites.flush().catch(() => {}); connectedSites.clear(); await connectedSites.forgetRevocations();
          permissions.controller.clearState(); permissions.setAccounts([]);
          await storage.remove(SITES_KEY);
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
      await store.flush(); await connectedSites.flush();
    },
    // The data notice (plan section 2.7): the screen's single button stores the agreed text version.
    acceptPrivacyNotice: () => privacyConsent.accept(),
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
    approvePermissionsRequest: request => permissions.acceptPermissionsRequest(request),
    rejectPermissionsRequest: id => permissions.controller.rejectPermissionsRequest(id),
    resolvePendingApproval: (id, value) => approvals.controller.acceptRequest(id, value),
    rejectPendingApproval: id => approvals.reject(id),
    getEvmBalances: chain => evm.getBalances(chain),
    // Design r3 §2.4a: the web-wallet reader owns price validation; only public
    // decimal strings cross the UI stream, whose state comparison uses JSON.
    async getPrices() {
      lockCoordinator.assertUnlocked();
      const quotes = await readPrices();
      return Object.fromEntries(Object.entries(quotes).map(([key, quote]) => [key, { units: quote.units.toString(), observedAt: quote.observedAt }]));
    },
    setChainNetwork: (chain, network) => networks.select(chain, network),
    // Package 7a: wallet-only methods on the authenticated controller stream
    // (engine.js setupTrustedCommunication); no Solana/Tron site routing.
    getQtcBalances: () => qtc.getBalances(),
    getQtcHistory: async options => { const h = await qtc.getHistory(options); return { ...h, local: h.local.map(row => ({ ...row, canResubmit: row.canResubmit && extensionCapabilitiesFor('qtc', networks.get('qtc').id).send })) }; },
    prepareQtcSend: fields => { if (networks.get('qtc').id !== 'mainnet' || !extensionCapabilitiesFor('qtc', networks.get('qtc').id).send) throw new Error('QTC mainnet sending is not enabled.'); return qtc.prepareSend(fields); },
    prepareQtcResubmit: hash => { if (networks.get('qtc').id !== 'mainnet' || !extensionCapabilitiesFor('qtc', networks.get('qtc').id).send) throw new Error('QTC mainnet recovery is not enabled.'); return qtc.prepareResubmit(hash); },
    confirmQtcSend: id => { if (networks.get('qtc').id !== 'mainnet' || !extensionCapabilitiesFor('qtc', networks.get('qtc').id).send) throw new Error('QTC mainnet sending is not enabled.'); return qtc.confirmSend(id); },
    cancelQtcSend: id => qtc.cancelSend(id),
    getCkbBalances: () => ckb.getBalances(),
    getCkbHistory: async options => { const h = await ckb.getHistory(options); return { ...h, local: h.local.map(row => ({ ...row, canResubmit: row.canResubmit && extensionCapabilitiesFor('ckb', networks.get('ckb').id).send })) }; },
    prepareCkbSend: fields => { if (!extensionCapabilitiesFor('ckb', networks.get('ckb').id).send) throw new Error('CKB sending is not enabled.'); return ckb.prepareSend(fields); },
    prepareCkbResubmit: hash => { if (!extensionCapabilitiesFor('ckb', networks.get('ckb').id).send) throw new Error('CKB recovery is not enabled.'); return ckb.prepareResubmit(hash); },
    confirmCkbSend: id => { if (!extensionCapabilitiesFor('ckb', networks.get('ckb').id).send) throw new Error('CKB sending is not enabled.'); return ckb.confirmOperation(id); },
    cancelCkbSend: id => ckb.cancelOperation(id),
    getIxiosBalances: () => ixios.getBalances(),
    getIxiosHistory: async options => { const h=await ixios.getHistory(options);return {...h,local:(h.local??[]).map(row=>({...row,canResubmit:row.canResubmit&&extensionCapabilitiesFor('ixios',networks.get('ixios').id).send}))}; },
    prepareIxiosSend: fields => { if(!extensionCapabilitiesFor('ixios',networks.get('ixios').id).send)throw new Error('IXIOS sending is not enabled.');return ixios.prepareSend(fields); },
    prepareIxiosResubmit: hash => { if(!extensionCapabilitiesFor('ixios',networks.get('ixios').id).send)throw new Error('IXIOS recovery is not enabled.');return ixios.prepareResubmit(hash); },
    confirmIxiosSend: id => { if(!extensionCapabilitiesFor('ixios',networks.get('ixios').id).send)throw new Error('IXIOS sending is not enabled.');return ixios.confirmOperation(id); },
    cancelIxiosSend: id => ixios.cancelOperation(id),
    getXionBalances: () => xion.getBalances(),
    getXionHistory: async options => { const h=await xion.getHistory(options);return {...h,local:h.local.map(row=>({...row,canResubmit:row.canResubmit&&extensionCapabilitiesFor('xion',networks.get('xion').id).send}))}; },
    prepareXionSend: fields => { if(!extensionCapabilitiesFor('xion',networks.get('xion').id).send)throw new Error('XION sending is not enabled.');return xion.prepareSend(fields); },
    prepareXionResubmit: hash => { if(!extensionCapabilitiesFor('xion',networks.get('xion').id).send)throw new Error('XION recovery is not enabled.');return xion.prepareResubmit(hash); },
    confirmXionSend: id => { if(!extensionCapabilitiesFor('xion',networks.get('xion').id).send)throw new Error('XION sending is not enabled.');return xion.confirmOperation(id); },
    cancelXionSend: id => xion.cancelOperation(id),
    getAsentumBalances: () => asentum.getBalances(),
    getAsentumHistory: async options => { const h=await asentum.getHistory(options);return {...h,local:h.local.map(row=>({...row,canResubmit:row.canResubmit&&extensionCapabilitiesFor('asentum',networks.get('asentum').id).send}))}; },
    prepareAsentumSend: fields => { if(!extensionCapabilitiesFor('asentum',networks.get('asentum').id).send)throw new Error('Asentum sending is not enabled.');return asentum.prepareSend(fields); },
    prepareAsentumResubmit: hash => { if(!extensionCapabilitiesFor('asentum',networks.get('asentum').id).send)throw new Error('Asentum recovery is not enabled.');return asentum.prepareResubmit(hash); },
    confirmAsentumSend: id => { if(!extensionCapabilitiesFor('asentum',networks.get('asentum').id).send)throw new Error('Asentum sending is not enabled.');return asentum.confirmOperation(id); },
    cancelAsentumSend: id => asentum.cancelOperation(id),
    getSplendorBalances: () => splendor.getBalances(),
    getSplendorHistory: options => splendor.getHistory(options),
    prepareSplendorSend: fields => { if (networks.get('splendor').id !== 'mainnet') throw new Error('Splendor sending is enabled only on verified mainnet.'); return splendor.prepareSend(fields); },
    prepareSplendorResubmit: hash => { if (networks.get('splendor').id !== 'mainnet') throw new Error('Splendor recovery is enabled only on verified mainnet.'); return splendor.prepareResubmit(hash); },
    confirmSplendorSend: id => splendor.confirmOperation(id),
    cancelSplendorSend: id => splendor.cancelOperation(id),
    getSoqucoinBalances: () => soqucoin.getBalances(),
    prepareSoqucoinResubmit: hash => soqucoin.prepareResubmit(hash),
    prepareSoqucoinSend: fields => soqucoin.prepareSend(fields),
    confirmSoqucoinSend: id => soqucoin.confirmSend(id),
    cancelSoqucoinSend: id => soqucoin.cancelSend(id),
    getSoqucoinHistory: options => soqucoin.getHistory(options),
    getAlgorandBalances: () => algorand.getBalances(),
    prepareAlgorandSend: fields => algorand.prepareSend(fields),
    confirmAlgorandSend: id => algorand.confirmSend(id),
    cancelAlgorandSend: id => algorand.cancelSend(id),
    getAlgorandHistory: options => algorand.getHistory(options),
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
    getIxiosBalance: () => nodus.getIxiosBalance(),
    prepareNodusSend: fields => nodus.prepareSend(fields),
    readNodusContract: fields => nodus.readContract(fields),
    prepareNodusContract: fields => nodus.prepareContract(fields),
    confirmNodusSend: id => nodus.confirmSend(id),
    cancelNodusSend: id => nodus.cancelSend(id),
    getNodusHistory: () => nodus.getHistory(),
    getNodusLocalHistory: () => nodus.getLocalHistory(),
    discardNodusActivity: () => nodus.discardActivity(),
    resubmitNodusSend: hash => nodus.resubmit(hash),
    abandonActivity: (chain, hash) => nodus.abandonActivity(chain, hash, networks.getState()[chain]),
    getChainHistory: (chain, options) => nodus.getChainHistory(chain, options),
    getChainLocalHistory: chain => nodus.getChainLocalHistory(chain),
    getKeptBalances: () => nodus.getKeptBalances(),
    keepBalances: entries => nodus.keepBalances(entries),
    getSessionLog: () => nodus.getSessionLog(),
    checkNodusLiveness: () => nodus.checkLiveness(),
    getAddressBook: () => nodus.getAddressBook(),
    setAddressBook: entries => nodus.setAddressBook(entries),
    getStakingOverview: () => publicResult(nodus.getStakingOverview()),
    prepareStake: (kind, params) => nodus.prepareStake(kind, params),
    getOwnName: () => nodus.getOwnName(),
    getNamePrices: () => publicResult(nodus.getNamePrices()),
    quoteName: name => publicResult(nodus.quoteName(name)),
    prepareName: name => nodus.prepareName(name),
    getClaimStatus: () => publicResult(nodus.getClaimStatus()),
    prepareClaim: () => nodus.prepareClaim(),
    contractAccount: fields => publicResult(nodus.contractOperation('account', fields)),
    contractTicket: fields => publicResult(nodus.contractOperation('ticket', fields)),
    contractSimulate: fields => publicResult(nodus.contractOperation('simulate', fields)),
    contractEstimate: fields => publicResult(nodus.contractOperation('estimate', fields)),
    getNodusContractReceipt: intentId => publicResult(nodus.getContractReceipt(intentId)),
    readSharedVault: (method, fields) => publicResult(nodus.readSharedVault(method, fields)),
    prepareSharedVault: (method, fields) => nodus.prepareSharedVault(method, fields),
    confirmSharedVault: id => publicResult(nodus.confirmSharedVault(id)),
    cancelSharedVault: id => nodus.cancelSharedVault(id),
    changePassword(oldPassword, newPassword) {
      const wallet = getWallet();
      const assertCurrent = () => { lockCoordinator.assertUnlocked(); if (getWallet() !== wallet || wallet.locked) throw new Error('Wallet is locked.'); };
      return vaultStore.changePassword(oldPassword, newPassword, { assertCurrent,
        validate(opened, value) { nodus.assertVault(value); if (opened.phrase !== wallet.recoveryPhrase) throw new Error('Unlock the saved wallet before changing its password.'); },
        changed: (previous, value) => nodus.replaceVault(previous, value) });
    },
    async deleteVault() {
      // A queued sealed write must land before the delete removes the record, never after it.
      await connectedSites.flush().catch(() => {}); await connectedSites.forgetRevocations();
      await vaultStore.deleteVault(); permissions.controller.clearState(); permissions.setAccounts([]); await store.flush();
    },
    setLocked: () => lockCoordinator.lock(),
    submitPasswordOrEncryptionKey: async ({ password }) => {
      // ADAPTATION: plan §3.5 uses the web-wallet password vault; no second keyring/encryption-key unlock path.
      if (!unlock) throw rpcErrors.resourceUnavailable('Wallet key consumers are not attached.');
      await assertConsent();
      return unlock(password);
    },
  };
  engine = createRequestEngine({ runtime, permissions, approvals, autoLockAlarm, trustedApi, getUiPorts: () => uiPorts, evm, nodus, swap: createSwap({ evm, nodus }), privacyConsent });
  engine.attachNetworkClient(evm.client, () => evm.client.metadata);
  const onPermissionsChanged = () => { void engine.notifyAccountsChanged(); };
  messenger.subscribe('PermissionController:stateChange', onPermissionsChanged);
  // Only public network/permission/approval state enters composition; ethers custody stays in walletKeys.
  // PermissionController is not registered: its connected-sites list is sealed by connected-sites.js (plan section 2.6).
  store.registerControllers({ ApprovalController: approvals.controller,
    EvmController: evm.controller,
    NetworksController: networks.controller });
  await store.flush();
  // Install one consumer only after all alarm handlers exist, then replay
  // the worker's waking alarm. One handler must not drain another's events.
  const onAlarm = alarm => Promise.all(alarmListeners.map(listener => listener(alarm)));
  const lazyListener = globalThis.chrome?.alarms === alarms && globalThis.stateHooks?.lazyListener;
  if (lazyListener) lazyListener.addListener('alarms', 'onAlarm', onAlarm);
  else alarms.onAlarm.addListener(onAlarm);
  return {
    vaultStore, lockCoordinator, autoLockAlarm, transactionNotifications, incomingNotifications, keyring, attachWalletKeys, store, permissions, connectedSites, privacyConsent, approvals, engine, evm, nodus, solana, tron, algorand, soqucoin, splendor, asentum, xion, ckb, qtc, ixios, networks,
    lock: () => lockCoordinator.lock(),
    get walletKeys() { return walletKeys; },
    get unlock() { return unlock; },
    async destroy() {
      for (const [event, { listener }] of uiSubscriptions) messenger.unsubscribe(event, listener);
      uiSubscriptions.clear();
      await lockCoordinator.lock();
      await incomingNotifications?.destroy();
      await transactionNotifications?.flush().catch(() => {});
      transactionNotifications?.destroy();
      await connectedSites.flush().catch(() => {}); connectedSites.destroy();
      engine.destroy(); approvals.destroy(); store.destroy(); evm.destroy(); networks.controller.destroy(); permissions.controller.destroy();
      messenger.unsubscribe('PermissionController:stateChange', onPermissionsChanged);
      alarms.onAlarm.removeListener(onAlarm);
      await store.flush();
    },
  };
}

// Port: background.ts:796-984: the service-worker entry installs runtime.onConnect during background initialization.
export const background = createBackground();
