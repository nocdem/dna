import { PermissionController, PermissionDoesNotExistError, PermissionType, SubjectMetadataController, createPermissionMiddleware } from '@metamask/permission-controller';
import { createMethodMiddleware } from '@metamask/json-rpc-engine';
import { BaseController } from '@metamask/base-controller';
import { isPlainObject } from '@metamask/controller-utils';
import { rpcErrors } from '@metamask/rpc-errors';
import {
  Caip25CaveatType, Caip25EndowmentPermissionName, caip25CaveatBuilder, caip25EndowmentBuilder,
  getCaip25PermissionFromLegacyPermissions, getEthAccounts, getPermittedEthChainIds, requestPermittedChainsPermissionIncremental,
} from '@metamask/chain-agnostic-permission';
import { CHAINS } from '../../../src/config.js';
import { PROVIDER_METHODS } from '../constants/stream.js';

// Port: shared/constants/app.ts:144; ADAPTATION: plan Q-9 (:999), renamed background-only method.
export const SEND_METADATA = 'nodus_sendDomainMetadata';

// Decision 2026-10-28-extension-nodus-site-signing.md: separate Nodus
// access, stored by the existing PermissionController. The account caveat
// retains only the approved public identity, just as EVM grants survive lock.
export const NODUS_PERMISSION = 'endowment:nodus';
export const NODUS_ACCOUNT_CAVEAT = 'nodusAccount';

// Port: MetaMask v13.54.0 app/scripts/controllers/permissions/specifications.ts:104-198.
// ADAPTATION: approved plan §3.3:235-246 renames methods; §3.4:312-319 removes snaps/EIP-7715/onboarding.
const unrestrictedMethods = [
  'eth_blockNumber', 'eth_call', 'eth_chainId', 'eth_coinbase', 'eth_decrypt', 'eth_estimateGas',
  'eth_feeHistory', 'eth_gasPrice', 'eth_getBalance', 'eth_getBlockByHash', 'eth_getBlockByNumber',
  'eth_getBlockTransactionCountByHash', 'eth_getBlockTransactionCountByNumber', 'eth_getCode',
  'eth_getEncryptionPublicKey', 'eth_getFilterChanges', 'eth_getFilterLogs', 'eth_getLogs', 'eth_getProof',
  'eth_getStorageAt', 'eth_getTransactionByBlockHashAndIndex', 'eth_getTransactionByBlockNumberAndIndex',
  'eth_getTransactionByHash', 'eth_getTransactionCount', 'eth_getTransactionReceipt',
  'eth_getUncleByBlockHashAndIndex', 'eth_getUncleByBlockNumberAndIndex', 'eth_getUncleCountByBlockHash',
  'eth_getUncleCountByBlockNumber', 'eth_getWork', 'eth_hashrate', 'eth_mining', 'eth_newBlockFilter',
  'eth_newFilter', 'eth_newPendingTransactionFilter', 'eth_protocolVersion', 'eth_requestAccounts',
  'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_signTypedData', 'eth_signTypedData_v1',
  'eth_signTypedData_v3', 'eth_signTypedData_v4', 'eth_submitHashrate', 'eth_submitWork', 'eth_subscribe',
  'eth_syncing', 'eth_uninstallFilter', 'eth_unsubscribe', PROVIDER_METHODS.getProviderState,
  PROVIDER_METHODS.logWeb3ShimUsage, SEND_METADATA, 'net_listening', 'net_peerCount',
  'net_version', 'personal_ecRecover', 'personal_sign', 'wallet_addEthereumChain', 'wallet_getPermissions',
  'wallet_requestPermissions', 'wallet_revokePermissions', 'wallet_switchEthereumChain',
  'wallet_watchAsset', 'web3_clientVersion', 'web3_sha3', 'nodus_requestAccounts', 'nodus_signMessage',
];

export function createPermissions({ messenger, approvals, store, runtime, getNetworkState, getNodusAccount }) {
  let accounts = [];
  const locks = new Set();
  // Port: controllers/alert-controller.ts:102, 125-130, 215-225; only the shim handler's state is in 4a.
  const shimMetadata = { web3ShimUsageOrigins: { persist: true, includeInStateLogs: true, includeInDebugSnapshot: false, usedInUi: true } };
  const alertController = new BaseController({ name: 'AlertController', metadata: shimMetadata,
    messenger: messenger.buildChild({ namespace: 'AlertController' }),
    state: { web3ShimUsageOrigins: {}, ...store?.getInitialState('AlertController', shimMetadata) },
  });
  // Port: app/scripts/messenger-client-init/permission-controller-init.ts:37-78,
  // controllers/permissions/specifications.ts:54-86. Plan §16: step 7 supplies non-EVM scope support.
  const controller = new PermissionController({
    messenger: messenger.buildChild({ namespace: 'PermissionController', actions: [
      'ApprovalController:addRequest', 'ApprovalController:hasRequest', 'ApprovalController:acceptRequest', 'ApprovalController:rejectRequest',
    ] }),
    state: store?.getInitialState('PermissionController', { subjects: { persist: true } }),
    // Same Endowment + validator structure as pinned chain-agnostic-
    // permission 1.6.2 dist/caip25Permission.cjs:168-180; no invented CAIP
    // chain identifier is needed for these separately defined site calls.
    permissionSpecifications: { [caip25EndowmentBuilder.targetName]: caip25EndowmentBuilder.specificationBuilder({}),
      [NODUS_PERMISSION]: { permissionType: PermissionType.Endowment, targetName: NODUS_PERMISSION,
        allowedCaveats: [NODUS_ACCOUNT_CAVEAT], endowmentGetter: () => null,
        validator(permission) {
          if (permission.caveats?.length !== 1 || permission.caveats[0].type !== NODUS_ACCOUNT_CAVEAT) throw rpcErrors.invalidParams('Select a Nodus account.');
        } },
    },
    caveatSpecifications: {
      [NODUS_ACCOUNT_CAVEAT]: { type: NODUS_ACCOUNT_CAVEAT,
        validator({ value }) {
          if (!value || !/^[0-9a-f]{128}$/.test(value.address) || !/^0x[0-9a-f]{5184}$/.test(value.publicKey)) throw rpcErrors.invalidParams('Invalid Nodus account.');
        } },
      [Caip25CaveatType]: caip25CaveatBuilder({
      listAccounts: () => accounts.map(address => ({ type: 'eip155:eoa', address })),
      findNetworkClientIdByChainId(chainId) {
        const entry = ['ethereum', 'bsc'].find(name => `0x${CHAINS[name].chainId.toString(16)}` === chainId);
        if (!entry) throw new Error('Unsupported EVM chain.');
        return entry;
      },
      isNonEvmScopeSupported: () => false,
      getNonEvmAccountAddresses: () => [],
    }) },
    unrestrictedMethods,
  });

  // Port: messenger-client-init/subject-metadata-controller-init.ts:19-22; permission-controller 13.1.1 exports this controller.
  const subjectMetadataController = new SubjectMetadataController({
    messenger: messenger.buildChild({ namespace: 'SubjectMetadataController', actions: ['PermissionController:hasPermissions'] }),
    subjectCacheLimit: 100,
    state: store?.getInitialState('SubjectMetadataController', { subjectMetadata: { persist: true } }),
  });

  // Port: metamask-controller.js:4053-4072, including the absence of a lock check.
  // ADAPTATION: plan Q-18 / §7:893 permits one account per network, so last-selected ordering is unchanged.
  function getAccounts(origin) {
    let caveat;
    try { caveat = controller.getCaveat(origin, Caip25EndowmentPermissionName, Caip25CaveatType); }
    catch (error) {
      if (error instanceof PermissionDoesNotExistError) return [];
      throw error;
    }
    return getEthAccounts(caveat.value);
  }

  function getNodusAccounts(origin) {
    try { return [structuredClone(controller.getCaveat(origin, NODUS_PERMISSION, NODUS_ACCOUNT_CAVEAT).value)]; }
    catch (error) { if (error instanceof PermissionDoesNotExistError) return []; throw error; }
  }

  function getChainIds(origin) {
    try { return getPermittedEthChainIds(controller.getCaveat(origin, Caip25EndowmentPermissionName, Caip25CaveatType).value); }
    catch (error) { if (error instanceof PermissionDoesNotExistError) return []; throw error; }
  }

  // Pinned ethereum-chain-utils.ts:314-345: a switch requests missing scope
  // through the existing permission approval rather than silently granting it.
  async function requestChainPermission(origin, chainId) {
    if (getChainIds(origin).includes(chainId)) return;
    await requestPermittedChainsPermissionIncremental({ origin, chainId, autoApprove: false,
      metadata: { isSwitchEthereumChain: true, isEip1193Request: true },
      hooks: { requestPermissionsIncremental: (...args) => controller.requestPermissionsIncremental(...args) },
    });
    if (!getChainIds(origin).includes(chainId)) throw rpcErrors.invalidParams('The requested network was not permitted.');
  }

  async function acceptPermissionsRequest(request) {
    // Port: metamask-controller.js:3278-3280, legacy-background-api-service.ts:3102-3113; signing remains guarded in keyring.js.
    if (Object.hasOwn(request.permissions, NODUS_PERMISSION)) {
      // The background selects its own identity at approval time. A site or
      // even a stale UI cannot install a different account/public key.
      request = structuredClone(request);
      request.permissions[NODUS_PERMISSION] = { ...request.permissions[NODUS_PERMISSION],
        caveats: [{ type: NODUS_ACCOUNT_CAVEAT, value: getNodusAccount() }] };
    }
    return controller.acceptPermissionsRequest(request);
  }

  function requestPermissionsForOrigin(origin, requestedPermissions) {
    // Port: metamask-controller.js:5530-5539; pending requests stay in ApprovalController until UI unlocks/answers.
    return controller.requestPermissions({ origin }, requestedPermissions, { metadata: { isEip1193Request: true } });
  }

  // Port: handlers/wallet-getPermissions.ts:79-131 and wallet-requestPermissions.ts:161-222.
  function legacyPermissions(origin, permissionMap, includeEmptyAccounts = false) {
    const permissions = { ...permissionMap }, endowment = permissions[Caip25EndowmentPermissionName];
    delete permissions[Caip25EndowmentPermissionName];
    const caveat = endowment?.caveats?.find(item => item.type === Caip25CaveatType);
    if (caveat) {
      const permitted = getAccounts(origin);
      if (includeEmptyAccounts || permitted.length) permissions.eth_accounts = {
        ...endowment, parentCapability: 'eth_accounts', caveats: [{ type: 'restrictReturnedAccounts', value: permitted }],
      };
      const chains = getPermittedEthChainIds(caveat.value);
      if (chains.length) permissions['endowment:permitted-chains'] = {
        ...endowment, parentCapability: 'endowment:permitted-chains', caveats: [{ type: 'restrictNetworkSwitching', value: chains }],
      };
    }
    return Object.values(permissions);
  }

  // Port: handlers/request-accounts.ts:92-143, 181-183; plan §3.4 removes metrics :145-179.
  async function requestAccounts(req, res, _next, end) {
    const { origin } = req;
    if (locks.has(origin)) return end(rpcErrors.resourceUnavailable('Already processing eth_requestAccounts. Please wait.'));
    const permitted = getAccounts(origin);
    if (permitted.length) {
      try { locks.add(origin); res.result = permitted; return end(); }
      finally { locks.delete(origin); }
    }
    await requestPermissionsForOrigin(origin, getCaip25PermissionFromLegacyPermissions());
    res.result = getAccounts(origin);
    return end();
  }

  // Same flow and locked behavior as requestAccounts above: an existing
  // public grant returns immediately; a new grant waits in ApprovalController
  // until the wallet UI unlocks (ui/app.js render's !state.isUnlocked branch).
  async function requestNodusAccounts(req, res, _next, end) {
    const permitted = getNodusAccounts(req.origin);
    if (permitted.length) { res.result = permitted; return end(); }
    await requestPermissionsForOrigin(req.origin, { [NODUS_PERMISSION]: {} });
    res.result = getNodusAccounts(req.origin); return end();
  }

  // Port: handlers/wallet-requestPermissions.ts:113-160.
  async function requestPermissions(req, res, _next, end) {
    if (!Array.isArray(req.params) || !isPlainObject(req.params[0])) throw rpcErrors.invalidParams();
    let requested = { ...req.params[0] };
    delete requested[Caip25EndowmentPermissionName];
    const equivalent = {};
    for (const name of ['eth_accounts', 'endowment:permitted-chains']) {
      if (Object.hasOwn(requested, name)) equivalent[name] = requested[name];
      delete requested[name];
    }
    const hasEquivalent = Object.keys(equivalent).length > 0;
    if (hasEquivalent) requested = { ...requested, ...getCaip25PermissionFromLegacyPermissions(equivalent) };
    const [granted] = await requestPermissionsForOrigin(req.origin, requested);
    res.result = legacyPermissions(req.origin, granted, hasEquivalent);
    return end();
  }

  // Port: handlers/wallet-revokePermissions.ts:86-132; metamask-controller.js:5540-5552 tolerates missing grants.
  function revokePermissions(req, res, _next, end) {
    const param = req.params?.[0];
    if (!param) throw rpcErrors.invalidParams();
    const keys = Object.keys(param).filter(name => name !== Caip25EndowmentPermissionName);
    if (!keys.length) throw rpcErrors.invalidParams();
    const relevant = keys.filter(name => !['eth_accounts', 'endowment:permitted-chains'].includes(name));
    if (relevant.length !== keys.length) relevant.push(Caip25EndowmentPermissionName);
    try { controller.revokePermissions({ [req.origin]: relevant }); }
    catch {
      // Port: metamask-controller.js:5540-5552 returns null for absent grants too.
      // ADAPTATION: plan §11:964-966 removes the raw error log, which may include request data.
    }
    if (relevant.includes(Caip25EndowmentPermissionName) || relevant.includes(NODUS_PERMISSION)) approvals.rejectOrigin(req.origin);
    res.result = null; return end();
  }

  const ethAccountsHandler = { implementation: (req, res, _next, end) => { res.result = getAccounts(req.origin); end(); } };
  // Port: handlers/index.ts:34-56. Plan §16 step 5 owns add/switch/watchAsset, excluded from this package.
  const handlers = {
    eth_accounts: ethAccountsHandler,
    eth_requestAccounts: { implementation: requestAccounts },
    nodus_requestAccounts: { implementation: requestNodusAccounts },
    wallet_getPermissions: { implementation: (req, res, _next, end) => { res.result = legacyPermissions(req.origin, controller.getPermissions(req.origin)); end(); } },
    wallet_requestPermissions: { implementation: requestPermissions },
    wallet_revokePermissions: { implementation: revokePermissions },
    // Port: handlers/get-provider-state.ts:95-104; metamask-controller.js:2287-2299 supplies runtime id.
    [PROVIDER_METHODS.getProviderState]: { implementation: async (req, res, _next, end) => {
      const networkState = await getNetworkState({ isInitializingStreamProvider: req.params?.isInitializingStreamProvider });
      res.result = { isUnlocked: true, accounts: getAccounts(req.origin), extensionId: runtime.id, ...networkState };
      end();
    } },
    // Port: handlers/log-web3-shim-usage.ts:83-91; plan §8 removes MetaMetrics, retaining shim state only.
    [PROVIDER_METHODS.logWeb3ShimUsage]: { implementation: (req, res, _next, end) => {
      if (alertController.state.web3ShimUsageOrigins[req.origin] === undefined) {
        alertController.update(state => { state.web3ShimUsageOrigins[req.origin] = 1; });
      }
      res.result = true; end();
    } },
    // Port: handlers/send-metadata.ts:65-69 is deliberately a backwards-compatibility no-op.
    [SEND_METADATA]: { implementation: (_req, res, _next, end) => { res.result = true; end(); } },
  };

  return { controller, alertController, subjectMetadataController, getAccounts, getNodusAccounts, getChainIds, requestChainPermission, acceptPermissionsRequest,
    setAccounts(value) { accounts = [...value]; },
    // ADAPTATION: plan Q-18 / §3.5: one HD EVM account from package 2, exposed directly instead of an AccountsController.
    // Account type / pre-creation empty address: accounts-controller 39.1.0 dist/AccountsController.cjs:73-80, 180-185.
    getSelectedAccount: () => ({ address: accounts[0] ?? '', type: 'eip155:eoa' }),
    createEthAccountsMethodMiddleware: () => createMethodMiddleware({ handlers: { eth_accounts: ethAccountsHandler }, hooks: {} }),
    createPermissionMiddleware: origin => createPermissionMiddleware({ messenger, origin }),
    createEip1193MethodMiddleware: () => createMethodMiddleware({ handlers, hooks: {} }),
  };
}
