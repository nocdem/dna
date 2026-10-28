import ObjectMultiplex from '@metamask/object-multiplex';
import { ExtensionPortStream } from 'extension-port-stream';
import { pipeline, Transform } from 'readable-stream';
import { JsonRpcEngine } from '@metamask/json-rpc-engine';
import { asLegacyMiddleware, JsonRpcEngineV2, createScaffoldMiddleware } from '@metamask/json-rpc-engine/v2';
import { createEngineStream } from '@metamask/json-rpc-middleware-stream';
import createFilterMiddleware from '@metamask/eth-json-rpc-filters';
import createSubscriptionManager from '@metamask/eth-json-rpc-filters/subscriptionManager.js';
import { createWalletMiddleware, providerAsMiddleware } from '@metamask/eth-json-rpc-middleware';
import { rpcErrors, serializeError } from '@metamask/rpc-errors';
import { convertHexToDecimal } from '@metamask/controller-utils';
import log from 'loglevel';
import { CHAINS } from '../../../src/config.js';
import { EIP_1193_PROVIDER, CAIP_MULTICHAIN_PROVIDER, PROVIDER_METHODS } from '../constants/stream.js';

// Port: shared/constants/app.ts:200; ADAPTATION: approved plan Q-9 (:999) renames the internal origin.
export const ORIGIN_NODUS = 'nodus';

// Port: lib/createEvmMethodsToNonEvmAccountReqFilterMiddleware.ts:17-20, 29-98.
// Method lists: shared/constants/permissions.ts:10-14, controllers/permissions/specifications.ts:88-95.
const METHODS_TO_CHECK = ['eth_accounts', 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_signTypedData',
  'eth_signTypedData_v1', 'eth_signTypedData_v3', 'eth_signTypedData_v4'];

export function createEvmMethodsToNonEvmAccountReqFilterMiddleware({ getSelectedAccount }) {
  // ADAPTATION: plan Q-18 / §3.5: the single HD account's accessor replaces the AccountsController messenger action.
  return (req, _res, next, end) => {
    const selectedAccount = getSelectedAccount();
    // Port the keyring-api 24.1.0 dist/eth/utils.mjs:8-10 predicate without adding an undeclared dependency.
    if (selectedAccount.type === 'eip155:eoa' || selectedAccount.type === 'eip155:erc4337') return next();
    if (METHODS_TO_CHECK.includes(req.method)) return end(new Error(`Non-EVM account cannot request this method: ${req.method}`));
    if (req.method === 'wallet_requestPermissions' && req.params && Array.isArray(req.params) && req.params.length > 0 && req.params[0]) {
      const permissionsMethodRequest = Object.keys(req.params[0]);
      if (METHODS_TO_CHECK.some(method => permissionsMethodRequest.includes(method))) {
        return end(new Error(`Non-EVM account cannot request this method: ${permissionsMethodRequest.toString()}`));
      }
    }
    return next();
  };
}

// Port: MetaMask v13.54.0 app/scripts/lib/parse-port-info.ts:31-47, Chromium branch only (plan §3.2).
export function parsePortInfo(port, runtime) {
  let senderUrl = null;
  try { if (port.sender?.url) senderUrl = new URL(port.sender.url); } catch { /* Malformed senders have no trusted origin. */ }
  // ADAPTATION: plan §3.2:195-197's Chromium origin comparison, serialized explicitly for Node's opaque-scheme URL implementation.
  const origin = senderUrl?.protocol === 'chrome-extension:' ? `${senderUrl.protocol}//${senderUrl.host}` : senderUrl?.origin;
  return { processName: port.name, senderUrl, origin, isUiPort: origin === `chrome-extension://${runtime.id}` };
}

// Port: app/scripts/lib/createDupeReqFilterStream.ts:10-79.
function createDupeReqFilterStream() {
  const seen = new Map();
  const timer = setInterval(() => {
    const cutoff = Date.now() - 180_000;
    for (const [id, time] of seen) { if (time <= cutoff) seen.delete(id); else break; }
  }, 180_000);
  return new Transform({ objectMode: true,
    transform(request, _encoding, done) {
      if (request.id === undefined) return done(null, request);
      if (seen.has(request.id)) return done();
      seen.set(request.id, Date.now()); done(null, request);
    },
    destroy(error, done) { clearInterval(timer); seen.clear(); done(error); },
  });
}

export function createRequestEngine({ runtime, permissions, approvals, autoLockAlarm, trustedApi, getUiPorts, networkClient: initialNetworkClient }) {
  const connections = new Map(), ports = new Set();
  // Port: background.ts:207, 935-952, with no disconnect-time deletion in that reference path.
  const requestAccountTabIds = {};
  let networkClient = null, networkVersion, getNetworkMetadata;

  // Port: shared/lib/network.utils.ts:78-86 (hex predicate equivalent to utils dist/hex.mjs:33-34).
  function convertNetworkId(value) {
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return `${value}`;
    if (typeof value === 'string' && /^0x[0-9a-f]+$/iu.test(value)) return `${convertHexToDecimal(value)}`;
    if (typeof value === 'string' && /^\d+$/u.test(value)) return value;
    return null;
  }

  // ADAPTATION: plan Q-24 (§5.6:816-827), Kurultay 51: one shared client; no SelectedNetworkController/domains.
  // Plan §16 step 5 supplies the real EVM client. Attachment is local-only, never a site or UI RPC method.
  function attachNetworkClient(client, readMetadata) {
    if (typeof client?.provider?.request !== 'function' || typeof client.provider.sendAsync !== 'function' ||
      typeof client.blockTracker?.on !== 'function' || typeof client.blockTracker?.getLatestBlock !== 'function' ||
      !/^0x[0-9a-f]+$/iu.test(client.configuration?.chainId) ||
      (readMetadata !== undefined && typeof readMetadata !== 'function')) throw new Error('Invalid EVM network client.');
    networkClient = client; networkVersion = undefined; getNetworkMetadata = readMetadata;
    for (const connection of connections.values()) {
      connection.resetNetwork();
      void notifyChainChange(connection);
    }
  }

  // Port: metamask-controller.js:2311-2366; plan §5.6 defaults mainnet, web-wallet config supplies chain data.
  async function getNetworkState({ isInitializingStreamProvider = false } = {}) {
    const client = networkClient;
    if (client && networkVersion === undefined && !isInitializingStreamProvider) {
      try {
        const version = await client.provider.request({ method: 'net_version' });
        if (client === networkClient) networkVersion = convertNetworkId(version);
      } catch {
        // Plan §11: never log raw provider errors, which may contain signing parameters.
        if (client === networkClient) networkVersion = null;
      }
    }
    // Port: metamask-controller.js:2359-2365, shared/constants/network.ts:1802.
    // Package 5 supplies its NetworkController metadata reader along with the client; absent metadata is disconnected.
    return { chainId: networkClient?.configuration.chainId ?? `0x${CHAINS.ethereum.chainId.toString(16)}`,
      networkVersion: networkVersion ?? 'loading', isConnected: getNetworkMetadata?.()?.status === 'available' };
  }

  // Port: metamask-controller.js:5216-5654, preserving retained middleware order.
  function setupProviderEngineEip1193({ origin, tabId, frameId, mainFrameOrigin, subjectType }) {
    const engine = new JsonRpcEngine();
    // Port: lib/createOriginMiddleware.js:7-16; main/frame/tab middleware overwrite all page-supplied context.
    engine.push((req, _res, next) => { req.origin = origin; next(); });
    if (mainFrameOrigin) engine.push((req, _res, next) => { req.mainFrameOrigin = mainFrameOrigin; next(); });
    // Q-24 removes createSelectedNetworkMiddleware (:5235); every connection reads the one client above.
    let clientEngine = null, clientMiddleware = null;
    function resetNetwork() { clientEngine?.destroy(); clientEngine = null; clientMiddleware = null; }
    if (tabId) engine.push((req, _res, next) => { req.tabId = tabId; next(); });
    if (typeof frameId === 'number') engine.push((req, _res, next) => { req.frameId = frameId; next(); });
    // Port: lib/createLoggerMiddleware.js:17-30. ADAPTATION: plan §3.4:299-303/§11:964-966,
    // F7 forbids the reference's whole-error log too; emit only trusted origin/method/status, never params/errors.
    engine.push((req, res, next) => next(done => {
      // ADAPTATION: plan Q-9 (:999) renames req.isMetamaskInternal; preserve the reference's flag-based skip.
      if (!req.isNodusInternal) log.info(`RPC (${origin}): ${req.method} -> ${res.error ? 'error' : 'success'}`);
      done();
    }));
    engine.push(approvals.createOriginThrottlingMiddleware());
    // Plan §3.4:312-319 removes permission log, traces, scans, referrals, swaps, snaps and EIP-7715.
    engine.push((req, _res, next, end) => req.method === 'eth_signTransaction' ? end(rpcErrors.methodNotSupported()) : next());
    engine.push(permissions.createEthAccountsMethodMiddleware());
    if (subjectType !== 'internal') engine.push(permissions.createPermissionMiddleware(origin));
    // Port: metamask-controller.js:5476-5480, after permission checks and before the EIP-1193 handlers.
    engine.push(createEvmMethodsToNonEvmAccountReqFilterMiddleware({ getSelectedAccount: () => permissions.getSelectedAccount() }));
    engine.push(permissions.createEip1193MethodMiddleware());

    // Port: metamask-controller.js:5247-5251, 5640-5641. Lazily bind filters to the package-5 client.
    const filtersAndSubscriptions = (req, res, next, end) => {
      if (!networkClient) return next();
      if (!clientEngine) {
        clientEngine = new JsonRpcEngine();
        const filter = createFilterMiddleware(networkClient), subscriptions = createSubscriptionManager(networkClient);
        subscriptions.events.on('notification', message => engine.emit('notification', message));
        clientEngine.push(filter); clientEngine.push(subscriptions.middleware);
        clientMiddleware = clientEngine.asMiddleware();
      }
      return clientMiddleware(req, res, next, end);
    };
    filtersAndSubscriptions.destroy = resetNetwork;
    engine.push(filtersAndSubscriptions);

    // Port: lib/createMetamaskMiddleware.ts:21-63. Plan §16 step 5 owns signing hooks;
    // absent hooks intentionally use the real wallet middleware's methodNotSupported branches.
    // Deferred to package 5 (dispatch correction; plan §16 step 5): pending nonce/tx middleware (:59-60) needs its transaction controller.
    engine.push(asLegacyMiddleware(JsonRpcEngineV2.create({ middleware: [
      // ADAPTATION: plan Q-9 (:999) renames the reference's MetaMask/v client identifier.
      createScaffoldMiddleware({ eth_syncing: false, web3_clientVersion: `Nodus/v${runtime.getManifest().version}` }),
      createWalletMiddleware({ getAccounts: origin => permissions.getAccounts(origin) }),
    ] })));
    // Port: metamask-controller.js:5651. No node backend is fabricated before package 5 attaches it.
    engine.push((req, res, next, end) => {
      if (!networkClient) return end(rpcErrors.resourceUnavailable('EVM network client is not attached.'));
      return providerAsMiddleware(networkClient.provider)(req, res, next, end);
    });
    return { engine, resetNetwork };
  }

  async function notifyChainChange(connection) {
    const params = await getNetworkState();
    if (connections.has(connection.id)) connection.engine.emit('notification', { jsonrpc: '2.0', method: PROVIDER_METHODS.chainChanged, params });
  }

  // Port: metamask-controller.js:4936-5006, with plan §3.3's renamed notification constants.
  function setupProviderConnectionEip1193(outStream, sender, subjectType) {
    const origin = subjectType === 'internal' ? ORIGIN_NODUS : new URL(sender.url).origin;
    // Port: metamask-controller.js:4946-4952; record only other extensions, using the sender's real id.
    if (sender.id && sender.id !== runtime.id) permissions.subjectMetadataController.addSubjectMetadata({
      origin, extensionId: sender.id, subjectType: 'extension',
    });
    const mainFrameOrigin = sender.tab?.url ? new URL(sender.tab.url).origin : origin;
    const { engine, resetNetwork } = setupProviderEngineEip1193({ origin, subjectType, mainFrameOrigin, tabId: sender.tab?.id, frameId: sender.frameId });
    const duplicateFilter = createDupeReqFilterStream(), providerStream = createEngineStream({ engine });
    const id = Symbol(origin), connection = { id, origin, engine, resetNetwork, outStream };
    connections.set(id, connection);
    pipeline(outStream, duplicateFilter, providerStream, outStream, () => {
      engine.destroy(); connections.delete(id);
      // Plan §11: no raw stream/request error logging.
    });
    if (subjectType !== 'internal') void notifyChainChange(connection);
    return connection;
  }

  // Port: lib/stream-utils.ts setupMultiplex, metamask-controller.js:4545-4554.
  function setupMultiplex(connectionStream) {
    const mux = new ObjectMultiplex(); mux.setMaxListeners(25);
    pipeline(connectionStream, mux, connectionStream, () => {});
    return mux;
  }

  function setupUntrustedCommunicationEip1193({ connectionStream, sender }) {
    const subjectType = sender.id && sender.id !== runtime.id ? 'extension' : 'website';
    const mux = setupMultiplex(connectionStream);
    mux.ignoreStream(CAIP_MULTICHAIN_PROVIDER);
    // Plan §3.4 removes phishing/publicConfig; §16 step 7 owns the CAIP port.
    return setupProviderConnectionEip1193(mux.createStream(EIP_1193_PROVIDER), sender, subjectType);
  }

  // Port: metamask-controller.js:4601-4613, 4855-4856; lib/createMetaRPCHandler.ts:30-118.
  function setupTrustedCommunication(connectionStream, sender, port) {
    const mux = setupMultiplex(connectionStream), controllerStream = mux.createStream('controller');
    const activity = autoLockAlarm.openTrustedInterface();
    const api = { ...trustedApi, setLastActiveTime: () => activity.activity() };
    const onData = async data => {
      if (!data || typeof data.method !== 'string' || !Object.hasOwn(api, data.method)) {
        if (!controllerStream.destroyed) controllerStream.write({ jsonrpc: '2.0', id: data?.id, error: serializeError(rpcErrors.methodNotFound()) });
        return;
      }
      let result, error;
      try { result = Array.isArray(data.params) ? await api[data.method](...data.params) : await api[data.method](data.params); }
      catch (caught) { error = serializeError(caught); }
      if (!controllerStream.destroyed && !controllerStream.writableEnded) {
        controllerStream.write({ jsonrpc: '2.0', id: data.id, ...(error ? { error } : { result: result ?? null }) });
      }
    };
    controllerStream.on('data', onData);
    const close = () => { activity.close(); controllerStream.removeListener('data', onData); getUiPorts().delete(port); };
    controllerStream.once('close', close); controllerStream.once('end', close);
    getUiPorts().add(port);
    return setupProviderConnectionEip1193(mux.createStream('provider'), sender, 'internal');
  }

  // Port: background.ts:796-839, 968-970; trust is derived exclusively from sender URL.
  function onConnect(port) {
    const info = parsePortInfo(port, runtime);
    // Port: background.ts:935-952; tab tracking observes eth_requestAccounts on untrusted port messages.
    if (!info.isUiPort && port.sender?.tab && port.sender.url) {
      const tabId = port.sender.tab.id, { origin } = new URL(port.sender.url);
      port.onMessage.addListener(message => {
        if (message && typeof message === 'object' && !Array.isArray(message) &&
          message.data && typeof message.data === 'object' && !Array.isArray(message.data) &&
          message.data.method === 'eth_requestAccounts' && tabId !== undefined) requestAccountTabIds[origin] = tabId;
      });
    }
    // Port: background.ts:807-808, 968: only page streams disable chunking.
    const stream = info.isUiPort ? new ExtensionPortStream(port) : new ExtensionPortStream(port, { chunkSize: 0 });
    ports.add(stream); stream.once('close', () => ports.delete(stream));
    if (info.isUiPort) setupTrustedCommunication(stream, port.sender, port);
    else setupUntrustedCommunicationEip1193({ connectionStream: stream, sender: port.sender });
  }

  async function notifyAccountsChanged() {
    for (const connection of connections.values()) {
      const accounts = permissions.getAccounts(connection.origin);
      if (connections.has(connection.id)) connection.engine.emit('notification', { jsonrpc: '2.0', method: PROVIDER_METHODS.accountsChanged, params: accounts });
    }
  }

  // Port: background.ts:520; drain package 3's early-port buffer when loaded by the service worker.
  const lazyListener = globalThis.chrome?.runtime === runtime && globalThis.stateHooks?.lazyListener;
  if (lazyListener) lazyListener.addListener('runtime', 'onConnect', onConnect);
  else runtime.onConnect.addListener(onConnect);
  if (initialNetworkClient) attachNetworkClient(initialNetworkClient);
  return { connections, requestAccountTabIds, onConnect, setupUntrustedCommunicationEip1193, setupProviderConnectionEip1193,
    setupProviderEngineEip1193, getNetworkState, attachNetworkClient, notifyAccountsChanged,
    destroy() { runtime.onConnect.removeListener(onConnect); for (const stream of ports) stream.destroy(); for (const connection of connections.values()) { connection.engine.destroy(); connection.outStream.destroy(); } connections.clear(); } };
}
