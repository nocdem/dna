// Port: MetaMask v13.54.0 app/scripts/inpage.js:4-31; plan §9:930-932 uses Vite, so address its global namespace through globalThis.
let __define;
const cleanContextForImports = () => {
  __define = globalThis.define;
  try { globalThis.define = undefined; }
  catch { console.warn('Nodus - global.define could not be deleted.'); }
};
const restoreContextAfterImports = () => {
  try { globalThis.define = __define; }
  catch { console.warn('Nodus - global.define could not be overwritten.'); }
};
cleanContextForImports();

import log from 'loglevel';
import { v4 as uuid } from 'uuid';
import { BaseProvider, eip6963AnnounceProvider, caip294AnnounceWallet } from '@metamask/providers';
import { setGlobalProvider } from '@metamask/providers/initializeInpageProvider';
import { createIdRemapMiddleware } from '@metamask/json-rpc-engine';
import { createStreamMiddleware } from '@metamask/json-rpc-middleware-stream';
import { rpcErrors } from '@metamask/rpc-errors';
import isStream from 'is-stream/index.js';
import { WindowPostMessageStream } from '@metamask/post-message-stream';
import ObjectMultiplex from '@metamask/object-multiplex';
import { pipeline } from 'readable-stream';
import { CONTENT_SCRIPT, INPAGE, EIP_1193_PROVIDER, PROVIDER_METHODS } from './constants/stream.js';
import shouldInjectProvider from './lib/provider-injection.js';

// Port: app/scripts/inpage.js:55-57; 'warn' is the reference default when METAMASK_DEBUG is unset.
restoreContextAfterImports();
log.setDefaultLevel('warn');

// Exact existing web-wallet/public/assets/nodus-mark.svg (including its final newline).
const icon = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="17" fill="#d5f998"/><g fill="none" stroke="#171b13" stroke-width="7" stroke-linecap="square" stroke-linejoin="round"><path d="M17 44V21l30 23V21"/><path d="M17 32 32 20 47 32M17 44l15-12 15 12"/></g></svg>\n');

// Port: providers 22.1.1 dist/messages.mjs:3-8,20-35; Q-9 renames the provider and API identifier, preserving reference text and links.
const messages = {
  errors: {
    disconnected: () => 'Nodus: Disconnected from chain. Attempting to connect.',
    permanentlyDisconnected: () => 'Nodus: Disconnected from Nodus background. Page reload required.',
    unsupportedSync: method => `Nodus: The Nodus Ethereum provider does not support synchronous methods like ${method} without a callback parameter.`,
    invalidNetworkParams: () => 'Nodus: Received invalid network parameters. Please report this bug.',
  },
  warnings: {
    enableDeprecation: "Nodus: 'ethereum.enable()' is deprecated and may be removed in the future. Please use the 'eth_requestAccounts' RPC method instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1102",
    sendDeprecation: "Nodus: 'ethereum.send(...)' is deprecated and may be removed in the future. Please use 'ethereum.sendAsync(...)' or 'ethereum.request(...)' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193",
    events: {
      close: "Nodus: The event 'close' is deprecated and may be removed in the future. Please use 'disconnect' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#disconnect",
      data: "Nodus: The event 'data' is deprecated and will be removed in the future. Use 'message' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#message",
      networkChanged: "Nodus: The event 'networkChanged' is deprecated and may be removed in the future. Use 'chainChanged' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#chainchanged",
      notification: "Nodus: The event 'notification' is deprecated and may be removed in the future. Use 'message' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#message",
    },
    rpc: {
      ethDecryptDeprecation: "Nodus: The RPC method 'eth_decrypt' is deprecated and may be removed in the future.\nFor more information, see: https://medium.com/metamask/metamask-api-method-deprecation-2b0564a84686",
      ethGetEncryptionPublicKeyDeprecation: "Nodus: The RPC method 'eth_getEncryptionPublicKey' is deprecated and may be removed in the future.\nFor more information, see: https://medium.com/metamask/metamask-api-method-deprecation-2b0564a84686",
      walletWatchAssetNFTExperimental: "Nodus: The RPC method 'wallet_watchAsset' is experimental for ERC721/ERC1155 assets and may change in the future.\nFor more information, see: https://github.com/MetaMask/metamask-improvement-proposals/blob/main/MIPs/mip-1.md and https://github.com/MetaMask/metamask-improvement-proposals/blob/main/PROCESS-GUIDE.md#proposal-lifecycle",
    },
    experimentalMethods: "Nodus: 'ethereum._nodus' exposes non-standard, experimental methods. They may be removed or changed without warning.",
  },
};

// Source port under Q-9: providers 22.1.1 dist/utils.mjs:22-62 and
// dist/middleware/createRpcWarningMiddleware.mjs:11-44; request behavior stays in the pinned BaseProvider.
function getDefaultExternalMiddleware(log) {
  const warned = new Set();
  return [
    createIdRemapMiddleware(),
    (request, response, next) => {
      if (typeof request.method !== 'string' || !request.method) {
        response.error = rpcErrors.invalidRequest({ message: "The request 'method' must be a non-empty string.", data: request });
      }
      next(done => {
        const { error } = response;
        if (error) log.warn(`Nodus - RPC Error: ${error.message}`, error);
        done();
      });
    },
    (request, _response, next) => {
      const deprecated = ['eth_decrypt', 'eth_getEncryptionPublicKey'].includes(request.method);
      const experimental = request.method === 'wallet_watchAsset' && ['ERC721', 'ERC1155'].includes(request.params?.type || '');
      if ((deprecated || experimental) && !warned.has(request.method)) {
        warned.add(request.method);
        log.warn(request.method === 'eth_decrypt' ? messages.warnings.rpc.ethDecryptDeprecation
          : request.method === 'eth_getEncryptionPublicKey' ? messages.warnings.rpc.ethGetEncryptionPublicKeyDeprecation
            : messages.warnings.rpc.walletWatchAssetNFTExperimental);
      }
      next();
    },
  ];
}
const getRpcPromiseCallback = (resolve, reject, unwrapResult = true) => (error, response) => {
  if (error || response.error) reject(error || response.error);
  else resolve(!unwrapResult || Array.isArray(response) ? response : response.result);
};
const isValidChainId = value => Boolean(value) && typeof value === 'string' && value.startsWith('0x');
const isValidNetworkVersion = value => typeof value === 'string' && (/^(\d*[1-9]\d*|0)$/u.test(value) || value === 'loading');

// Port: providers 22.1.1 dist/StreamProvider.mjs:25-128; all notification/retry/state identifiers use Q-9 Nodus constants.
class NodusStreamProvider extends BaseProvider {
  constructor(connectionStream, { logger = log, maxEventListeners = 100, rpcMiddleware = [] } = {}) {
    // BaseProvider.mjs:46,222,273,296-311 accepts a logger; Q-9 renames only its leading brand, preserving every other argument.
    const renamedLogger = new Proxy(logger, {
      get(target, property) {
        if (property === 'debug' || property === 'error') return (message, ...args) =>
          target[property](typeof message === 'string' ? message.replace(/^MetaMask/u, 'Nodus') : message, ...args);
        return Reflect.get(target, property);
      },
    });
    super({ logger: renamedLogger, maxEventListeners, rpcMiddleware });
    if (!isStream.duplex(connectionStream)) throw new Error('Must provide a Node.js-style duplex stream.');
    this._handleStreamDisconnect = this._handleStreamDisconnect.bind(this);
    this._jsonRpcConnection = createStreamMiddleware({ retryOnMessage: PROVIDER_METHODS.connectCanRetry });
    pipeline(connectionStream, this._jsonRpcConnection.stream, connectionStream, this._handleStreamDisconnect.bind(this, 'Nodus RpcProvider'));
    this._rpcEngine.push(this._jsonRpcConnection.middleware);
    this._jsonRpcConnection.events.on('notification', ({ method, params }) => {
      if (method === PROVIDER_METHODS.accountsChanged) this._handleAccountsChanged(params);
      else if (method === PROVIDER_METHODS.chainChanged) this._handleChainChanged(params);
      else if (method === 'eth_subscription') this.emit('message', { type: method, data: params });
      else if (method === PROVIDER_METHODS.streamFailure) connectionStream.destroy(new Error(messages.errors.permanentlyDisconnected()));
    });
  }

  async _initializeStateAsync() {
    let initialState;
    try {
      initialState = await this.request({ method: PROVIDER_METHODS.getProviderState, params: { isInitializingStreamProvider: true } });
    } catch (error) {
      this._log.error('Nodus: Failed to get initial state. Please report this bug.', error);
    }
    this._initializeState(initialState);
  }

  _handleStreamDisconnect(streamName, error) {
    let warning = `Nodus: Lost connection to "${streamName}".`;
    if (error?.stack) warning += `\n${error.stack}`;
    this._log.warn(warning);
    if (this.listenerCount('error') > 0) this.emit('error', warning);
    this._handleDisconnect(false, error?.message);
  }

  // Plan §3.3:235-247/Q-9 requires renamed defaults before BaseProvider.mjs:236-255 constructs the page-visible error.
  _handleDisconnect(isRecoverable, errorMessage) {
    super._handleDisconnect(isRecoverable, errorMessage ?? (isRecoverable
      ? messages.errors.disconnected()
      : messages.errors.permanentlyDisconnected()));
  }

  _handleChainChanged({ chainId, networkVersion, isConnected } = {}) {
    if (!isValidChainId(chainId) || !isValidNetworkVersion(networkVersion)) {
      this._log.error(messages.errors.invalidNetworkParams(), { chainId, networkVersion });
      return;
    }
    super._handleChainChanged({ chainId, isConnected });
    if (!isConnected) this._handleDisconnect(true);
  }
}

// Port: providers 22.1.1 dist/MetaMaskInpageProvider.mjs:34-77, 97-324.
// Metadata stays disabled as in app/scripts/inpage.js:115; the source port avoids the package's hard-coded identifiers.
class NodusInpageProvider extends NodusStreamProvider {
  #networkVersion = null;

  constructor(connectionStream, { logger = log, maxEventListeners = 100 } = {}) {
    super(connectionStream, { logger, maxEventListeners, rpcMiddleware: getDefaultExternalMiddleware(logger) });
    this._sentWarnings = { enable: false, experimentalMethods: false, send: false, events: { close: false, data: false, networkChanged: false, notification: false } };
    this._initializeStateAsync();
    this.isNodus = true;
    this._sendSync = this._sendSync.bind(this);
    this.enable = this.enable.bind(this);
    this.send = this.send.bind(this);
    this.sendAsync = this.sendAsync.bind(this);
    this._warnOfDeprecation = this._warnOfDeprecation.bind(this);
    this._nodus = this._getExperimentalApi();
    this._jsonRpcConnection.events.on('notification', payload => {
      if (payload.method === 'eth_subscription') {
        this.emit('data', payload);
        this.emit('notification', payload.params.result);
      }
    });
  }

  get chainId() { return super.chainId; }
  get networkVersion() { return this.#networkVersion; }
  get selectedAddress() { return super.selectedAddress; }
  sendAsync(payload, callback) { this._rpcRequest(payload, callback); }
  addListener(event, listener) { this._warnOfDeprecation(event); return super.addListener(event, listener); }
  on(event, listener) { this._warnOfDeprecation(event); return super.on(event, listener); }
  once(event, listener) { this._warnOfDeprecation(event); return super.once(event, listener); }
  prependListener(event, listener) { this._warnOfDeprecation(event); return super.prependListener(event, listener); }
  prependOnceListener(event, listener) { this._warnOfDeprecation(event); return super.prependOnceListener(event, listener); }

  _handleDisconnect(isRecoverable, errorMessage) {
    super._handleDisconnect(isRecoverable, errorMessage);
    if (this.#networkVersion && !isRecoverable) this.#networkVersion = null;
  }

  _warnOfDeprecation(event) {
    if (this._sentWarnings?.events[event] === false) {
      this._log.warn(messages.warnings.events[event]);
      this._sentWarnings.events[event] = true;
    }
  }

  async enable() {
    if (!this._sentWarnings.enable) {
      this._log.warn(messages.warnings.enableDeprecation);
      this._sentWarnings.enable = true;
    }
    return new Promise((resolve, reject) => {
      try { this._rpcRequest({ method: 'eth_requestAccounts', params: [] }, getRpcPromiseCallback(resolve, reject)); }
      catch (error) { reject(error); }
    });
  }

  send(methodOrPayload, callbackOrArgs) {
    if (!this._sentWarnings.send) {
      this._log.warn(messages.warnings.sendDeprecation);
      this._sentWarnings.send = true;
    }
    if (typeof methodOrPayload === 'string' && (!callbackOrArgs || Array.isArray(callbackOrArgs))) {
      return new Promise((resolve, reject) => {
        try { this._rpcRequest({ method: methodOrPayload, params: callbackOrArgs }, getRpcPromiseCallback(resolve, reject, false)); }
        catch (error) { reject(error); }
      });
    }
    if (methodOrPayload && typeof methodOrPayload === 'object' && typeof callbackOrArgs === 'function') return this._rpcRequest(methodOrPayload, callbackOrArgs);
    return this._sendSync(methodOrPayload);
  }

  _sendSync(payload) {
    let result;
    switch (payload.method) {
      case 'eth_accounts': result = this.selectedAddress ? [this.selectedAddress] : []; break;
      case 'eth_coinbase': result = this.selectedAddress ?? null; break;
      case 'eth_uninstallFilter': this._rpcRequest(payload, () => {}); result = true; break;
      case 'net_version': result = this.#networkVersion ?? null; break;
      default: throw new Error(messages.errors.unsupportedSync(payload.method));
    }
    return { id: payload.id, jsonrpc: payload.jsonrpc, result };
  }

  _getExperimentalApi() {
    return new Proxy({
      isUnlocked: async () => !this._state.isPermanentlyDisconnected,
      requestBatch: async requests => {
        if (!Array.isArray(requests)) throw rpcErrors.invalidRequest({ message: 'Batch requests must be made with an array of request objects.', data: requests });
        return new Promise((resolve, reject) => this._rpcRequest(requests, getRpcPromiseCallback(resolve, reject)));
      },
    }, {
      get: (object, property, ...args) => {
        if (!this._sentWarnings.experimentalMethods) {
          this._log.warn(messages.warnings.experimentalMethods);
          this._sentWarnings.experimentalMethods = true;
        }
        return Reflect.get(object, property, ...args);
      },
    });
  }

  _handleChainChanged({ chainId, networkVersion, isConnected } = {}) {
    super._handleChainChanged({ chainId, networkVersion, isConnected });
    const targetNetworkVersion = networkVersion === 'loading' ? null : networkVersion;
    if (targetNetworkVersion !== this.#networkVersion) {
      this.#networkVersion = targetNetworkVersion;
      if (this._state.initialized) this.emit('networkChanged', this.#networkVersion);
    }
  }
}

// Port: providers 22.1.1 dist/shimWeb3.mjs:8-50, with Q-9 shim/usage names.
function shimWeb3(provider, log) {
  if (window.web3) return;
  let loggedCurrentProvider = false, loggedMissingProperty = false;
  const shimIdentifier = '__isNodusShim__';
  const shim = { currentProvider: provider };
  Object.defineProperty(shim, shimIdentifier, { value: true, enumerable: true, configurable: false, writable: false });
  const web3 = new Proxy(shim, {
    get(target, property, ...args) {
      if (property === 'currentProvider' && !loggedCurrentProvider) {
        loggedCurrentProvider = true;
        log.warn('You are accessing the Nodus window.web3.currentProvider shim. This property is deprecated; use window.ethereum instead. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3');
      } else if (property !== 'currentProvider' && property !== shimIdentifier && !loggedMissingProperty) {
        loggedMissingProperty = true;
        log.error('Nodus no longer injects web3. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3');
        provider.request({ method: PROVIDER_METHODS.logWeb3ShimUsage }).catch(error => log.debug('Nodus: Failed to log web3 shim usage.', error));
      }
      return Reflect.get(target, property, ...args);
    },
    set(...args) {
      log.warn('You are accessing the Nodus window.web3 shim. This object is deprecated; use window.ethereum instead. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3');
      return Reflect.set(...args);
    },
  });
  Object.defineProperty(window, 'web3', { value: web3, enumerable: false, configurable: true, writable: true });
}

// Source port: providers 22.1.1 dist/initializeInpageProvider.mjs:19-65, 75-91.
// Plan §3.3:235-247 requires the source initializer: the imported initializeProvider constructs hard-coded MetaMask classes and methods.
export function initializeProvider({ connectionStream, providerInfo, logger = log, shouldShimWeb3 = true }) {
  const provider = new NodusInpageProvider(connectionStream, { logger });
  const proxiedProvider = new Proxy(provider, { deleteProperty: () => true, get: (target, property) => target[property] });
  if (providerInfo) {
    eip6963AnnounceProvider({ info: providerInfo, provider: proxiedProvider });
    provider.request({ method: PROVIDER_METHODS.getProviderState }).then(providerState => {
      const targets = providerState?.extensionId ? [{ type: 'caip-348', value: providerState.extensionId }] : [];
      caip294AnnounceWallet({ ...providerInfo, targets });
    });
  }
  setGlobalProvider(proxiedProvider);
  if (shouldShimWeb3) shimWeb3(proxiedProvider, logger);
  return proxiedProvider;
}

// Port: MetaMask v13.54.0 app/scripts/inpage.js:63-122. Solana wallet-standard registration belongs to package 7.
export function startInpage() {
  if (!shouldInjectProvider()) return null;
  const stream = new WindowPostMessageStream({ name: INPAGE, target: CONTENT_SCRIPT });
  const mux = new ObjectMultiplex();
  pipeline(stream, mux, stream, error => {
    let warning = `Lost connection to "${EIP_1193_PROVIDER}".`;
    if (error?.stack) warning += `\n${error.stack}`;
    console.warn(warning);
  });
  const provider = initializeProvider({
    connectionStream: mux.createStream(EIP_1193_PROVIDER), logger: log,
    // Plan §3.3:252-254 fixes metadata off; this source initializer omits the unused metadata option and metadata branch.
    shouldShimWeb3: true,
    providerInfo: { uuid: uuid(), name: 'Nodus Wallet', icon, rdns: 'io.nodusnetwork.wallet' },
  });
  return { provider, stream, mux };
}

export const inpage = startInpage();
