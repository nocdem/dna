import ObjectMultiplex from '@metamask/object-multiplex';
import { WindowPostMessageStream } from '@metamask/post-message-stream';
import { pipeline } from 'readable-stream';
import browser from 'webextension-polyfill';
import { ExtensionPortStream } from 'extension-port-stream';
import shouldInjectProvider from './lib/provider-injection.js';
import { CONTENT_SCRIPT, INPAGE, EIP_1193_PROVIDER, CAIP_MULTICHAIN_PROVIDER, PROVIDER_METHODS, EXTENSION_READY } from './constants/stream.js';

// Port: MetaMask v13.54.0 app/scripts/contentscript.js:31-58; factory exposes the entry's streams to tests.
// Plan: approved 2026-10-28-nodus-extension.md:223-234 removes phishing, cookie, cashtag and legacy streams.
export function startContentscript({ runtime = browser.runtime } = {}) {
  if (!shouldInjectProvider()) return null;
  let extensionMux, extensionEip1193Channel, extensionCaipChannel;
  let extensionPort = null, extensionStream = null;
  let pageStream, pageMux, pageChannel, caipChannel;
  let NODUS_EXTENSION_CONNECT_SENT = false;

  // Port: app/scripts/streams/provider-stream.ts:45-102.
  function setupPageStreams() {
    pageStream = new WindowPostMessageStream({ name: CONTENT_SCRIPT, target: INPAGE });
    pageMux = new ObjectMultiplex();
    pageMux.setMaxListeners(25);
    const endPageMuxIfOpen = () => {
      if (!pageMux.destroyed && !pageMux.writableEnded) pageMux.end();
    };
    pageStream.once?.('close', endPageMuxIfOpen);
    pageStream.once?.('end', endPageMuxIfOpen);
    pipeline(pageMux, pageStream, pageMux, error => logStreamDisconnectWarning('Nodus Inpage Multiplex', error));
    pageChannel = pageMux.createStream(EIP_1193_PROVIDER);
    caipChannel = pageMux.createStream(CAIP_MULTICHAIN_PROVIDER);
  }

  // Port: app/scripts/streams/provider-stream.ts:114-170, with two per-channel pipelines.
  function setupExtensionStreams() {
    NODUS_EXTENSION_CONNECT_SENT = true;
    extensionPort = runtime.connect({ name: CONTENT_SCRIPT });
    extensionStream = new ExtensionPortStream(extensionPort, { chunkSize: 0 });
    extensionStream.on('data', extensionStreamMessageListener);
    extensionMux = new ObjectMultiplex();
    extensionMux.setMaxListeners(25);
    const endExtensionMuxIfOpen = () => {
      if (!extensionMux.destroyed && !extensionMux.writableEnded) extensionMux.end();
    };
    extensionStream?.once?.('close', endExtensionMuxIfOpen);
    extensionStream?.once?.('end', endExtensionMuxIfOpen);
    pipeline(extensionMux, extensionStream, extensionMux, error => {
      logStreamDisconnectWarning('Nodus Background Multiplex', error);
      notifyInpageOfStreamFailure();
    });
    extensionEip1193Channel = extensionMux.createStream(EIP_1193_PROVIDER);
    pipeline(pageChannel, extensionEip1193Channel, pageChannel, error =>
      console.debug(`Nodus: Muxed traffic for channel "${EIP_1193_PROVIDER}" failed.`, error));
    extensionCaipChannel = extensionMux.createStream(CAIP_MULTICHAIN_PROVIDER);
    pipeline(caipChannel, extensionCaipChannel, caipChannel, error =>
      console.debug(`Nodus: Muxed traffic for channel "${CAIP_MULTICHAIN_PROVIDER}" failed.`, error));
    extensionPort.onDisconnect.addListener(onDisconnectDestroyStreams);
  }

  // Port: app/scripts/streams/provider-stream.ts:174-187.
  function destroyExtensionStreams() {
    pageChannel.removeAllListeners();
    // Failure-fix dispatch: apply reference :175's cleanup to both :150-165 page channels so reconnect replaces every pipeline's listeners.
    caipChannel.removeAllListeners();
    extensionMux.removeAllListeners();
    extensionMux.destroy();
    extensionEip1193Channel.removeAllListeners();
    extensionEip1193Channel.destroy();
    extensionCaipChannel.removeAllListeners();
    extensionCaipChannel.destroy();
    extensionStream = null;
  }

  // Port: app/scripts/streams/provider-stream.ts:294-306.
  function onMessageSetUpExtensionStreams(message) {
    if (message !== null && typeof message === 'object' && !Array.isArray(message) && message.name === EXTENSION_READY) {
      if (!extensionStream) setupExtensionStreams();
      return Promise.resolve(`Nodus: handled ${EXTENSION_READY}`);
    }
    return undefined;
  }

  // Port: app/scripts/streams/provider-stream.ts:312-325.
  function destroyStreams() {
    if (!extensionPort) return;
    extensionPort.onDisconnect.removeListener(onDisconnectDestroyStreams);
    destroyExtensionStreams();
    extensionPort.disconnect();
    extensionPort = null;
    NODUS_EXTENSION_CONNECT_SENT = false;
  }

  // Port: shared/lib/browser-runtime.utils.ts:35-45.
  function checkForLastError() {
    const { lastError } = runtime;
    if (!lastError) return undefined;
    if ('stack' in lastError && lastError.stack && lastError.message) return lastError;
    return new Error(lastError.message);
  }

  // Port: app/scripts/streams/provider-stream.ts:333-350; the direct listener receives the Port argument.
  function onDisconnectDestroyStreams(error) {
    const lastError = error || checkForLastError();
    destroyStreams();
    if (lastError) {
      console.warn(`${lastError} Resetting the streams.`);
      setTimeout(setupExtensionStreams, 1000);
    }
  }

  // Port: app/scripts/streams/provider-stream.ts:400-421; method-only check, without a channel-name gate.
  function extensionStreamMessageListener(message) {
    if (NODUS_EXTENSION_CONNECT_SENT && message.data.method === PROVIDER_METHODS.chainChanged) {
      NODUS_EXTENSION_CONNECT_SENT = false;
      window.postMessage({
        target: INPAGE,
        data: { name: EIP_1193_PROVIDER, data: { jsonrpc: '2.0', method: PROVIDER_METHODS.connectCanRetry } },
      }, window.location.origin);
    }
  }

  // Port: app/scripts/streams/provider-stream.ts:428-443; every extension pipeline callback notifies.
  function notifyInpageOfStreamFailure() {
    window.postMessage({
      target: INPAGE,
      data: { name: EIP_1193_PROVIDER, data: { jsonrpc: '2.0', method: PROVIDER_METHODS.streamFailure } },
    }, window.location.origin);
  }

  // Port: app/scripts/streams/stream-utils.ts:8-15, Q-9 provider-name substitution.
  function logStreamDisconnectWarning(remoteLabel, error) {
    console.debug(`Nodus: Content script lost connection to "${remoteLabel}".`, error);
  }

  // Port: app/scripts/streams/provider-stream.ts:358-365.
  setupPageStreams();
  setupExtensionStreams();
  runtime.onMessage.addListener(onMessageSetUpExtensionStreams);
  // contentscript.js:34-39's prerender workaround is unreachable: manifest minimum 123 exceeds common.ts:53-66's fixes (120/121).
  // Port: app/scripts/contentscript.js:42-54.
  window.addEventListener('pageshow', event => {
    if (event.persisted) {
      console.warn('BFCached page has become active. Restoring the streams.');
      setupExtensionStreams();
    }
  });
  window.addEventListener('pagehide', event => {
    if (event.persisted) {
      console.warn('Page may become BFCached. Destroying the streams.');
      destroyStreams();
    }
  });
  return {
    setupExtensionStreams, destroyStreams, onDisconnectDestroyStreams, pageStream, pageMux, pageChannel, caipChannel,
    get extensionStream() { return extensionStream; },
    get extensionEip1193Channel() { return extensionEip1193Channel; },
  };
}

// Port: app/scripts/contentscript.js:58; the loaded entry always starts.
export const contentscript = startContentscript();
