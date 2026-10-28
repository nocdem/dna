import ObjectMultiplex from '@metamask/object-multiplex';
import { ExtensionPortStream } from 'extension-port-stream';
import { pipeline } from 'readable-stream';

// Port: v13.54.0 app/scripts/metamask-controller.js:4601-4613 (trusted multiplexed controller channel).
// Page names: app/scripts/background.ts:857-865, 907-916; approved plan §3.2.
export function connectTrusted({ runtime = chrome.runtime, page = globalThis.location.pathname.split('/').pop() } = {}) {
  const name = { 'popup.html': 'popup', 'notification.html': 'notification', 'home.html': 'fullscreen' }[page];
  if (!name) throw new Error('Unknown wallet page.');
  const port = runtime.connect({ name }), stream = new ExtensionPortStream(port), mux = new ObjectMultiplex();
  mux.ignoreStream('provider'); mux.ignoreStream('app-init-liveness');
  const controller = mux.createStream('controller'), pending = new Map(), disconnectListeners = new Set(), notificationListeners = new Set();
  let id = 0, closed = false;
  function disconnected() {
    if (closed) return;
    closed = true;
    // Port: lib/metaRPCClientFactory.ts:223-236: stop consuming responses and reject unfinished requests.
    controller.removeListener('data', onData);
    controller.removeListener('end', disconnected);
    for (const { reject } of pending.values()) reject(new Error('Wallet background disconnected. Reopen this wallet page.'));
    pending.clear();
    for (const listener of disconnectListeners) listener();
    disconnectListeners.clear();
    notificationListeners.clear();
  }
  pipeline(stream, mux, stream, disconnected);
  function onData(response) {
    // Port: lib/MessengerSubscriptions.ts:48-52 (trusted JSON-RPC event notifications).
    if (response?.id === undefined && typeof response?.method === 'string') {
      for (const listener of notificationListeners) listener(response);
      return;
    }
    const waiting = pending.get(response?.id);
    if (!waiting) return;
    pending.delete(response.id);
    if (response.error) waiting.reject(Object.assign(new Error(response.error.message), { code: response.error.code, data: response.error.data }));
    else waiting.resolve(response.result);
  }
  // Port: lib/metaRPCClientFactory.ts:129-132 (controller EOF closes the client).
  controller.on('data', onData); controller.on('end', disconnected);
  return {
    request(method, params = []) {
      if (closed) return Promise.reject(new Error('Wallet background disconnected. Reopen this wallet page.'));
      return new Promise((resolve, reject) => {
        const requestId = ++id; pending.set(requestId, { resolve, reject });
        try { controller.write({ jsonrpc: '2.0', id: requestId, method, params }); }
        catch (error) { pending.delete(requestId); reject(error); }
      });
    },
    onDisconnect(listener) { disconnectListeners.add(listener); return () => disconnectListeners.delete(listener); },
    onNotification(listener) { notificationListeners.add(listener); return () => notificationListeners.delete(listener); },
    // Port: lib/metaRPCClientFactory.ts:223-236: close cleans up the client; the port owns transport teardown.
    // extension-port-stream 5.0.3 dist/index.js:75-108 ends both sides on disconnect before destroying the stream.
    close() { disconnected(); },
  };
}
