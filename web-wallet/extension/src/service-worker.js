const { chrome } = globalThis;

// Port: MetaMask v13.54.0 app/service-worker.ts:9-20. The timestamp is session-only.
const SAVE_TIMESTAMP_INTERVAL_MS = 2 * 1000;
function saveTimestamp() {
  const timestamp = new Date().toISOString();
  chrome.storage.session.set({ timestamp });
}
saveTimestamp();
setInterval(saveTimestamp, SAVE_TIMESTAMP_INTERVAL_MS);

// Port: app/scripts/lib/extension-lazy-listener/extension-lazy-listener.ts:23-225; TypeScript types removed.
class ExtensionLazyListener {
  #browser;
  #namespaceListeners = new Map();

  constructor(browser, events = {}, timeout = 20000) {
    this.#browser = browser;
    for (const [namespace, eventNames] of Object.entries(events)) {
      const listeners = new Map();
      for (const eventName of eventNames) {
        const calls = [];
        const listener = (...args) => { calls.push(args); };
        this.#getEvent(namespace, eventName).addListener(listener);
        listeners.set(eventName, { listener, args: calls });
      }
      this.#namespaceListeners.set(namespace, listeners);
    }
    this.#startWarningTimer(timeout);
  }

  #startWarningTimer(timeout) {
    setTimeout(() => {
      for (const [namespace, listeners] of this.#namespaceListeners) {
        for (const [eventName, { args: calls }] of listeners) {
          const message = `ExtensionLazyListener: Possible memory leak detected. The event "${namespace}.${eventName}" has been listened to, but no application code has added a listener after ${timeout}ms. There are currently ${calls.length} buffered calls. If you are a developer of this extension, please ensure that you have added a listener for this event. If you are a user of this extension, please report this warning to the developers of the extension.`;
          if (process.env.IN_TEST) console.error(message);
          else console.warn(message);
        }
      }
    }, timeout);
  }

  #getEvent(namespace, eventName) {
    return this.#browser[namespace][eventName];
  }

  addListener(namespace, eventName, callback) {
    const event = this.#getEvent(namespace, eventName);
    event.addListener(callback);
    const listeners = this.#namespaceListeners.get(namespace);
    if (listeners) {
      const tracker = listeners.get(eventName);
      if (tracker) {
        event.removeListener(tracker.listener);
        listeners.delete(eventName);
        if (listeners.size === 0) this.#namespaceListeners.delete(namespace);
        const { args } = tracker;
        for (let i = 0, { length } = args; i < length; i++) {
          try {
            callback(...args[i]);
            if (!event.hasListener(callback)) {
              const next = i + 1;
              if (next !== length) {
                args.splice(0, next);
                listeners.set(eventName, tracker);
                this.#namespaceListeners.set(namespace, listeners);
                event.addListener(tracker.listener);
              }
              break;
            }
          } catch (error) {
            const next = i + 1;
            if (next !== length) {
              args.splice(0, next);
              listeners.set(eventName, tracker);
              this.#namespaceListeners.set(namespace, listeners);
              event.addListener(tracker.listener);
            }
            throw error;
          }
        }
      }
    }
  }

  once(namespace, eventName) {
    return new Promise(resolve => {
      const event = this.#getEvent(namespace, eventName);
      const listeners = this.#namespaceListeners.get(namespace);
      if (listeners) {
        const tracker = listeners.get(eventName);
        const length = tracker?.args.length;
        if (length) {
          resolve(tracker.args.shift());
          event.removeListener(tracker.listener);
          if (length === 1) {
            listeners.delete(eventName);
            if (listeners.size === 0) this.#namespaceListeners.delete(namespace);
          }
          return;
        }
      }
      const tempListener = (...args) => {
        event.removeListener(tempListener);
        resolve(args);
      };
      event.addListener(tempListener);
    });
  }
}

// Plan §8:907/§9:930-932 removes telemetry/webpack bootstrap; port its stateHooks initialization (app/scripts/load/bootstrap.ts:4) here.
globalThis.stateHooks ??= {};
// Port: app/service-worker.ts:24-30; package 4 attaches the background event consumers.
const lazyListener = new ExtensionLazyListener(chrome, { runtime: ['onInstalled', 'onConnect'] });
globalThis.stateHooks.lazyListener = lazyListener;
let runImportScriptsInitiated = false;

// Port: app/service-worker.ts:34-56; plan §16:1101-1103 limits this entry to packages 1-2 until the background engine package.
async function runImportScripts() {
  if (runImportScriptsInitiated) return;
  runImportScriptsInitiated = true;
  const startImportScriptsTime = performance.now();
  const { background } = await import('./background/index.js');
  await background;
  const endImportScriptsTime = performance.now();
  console.log(`importScripts completed in ${(endImportScriptsTime - startImportScriptsTime) / 1000} seconds`);
}
self.addEventListener('install', runImportScripts);

// Port: app/service-worker.ts:58-81 and shared/constants/ui-initialization.ts:6.
const APP_INIT_LIVENESS_METHOD = 'APP_INIT_ALIVE';
chrome.runtime.onConnect.addListener(port => {
  console.log('Nodus service worker: Received connection from port', port.name);
  try {
    port.postMessage({ data: { method: APP_INIT_LIVENESS_METHOD }, name: 'app-init-liveness' });
  } catch (error) {
    console.error('Nodus - app-init-liveness check: Failed to message to port', error);
  }
});

// Port: app/service-worker.ts:83-95; a restarted worker does not get another install event.
if (self.serviceWorker.state === 'activated') runImportScripts();
