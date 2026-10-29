import { deriveStateFromMetadata } from '@metamask/base-controller';

// Build constant for this package's controller state; the web-wallet VAULT_KEY stays owned by vault-store.
export const STATE_KEY = 'nodus.extension.state';

// Port: MetaMask v13.54.0 app/scripts/lib/ComposableObservableStore.js:4-5, 70-95, 139-150.
export async function createPersistedStore({ storage, messenger }) {
  const saved = (await storage.get(STATE_KEY))[STATE_KEY] ?? {};
  const controllers = new Map(), subscriptions = [];
  let state = {}, pending = Promise.resolve();

  function persistenceMetadata(name, metadata) {
    // SINGLE-VAULT METADATA FIREWALL: ADAPTATION, approved plan §3.5:388-406 (Q-27/F4).
    // Override even stock persist:true for initial hydration, updates and backup projection.
    // Package 2's private keyring is never registered here; this also protects future composition.
    return name === 'KeyringController' ? { ...metadata, vault: { ...metadata.vault, persist: false } } : metadata;
  }

  function project(name, value, metadata) {
    return deriveStateFromMetadata(value, persistenceMetadata(name, metadata), 'persist');
  }

  function getInitialState(name, metadata) {
    return structuredClone(project(name, saved[name] ?? {}, metadata));
  }

  function persist() {
    const snapshot = backup();
    pending = pending.catch(() => {}).then(() => storage.set({ [STATE_KEY]: snapshot }));
    // Events cannot await writes; flush retains the rejection for the caller.
    pending.catch(() => {});
  }

  function registerControllers(config) {
    if (controllers.size) throw new Error('Persistent controllers are already registered.');
    for (const [key, controller] of Object.entries(config)) {
      if (!controller?.metadata) throw new Error('Persistent controllers require state metadata.');
      const { name, metadata } = controller;
      const filteredMetadata = persistenceMetadata(name, metadata);
      controllers.set(key, { name, metadata });
      state[key] = project(name, controller.state, metadata);
      const onStateChange = (next, patches) => {
        if (!patches.some(({ path }) => path.length === 0 || !filteredMetadata[path[0]] || filteredMetadata[path[0]].persist)) return;
        state = { ...state, [key]: project(name, next, metadata) };
        persist();
      };
      messenger.subscribe(`${name}:stateChange`, onStateChange);
      subscriptions.push(() => messenger.unsubscribe(`${name}:stateChange`, onStateChange));
    }
    persist();
  }

  function backup() {
    // Projection is already applied, including persist transform functions; do not apply them twice.
    return structuredClone(state);
  }

  return { getInitialState, registerControllers, backup, flush: () => pending,
    destroy() { for (const unsubscribe of subscriptions.splice(0)) unsubscribe(); } };
}
