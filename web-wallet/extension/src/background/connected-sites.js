import { SITES_KEY, parseSites, serializeSites } from '../../../src/activity-storage.js';

// The websites the user connected, and the account each may see, are the
// PermissionController `subjects`. They are not part of the plain
// `nodus.extension.state`; they live sealed under `nodus.sites.v1`
// (src/activity-storage.js serializeSites), opened at unlock with a key from
// the unlocked wallet and cleared from memory at lock. Operator 2026-11-03
// "Şifrelesin tabii canım." (docs/plans/decisions/2026-11-03-chrome-web-store.md:13,15);
// no migration of an old plain list (same file, line 18).
export function createConnectedSites({ storage, controller, messenger }) {
  // `session` holds the vault id and the sealing key only between load() and clear().
  let session = null, generation = 0, writing = Promise.resolve(), applying = false, error = '';

  // Called after the wallet's keys exist. A record that fails to open keeps the
  // list empty, shows the reason and is left as it is.
  async function load({ id, key }) {
    const started = ++generation;
    session = null; error = '';
    let subjects = {}, readable = true;
    try {
      // A change made just before the previous lock may still be queued; read only after it has landed.
      await writing.catch(() => {});
      const saved = await storage.get(SITES_KEY), text = saved[SITES_KEY];
      if (started !== generation) return;
      // A record that does not open for this wallet (another vault id, damaged) is left as it is (plan section 2.6);
      // a restore removes the replaced wallet's record (index.js createNewVaultAndRestore).
      if (text !== undefined) subjects = await parseSites(text, id, key);
    } catch (failure) {
      readable = false; error = `Saved connected sites could not be read (${failure.message}). Websites you connect now are not saved.`;
    }
    if (started !== generation) return;
    if (Object.keys(subjects).length) {
      applying = true;
      try { controller.update(() => ({ subjects })); } finally { applying = false; }
    }
    session = { id, key, readable };
  }

  // Lock, delete and replacement: the list leaves memory without being saved.
  function clear() {
    generation++;
    session = null; error = '';
    if (controller.getSubjectNames().length) {
      applying = true;
      try { controller.clearState(); } finally { applying = false; }
    }
  }

  function onChanged() {
    if (applying || !session?.readable) return;
    // The snapshot and the key are captured now: a change made before a lock is still written after it
    // (the wallet's delete path flushes this queue first, so no write can follow the record's removal).
    const { id, key } = session, subjects = structuredClone(controller.state.subjects);
    const job = writing.catch(() => {}).then(async () => {
      await storage.set({ [SITES_KEY]: await serializeSites(id, subjects, key) });
    });
    // The caller of a change cannot await a write; flush() retains the failure.
    writing = job; job.catch(() => {});
  }
  messenger.subscribe('PermissionController:stateChange', onChanged);

  return { load, clear, flush: () => writing, getError: () => error,
    destroy() { generation++; session = null; messenger.unsubscribe('PermissionController:stateChange', onChanged); } };
}
