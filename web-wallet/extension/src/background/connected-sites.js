import { SITES_KEY, parseSites, serializeSites } from '../../../src/activity-storage.js';

// Revocations a website sent while the wallet was locked (see rememberRevocation). They are kept in
// chrome.storage.session, which lasts across service worker restarts and is not written to disk.
export const REVOKED_KEY = 'nodus.sites.revoked.v1';

// The websites the user connected, and the account each may see, are the
// PermissionController `subjects`. They are not part of the plain
// `nodus.extension.state`; they live sealed under `nodus.sites.v1`
// (src/activity-storage.js serializeSites), opened at unlock with a key from
// the unlocked wallet and cleared from memory at lock. Operator 2026-11-03
// "Şifrelesin tabii canım." (docs/plans/decisions/2026-11-03-chrome-web-store.md:13,15);
// no migration of an old plain list (same file, line 18).
export function createConnectedSites({ storage, sessionStorage, controller, messenger }) {
  // `session` holds the vault id and the sealing key only between load() and clear().
  let session = null, generation = 0, writing = Promise.resolve(), applying = false, error = '';
  // origin -> permission names a website revoked while locked; read back once after a worker restart.
  let revoked = {}, remembering = Promise.resolve();
  const ready = sessionStorage ? sessionStorage.get(REVOKED_KEY).then(saved => {
    for (const [origin, names] of Object.entries(saved?.[REVOKED_KEY] ?? {})) revoked[origin] = [...new Set([...(revoked[origin] ?? []), ...names])];
  }).catch(() => {}) : Promise.resolve();
  function persistRevoked() {
    if (!sessionStorage) return;
    const snapshot = structuredClone(revoked);
    remembering = Promise.all([ready, remembering]).then(() => Object.keys(snapshot).length
      ? sessionStorage.set({ [REVOKED_KEY]: snapshot }) : sessionStorage.remove(REVOKED_KEY)).catch(() => {});
  }

  // Called after the wallet's keys exist. A record that fails to open keeps the
  // list empty, shows the reason and is left as it is.
  async function load({ id, key }) {
    const started = ++generation;
    session = null; error = '';
    let subjects = {}, readable = true;
    try {
      // A change made just before the previous lock may still be queued; read only after it has landed.
      await writing.catch(() => {});
      await ready;
      const saved = await storage.get(SITES_KEY), text = saved[SITES_KEY];
      if (started !== generation) return;
      // A record that does not open for this wallet (another vault id, damaged) is left as it is (plan section 2.6);
      // a restore removes the replaced wallet's record (index.js createNewVaultAndRestore).
      if (text !== undefined) subjects = await parseSites(text, id, key);
    } catch (failure) {
      readable = false; error = `Saved connected sites could not be read (${failure.message}). Websites you connect now are not saved.`;
    }
    if (started !== generation) return;
    // From here to `session` nothing awaits, so a revocation sent while locked is either applied now or,
    // arriving later, finds the list open and is handled by the controller directly.
    const changed = applyRevoked(subjects);
    if (Object.keys(subjects).length) {
      applying = true;
      try { controller.update(() => ({ subjects })); } finally { applying = false; }
    }
    session = { id, key, readable };
    if (changed && readable) save();
  }

  // Operator 2026-11-04 on wallet_revokePermissions sent while locked: "Hatırlansın, kilit açılınca uygulansın"
  // (docs/plans/decisions/2026-11-03-chrome-web-store.md). Same result as PermissionController.revokePermissions
  // (@metamask/permission-controller 13.1.1 dist/PermissionController.cjs:262-276, 804-811): an origin with a missing
  // subject or a missing permission is left unchanged; removing the last permission removes the subject.
  function applyRevoked(subjects) {
    const pending = revoked;
    if (!Object.keys(pending).length) return false;
    revoked = {}; persistRevoked();
    let changed = false;
    for (const [origin, names] of Object.entries(pending)) {
      const permissions = subjects[origin]?.permissions;
      if (!permissions || !names.every(name => Object.hasOwn(permissions, name))) continue;
      for (const name of names) {
        if (Object.keys(subjects[origin].permissions).length > 1) delete subjects[origin].permissions[name];
        else delete subjects[origin];
      }
      changed = true;
    }
    return changed;
  }

  // While locked the list is sealed and not in memory, so the controller has nothing to revoke;
  // the request is remembered and applied by the next load().
  function rememberRevocation(origin, names) {
    if (session) return;
    revoked[origin] = [...new Set([...(revoked[origin] ?? []), ...names])];
    persistRevoked();
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

  function save() {
    // The snapshot and the key are captured now: a change made before a lock is still written after it
    // (the wallet's delete path flushes this queue first, so no write can follow the record's removal).
    const { id, key } = session, subjects = structuredClone(controller.state.subjects);
    const job = writing.catch(() => {}).then(async () => {
      await storage.set({ [SITES_KEY]: await serializeSites(id, subjects, key) });
    });
    // The caller of a change cannot await a write; flush() retains the failure.
    writing = job; job.catch(() => {});
  }
  function onChanged() {
    if (applying || !session?.readable) return;
    save();
  }
  messenger.subscribe('PermissionController:stateChange', onChanged);

  return { load, clear, rememberRevocation, flush: () => writing, flushRevoked: () => remembering, getError: () => error,
    destroy() { generation++; session = null; messenger.unsubscribe('PermissionController:stateChange', onChanged); } };
}
