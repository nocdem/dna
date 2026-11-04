import { SITES_KEY, parseSites, serializeSites } from '../../../src/activity-storage.js';

// Revocations a website sent while the wallet was locked (see rememberRevocation). They are kept in
// chrome.storage.session, which lasts across service worker restarts and is not written to disk.
export const REVOKED_KEY = 'nodus.sites.revoked.v1';

// An identical request already queued for the origin is not added again: a second one changes nothing when applied.
function addRequest(target, origin, names) {
  const requests = target[origin] ??= [], same = JSON.stringify([...names].sort());
  if (!requests.some(request => JSON.stringify([...request].sort()) === same)) requests.push([...names]);
}
function mergeRevoked(first, second) {
  const result = {};
  for (const source of [first, second]) for (const [origin, requests] of Object.entries(source)) for (const names of requests) addRequest(result, origin, names);
  return result;
}

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
  // origin -> the separate revocation requests (each a list of permission names) a website sent while locked,
  // in arrival order; read back once after a worker restart.
  let revoked = {}, remembering = Promise.resolve();
  const ready = sessionStorage ? sessionStorage.get(REVOKED_KEY).then(saved => {
    revoked = mergeRevoked(saved?.[REVOKED_KEY] ?? {}, revoked);
  }).catch(() => {}) : Promise.resolve();
  // The stored copy is written from the queue as it is when the write runs, after the read-back above.
  function persistRevoked() {
    if (!sessionStorage) return remembering;
    remembering = Promise.all([ready, remembering]).then(() => Object.keys(revoked).length
      ? sessionStorage.set({ [REVOKED_KEY]: structuredClone(revoked) }) : sessionStorage.remove(REVOKED_KEY)).catch(() => {});
    return remembering;
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
    // arriving later, finds the list open and is handled by the controller directly. A record that did not
    // open keeps the queue for an unlock that reads it.
    const pending = readable ? revoked : {}, changed = applyRevoked(subjects, pending);
    if (readable) revoked = {};
    if (Object.keys(subjects).length) {
      applying = true;
      try { controller.update(() => ({ subjects })); } finally { applying = false; }
    }
    session = { id, key, readable };
    if (!Object.keys(pending).length) return;
    // The stored queue is dropped only after the sealed record without the sites has been written;
    // a failed write puts the requests back for the next unlock.
    (changed ? save() : Promise.resolve()).then(() => persistRevoked(),
      () => { revoked = mergeRevoked(pending, revoked); return persistRevoked(); });
  }

  // Operator 2026-11-04 on wallet_revokePermissions sent while locked: "Hatırlansın, kilit açılınca uygulansın"
  // (docs/plans/decisions/2026-11-03-chrome-web-store.md). Each request has the result
  // PermissionController.revokePermissions gives it when unlocked (@metamask/permission-controller 13.1.1
  // dist/PermissionController.cjs:262-276, 804-811), in arrival order: a request naming a missing subject or a
  // missing permission changes nothing; removing the last permission removes the subject.
  function applyRevoked(subjects, pending) {
    let changed = false;
    for (const [origin, requests] of Object.entries(pending)) {
      for (const names of requests) {
        const permissions = subjects[origin]?.permissions;
        if (!permissions || !names.every(name => Object.hasOwn(permissions, name))) continue;
        for (const name of names) {
          if (Object.keys(subjects[origin].permissions).length > 1) delete subjects[origin].permissions[name];
          else delete subjects[origin];
        }
        changed = true;
      }
    }
    return changed;
  }

  // While locked the list is sealed and not in memory, so the controller has nothing to revoke;
  // the request is remembered and applied by the next load(). Resolves when the stored copy is written.
  function rememberRevocation(origin, names) {
    if (session) return Promise.resolve();
    addRequest(revoked, origin, names);
    return persistRevoked();
  }

  // A restore or delete replaces the wallet whose grants the remembered requests were for.
  function forgetRevocations() {
    revoked = {};
    return persistRevoked();
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
    return job;
  }
  function onChanged() {
    if (applying || !session?.readable) return;
    save();
  }
  messenger.subscribe('PermissionController:stateChange', onChanged);

  return { load, clear, rememberRevocation, forgetRevocations, flush: () => writing, flushRevoked: () => remembering, getError: () => error,
    destroy() { generation++; session = null; messenger.unsubscribe('PermissionController:stateChange', onChanged); } };
}
