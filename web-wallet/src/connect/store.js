// Nodus Connect — the Messages history kept in this browser (package NC-4c).
//
// Governing records:
//   docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md
//     S8: the IndexedDB database is named by the wallet vault's random 16-byte
//         id (src/vault.js encryptVault); an unsaved wallet has no id and
//         therefore NO persistent history (memoryHistoryStore below).
//     Ek 2 "Geçmiş kayıt düzeni": every record keeps its fields separate —
//         id, nonce (12 B), ciphertext, tag (16 B); ONE counter record per
//         vault (the SP 800-38D §8.3 2^32 budget, nc_history_encrypt counter).
//   docs/plans/decisions/2026-09-30-connect-history-at-rest.md rev 2: the key
//     and the AES-256-GCM sealing live in the core (C, nc_history.c); this file
//     never sees the key and never stores a plaintext.
//   docs/plans/2026-09-24-web-connect-design.md rev 5 §1.7: all bytes are
//     ready before a transaction opens; the transaction body only calls
//     put/delete; completion is oncomplete, and onerror/onabort are surfaced;
//     a failed load keeps Messages closed and writes nothing; deleting the
//     history from this device takes the storage Web Lock.
//
// Naming: database = the vault id as 32 lowercase hex characters (the same 16
// bytes as the vault's base64 `id`). Object stores: 'messages' (one record per
// message, id 'm' + 20-digit local sequence), 'state' (the record id 'state':
// contacts, salts, pending requests, the contacts removed on this device,
// ACK times, the next local sequence,
// the profile cache index and the message-check times; plus one record per
// kept contact profile, id 'p' + 20-digit local sequence, and one per shared
// vault, id 'v' + 20-digit local sequence — src/vaults/), 'meta' (the
// counter record). Record ids are opaque on purpose: who you talk
// to is inside the ciphertext, not in an id or the AAD. The counter is also
// kept in localStorage ('nodus.connect.counter.v1.<database name>', a
// decimal string) so deleting the history does not restart it (NC-RT2 D).
//
// Core calls used (src/connect/core.js, NC-4b):
//   core.historyKey(vaultIdHex)             32 lowercase hex
//   core.historyEncrypt({ store, id, plaintext, counter }) -> { nonce, ct, tag, counter }
//     store = the object-store name (nc_history.h: the AAD's "store");
//     plaintext: Uint8Array (UTF-8 JSON here), 1..65536 bytes
//     (nc_wasm.c NC_HIST_PT_MAX); counter: decimal string in, the new value
//     out (checked here to be exactly in + 1); nonce / ct / tag: Uint8Array
//   core.historyDecrypt({ store, id, nonce, ct, tag }) -> { plaintext: Uint8Array }

// Every failure of this file is a StorageError whose message is plain words
// meant for the user (§1.7: onerror/onabort are shown, not hidden behind a
// network message). A failed core seal/open is reported the same way; the
// core's own error text is not shown.
import { chainNameOk } from '../nodus/names.js';

export class StorageError extends Error {}
const sealing = async (run, what) => {
  try { return await run(); }
  catch (error) { throw error instanceof StorageError ? error : new StorageError(what); }
};

export const STORE_MESSAGES = 'messages', STORE_STATE = 'state', STORE_META = 'meta';
export const STATE_ID = 'state', COUNTER_ID = 'counter';
export const NONCE_LEN = 12, TAG_LEN = 16;
// SP 800-38D §8.3: at most 2^32 random-nonce invocations per key.
export const MAX_INVOCATIONS = 2n ** 32n;
// The core seals at most this many plaintext bytes per record (nc_wasm.c NC_HIST_PT_MAX).
export const PLAINTEXT_MAX = 65536;
const U64 = /^(0|[1-9]\d{0,19})$/;

function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

// The vault's base64 id (16 bytes) -> the database name.
export function databaseNameForVault(vaultId) {
  if (typeof vaultId !== 'string' || !/^[A-Za-z0-9+/]{22}==$/.test(vaultId)) throw new StorageError('Invalid saved wallet id.');
  const bytes = Uint8Array.from(atob(vaultId), c => c.charCodeAt(0));
  if (bytes.length !== 16) throw new StorageError('Invalid saved wallet id.');
  return bytesToHex(bytes);
}

export function messageRecordId(seq) {
  if (typeof seq !== 'string' || !U64.test(seq)) throw new StorageError('Invalid message number.');
  return 'm' + seq.padStart(20, '0');
}

// A value -> the plaintext bytes handed to the core (UTF-8 JSON), and back.
export function plaintextBytes(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  if (bytes.length === 0 || bytes.length > PLAINTEXT_MAX) throw new StorageError('This is too large to save on this device.');
  return bytes;
}
export function parsePlaintext(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new StorageError('A stored message could not be read.');
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new StorageError('A stored message could not be read.'); }
  finally { bytes.fill(0); }
}

const bytesOf = (value, length) => value instanceof Uint8Array && (length === undefined ? value.length > 0 : value.length === length);

// Core result -> the stored record: four separate fields (Ek 2), each its own copy.
export function encodeRecord(id, sealed) {
  if (typeof id !== 'string' || id.length === 0 || !sealed ||
      !bytesOf(sealed.nonce, NONCE_LEN) || !bytesOf(sealed.tag, TAG_LEN) || !bytesOf(sealed.ct)) throw new StorageError('Invalid message record.');
  return { id, nonce: sealed.nonce.slice(), ct: sealed.ct.slice(), tag: sealed.tag.slice() };
}
// Stored record -> the core's decrypt arguments; refuses anything malformed.
export function decodeRecord(record) {
  if (!record || typeof record.id !== 'string' || record.id.length === 0 ||
      !bytesOf(record.nonce, NONCE_LEN) || !bytesOf(record.tag, TAG_LEN) || !bytesOf(record.ct) ||
      Object.keys(record).sort().join() !== 'ct,id,nonce,tag') throw new StorageError('A stored message record is damaged.');
  return { id: record.id, nonce: record.nonce, ct: record.ct, tag: record.tag };
}

// The one counter record per vault: a decimal string.
export function encodeCounter(count) {
  if (typeof count !== 'bigint' || count < 0n || count > MAX_INVOCATIONS) throw new StorageError('Invalid counter.');
  return { id: COUNTER_ID, value: count.toString() };
}
export function decodeCounter(record) {
  if (record === undefined) return 0n;
  if (!record || record.id !== COUNTER_ID || typeof record.value !== 'string' || !U64.test(record.value) ||
      Object.keys(record).sort().join() !== 'id,value') throw new StorageError('The stored message counter is damaged.');
  const count = BigInt(record.value);
  if (count > MAX_INVOCATIONS) throw new StorageError('The stored message counter is damaged.');
  return count;
}

// The next counter the core returned must be exactly one more.
export function nextCounter(current, returned) {
  if (typeof returned !== 'string' || !U64.test(returned) || BigInt(returned) !== current + 1n) throw new StorageError('Message history could not be saved (counter mismatch).');
  return current + 1n;
}

// Whether `count` more encryptions fit the budget.
export function budgetAllows(current, count) { return current + BigInt(count) <= MAX_INVOCATIONS; }

// A copy of the counter OUTSIDE the database (NC-RT2 D). Deleting the
// message history deletes the database with its counter record, but the key
// K is unchanged (same ML-DSA secret, same vault id: decision rev 2 item 2),
// so the 2^32 budget of K must not restart. The copy lives in localStorage
// under the database name, survives erase(), is the larger of the two on
// open, is written before every database write, and is deleted only with
// the saved wallet itself (deleteVaultHistory, called by src/app.js).
const COUNTER_STORAGE_PREFIX = 'nodus.connect.counter.v1.';
export function counterStorageKey(name) { return COUNTER_STORAGE_PREFIX + name; }
export function readStoredCounter(storage, name) {
  if (!storage || typeof storage.getItem !== 'function') throw new StorageError('This browser cannot keep the message counter.');
  const value = storage.getItem(counterStorageKey(name));
  if (value === null) return 0n;
  if (typeof value !== 'string' || !U64.test(value) || BigInt(value) > MAX_INVOCATIONS) throw new StorageError('The stored message counter is damaged.');
  return BigInt(value);
}
export function writeStoredCounter(storage, name, count) {
  if (typeof count !== 'bigint' || count < 0n || count > MAX_INVOCATIONS) throw new StorageError('Invalid counter.');
  try { storage.setItem(counterStorageKey(name), count.toString()); }
  catch { throw new StorageError('Message history could not be saved (the message counter could not be stored).'); }
}
export function openingCounter(fromDatabase, fromStorage) { return fromDatabase > fromStorage ? fromDatabase : fromStorage; }

// Raised by deleteVaultHistory when another connection keeps the database
// open: the browser deletes it once that connection closes (the delete
// request stays queued), but it is NOT deleted yet.
export class HistoryDeleteBlocked extends StorageError {}

// Deletes the database (no Web Lock taken here: the caller holds the
// storage lock — store.erase below, or src/app.js deleting the saved wallet;
// a second request of the same lock inside it would wait forever).
function deleteDatabase(name) {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') { resolve(); return; }
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(new StorageError('Message history could not be deleted.'));
    request.onblocked = () => reject(new HistoryDeleteBlocked('Message history is open in another tab; it is deleted when that tab closes it.'));
  });
}

// The saved wallet `vaultId` (its base64 id, src/vault.js) is being deleted:
// its Messages database and its counter copy go with it. Call inside the
// storage Web Lock. Rejects with StorageError / HistoryDeleteBlocked.
export async function deleteVaultHistory(vaultId, storage) {
  const name = databaseNameForVault(vaultId);
  try { storage?.removeItem(counterStorageKey(name)); }
  catch { throw new StorageError('The message counter could not be deleted.'); }
  await deleteDatabase(name);
}

// The local state kept in the 'state' record, with defaults. `acks`: the
// last ACK value read per contact; `ackSent`: the last ACK value this device
// published per contact (no re-ACK unless something newer was stored).
// `profileCache`: fp -> { id, at, name } — a contact's profile row kept in
// the 'state' store under record id `id` ('p' + 20 digits), read at `at`
// (unix seconds) with the verified name `name` (the app's profile cache,
// profile_cache.h:40). `dmSync`: fp -> unix seconds of the last completed
// check of that contact's messages (the app's contacts_db dm sync
// timestamp, transport_offline.c smart sync). `chainNames`: fp -> { name,
// at } — the chain name (HF-4, dnac_name_of) the node reported for that ID
// at `at` (unix seconds), kept like a profile (text.js profileFresh, 7
// days); only a found name is kept (a name is permanent — decision
// 2026-10-02-onchain-names.md item 4 — while "no name" can change any
// block). `removed`: IDs the user removed from the contacts on THIS device
// (text.js removeContact); the own list on the network is merge-only
// (nc_core.h nc_contactlist_add), so it still lists them and they must not
// be added back from it (text.js mergeListedContacts). Adding the person
// again (request accepted, theirs or ours) takes the ID off this list.
export function emptyState() {
  return { version: 1, nextSeq: '1', contacts: [], outgoing: [], declined: [], removed: [], acks: {}, ackSent: {}, profileCache: {}, dmSync: {}, chainNames: {}, vaults: {} };
}
const isMap = value => value && typeof value === 'object' && !Array.isArray(value);
const HEX128_KEY = /^[0-9a-f]{128}$/;
export const PROFILE_RECORD_ID = /^p\d{20}$/;
// Shared vaults (src/vaults/): state.vaults maps a vault address to the id
// of its own record in the 'state' store ({ id: 'v' + 20 digits, at }),
// like state.profileCache; the record holds what src/vaults/core.js
// checkVaultRecord accepts. Record ids stay opaque (the address is inside
// the ciphertext and the state, never in an id or the AAD).
export const VAULT_RECORD_ID = /^v\d{20}$/;
export function checkState(value) {
  // A state saved before `ackSent`, `profileCache`, `dmSync`, `chainNames`
  // or `vaults` existed gets the default (same version).
  if (value && value.version === 1) for (const key of ['ackSent', 'profileCache', 'dmSync', 'chainNames', 'vaults']) if (value[key] === undefined) value[key] = {};
  // … and before `removed` existed, likewise (an empty list).
  if (value && value.version === 1 && value.removed === undefined) value.removed = [];
  if (!value || value.version !== 1 || !U64.test(String(value.nextSeq)) || !Array.isArray(value.contacts) ||
      !Array.isArray(value.outgoing) || !Array.isArray(value.declined) ||
      !Array.isArray(value.removed) || value.removed.some(fp => typeof fp !== 'string' || !HEX128_KEY.test(fp)) ||
      !value.acks || typeof value.acks !== 'object' ||
      !isMap(value.ackSent) || !isMap(value.profileCache) || !isMap(value.dmSync) || !isMap(value.chainNames) || !isMap(value.vaults) ||
      Object.values(value.profileCache).some(e => !isMap(e) || typeof e.id !== 'string' || !PROFILE_RECORD_ID.test(e.id) ||
        !U64.test(String(e.at)) || typeof e.name !== 'string') ||
      Object.values(value.dmSync).some(t => !U64.test(String(t))) ||
      Object.entries(value.chainNames).some(([fp, e]) => !HEX128_KEY.test(fp) || !isMap(e) || !chainNameOk(e.name) || !U64.test(String(e.at))) ||
      Object.entries(value.vaults).some(([addr, e]) => !HEX128_KEY.test(addr) || !isMap(e) || typeof e.id !== 'string' || !VAULT_RECORD_ID.test(e.id) || !U64.test(String(e.at)))) throw new StorageError('The stored contact list is damaged.');
  return value;
}

// A kept vault record: { address, value } — `value` is checked by the
// vault module itself when it is used (src/vaults/core.js).
function checkVaultRecord(value) {
  if (!isMap(value) || typeof value.address !== 'string' || !HEX128_KEY.test(value.address) || !isMap(value.value)) throw new StorageError('A stored vault is damaged.');
  return value;
}

// A kept profile record: { fp, record } (the signed row as read, checked
// again by the core when loaded: core.profileLoad).
function checkProfileRecord(value) {
  if (!isMap(value) || typeof value.fp !== 'string' || !/^[0-9a-f]{128}$/.test(value.fp) ||
      typeof value.record !== 'string' || value.record.length === 0) throw new StorageError('A stored profile is damaged.');
  return value;
}

const txError = (tx, what) => new StorageError(`${what}: ${tx.error?.message || tx.error?.name || 'the browser refused the change'}.`);

// Opens (creating on first use) the database.
function openDatabase(name) {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') { reject(new StorageError('This browser cannot keep message history.')); return; }
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      for (const store of [STORE_MESSAGES, STORE_STATE, STORE_META]) if (!db.objectStoreNames.contains(store)) db.createObjectStore(store, { keyPath: 'id' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new StorageError(`Message history could not be opened: ${request.error?.message || 'unknown error'}.`));
    request.onblocked = () => reject(new StorageError('Message history is in use by another tab. Close it and try again.'));
  });
}

export const HISTORY_SLOW_TEXT = 'Your message history could not be opened on this device right now.';
// `promise` until `signal` aborts, then a StorageError (HISTORY_SLOW_TEXT);
// a value that settles after that is handed to `late` (to close it) and
// dropped. No signal: `promise` itself.
function bounded(promise, signal, late) {
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    let done = false;
    const stop = () => { if (done) return; done = true; reject(new StorageError(HISTORY_SLOW_TEXT)); };
    if (signal.aborted) stop(); else signal.addEventListener('abort', stop, { once: true });
    promise.then(value => {
      if (done) { try { late?.(value); } catch { /* dropped either way */ } return; }
      done = true; signal.removeEventListener('abort', stop); resolve(value);
    }, error => {
      if (done) return;
      done = true; signal.removeEventListener('abort', stop); reject(error);
    });
  });
}

// One read-only pass over the three stores; decryption happens after it.
// (These IndexedDB paths have no automated test: test/connect-ui.test.js.)
function readAll(db) {
  return new Promise((resolve, reject) => {
    let tx;
    try { tx = db.transaction([STORE_MESSAGES, STORE_STATE, STORE_META], 'readonly'); }
    catch (error) { reject(new StorageError(`Message history could not be read: ${error.message}.`)); return; }
    const out = {};
    tx.objectStore(STORE_MESSAGES).getAll().onsuccess = event => { out.messages = event.target.result; };
    // The 'state' record and the kept profile records ('p…', profileCache).
    tx.objectStore(STORE_STATE).getAll().onsuccess = event => { out.stateRecords = event.target.result; };
    tx.objectStore(STORE_META).get(COUNTER_ID).onsuccess = event => { out.counter = event.target.result; };
    tx.oncomplete = () => resolve(out);
    tx.onerror = () => reject(txError(tx, 'Message history could not be read'));
    tx.onabort = () => reject(txError(tx, 'Message history could not be read'));
  });
}

// `puts`: [{ store, record }] — every byte already prepared; the body only puts.
function writeAll(db, puts) {
  return new Promise((resolve, reject) => {
    let tx;
    try { tx = db.transaction([STORE_MESSAGES, STORE_STATE, STORE_META], 'readwrite'); }
    catch (error) { reject(new StorageError(`Message history could not be saved: ${error.message}.`)); return; }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(txError(tx, 'Message history could not be saved'));
    tx.onabort = () => reject(txError(tx, 'Message history could not be saved'));
    for (const { store, record } of puts) tx.objectStore(store).put(record);
  });
}

// The persistent store of a saved wallet. Resolves once the whole history
// has been read and decrypted; rejects (Messages stays closed) on any error.
// Returns { persistent: true, state, messages, save(state, newMessages), close(), erase() }.
// `signal` (optional): bounds the IndexedDB open and read, which resolve only
// when the browser answers — once it aborts the open rejects with a
// StorageError (HISTORY_SLOW_TEXT); a database handle that arrives later is
// closed and dropped, nothing is written.
export async function openHistoryStore({ core, vaultId, storage = globalThis.localStorage, signal }) {
  const name = databaseNameForVault(vaultId);
  await sealing(() => core.historyKey(name), 'The key for your message history could not be prepared.');
  const db = await bounded(openDatabase(name), signal, late => late.close());
  db.onversionchange = () => db.close();
  let counter, state, messages, profiles, vaults;
  try {
    const raw = await bounded(readAll(db), signal);
    // The larger of the database record and the copy that survives a
    // history delete (counterStorageKey above).
    counter = openingCounter(decodeCounter(raw.counter), readStoredCounter(storage, name));
    const open = async (store, record) => {
      const args = decodeRecord(record);
      const { plaintext } = await sealing(() => core.historyDecrypt({ store, ...args }), 'A stored message could not be opened. It may be damaged or from a different wallet.');
      return parsePlaintext(plaintext);
    };
    const stateRecords = raw.stateRecords || [];
    const stateRecord = stateRecords.find(r => r?.id === STATE_ID);
    state = stateRecord === undefined ? emptyState() : checkState(await open(STORE_STATE, stateRecord));
    // Only the profile records the state still points to are opened; one
    // that fails is dropped (the profile is read from the network again),
    // it does not keep Messages closed.
    profiles = [];
    const wanted = new Map(Object.entries(state.profileCache).map(([fp, e]) => [e.id, fp]));
    for (const record of stateRecords) {
      if (!record || !wanted.has(record.id)) continue;
      try {
        const kept = checkProfileRecord(await open(STORE_STATE, record));
        if (kept.fp === wanted.get(record.id)) profiles.push({ id: record.id, fp: kept.fp, record: kept.record });
      } catch { /* not used */ }
    }
    // The vault records the state points to, likewise: one that fails is
    // dropped (the vault is added again from its message), it does not keep
    // Messages closed.
    vaults = [];
    const wantedVaults = new Map(Object.entries(state.vaults).map(([address, e]) => [e.id, address]));
    for (const record of stateRecords) {
      if (!record || !wantedVaults.has(record.id)) continue;
      try {
        const kept = checkVaultRecord(await open(STORE_STATE, record));
        if (kept.address === wantedVaults.get(record.id)) vaults.push({ id: record.id, address: kept.address, value: kept.value });
      } catch { /* not used */ }
    }
    messages = [];
    for (const record of raw.messages || []) {
      const message = await open(STORE_MESSAGES, record);
      if (!message || messageRecordId(String(message.seq)) !== record.id) throw new StorageError('A stored message record is damaged.');
      messages.push(message);
    }
  } catch (error) { db.close(); throw error; }

  let queue = Promise.resolve(), closed = false;
  // Another tab deleting this history (the wallet page's vault delete) closes
  // the store for good: a save already sealing must not write the counter
  // copy back after the delete (Connect RT2 L3 F1).
  db.onversionchange = () => { closed = true; db.close(); };
  // Writes are serialised so the counter only ever grows. A transaction that
  // fails after encryption leaves the in-memory counter advanced (the
  // encryptions happened; counting them keeps the 2^32 budget conservative);
  // the next successful write stores it.
  // `keptProfiles`: [{ id, fp, record }] written to the 'state' store next
  // to the state that points to them (state.profileCache).
  // `keptVaults`: [{ id, address, value }] likewise (state.vaults).
  function save(nextState, newMessages = [], keptProfiles = [], keptVaults = []) {
    const run = async () => {
      if (closed) throw new StorageError('Message history is closed.');
      const entries = [
        ...newMessages.map(m => ({ store: STORE_MESSAGES, id: messageRecordId(String(m.seq)), value: m })),
        ...keptProfiles.map(p => {
          if (typeof p?.id !== 'string' || !PROFILE_RECORD_ID.test(p.id)) throw new StorageError('Invalid profile record.');
          return { store: STORE_STATE, id: p.id, value: checkProfileRecord({ fp: p.fp, record: p.record }) };
        }),
        ...keptVaults.map(v => {
          if (typeof v?.id !== 'string' || !VAULT_RECORD_ID.test(v.id)) throw new StorageError('Invalid vault record.');
          return { store: STORE_STATE, id: v.id, value: checkVaultRecord({ address: v.address, value: v.value }) };
        }),
        { store: STORE_STATE, id: STATE_ID, value: checkState(nextState) }
      ];
      if (!budgetAllows(counter, entries.length)) throw new StorageError('This device has stored the maximum number of messages for this wallet. Nothing more can be saved here.');
      // Every plaintext is built (and size-checked) before the first seal.
      const plains = entries.map(entry => plaintextBytes(entry.value));
      const puts = [];
      try {
        for (const [i, entry] of entries.entries()) {
          const sealed = await sealing(() => core.historyEncrypt({ store: entry.store, id: entry.id, plaintext: plains[i], counter: counter.toString() }), 'Message history could not be saved: the message could not be sealed.');
          counter = nextCounter(counter, sealed.counter);
          puts.push({ store: entry.store, record: encodeRecord(entry.id, sealed) });
        }
      } finally { for (const bytes of plains) bytes.fill(0); }
      // Closed while sealing (lock, or the history deleted by another tab):
      // nothing is written, not even the counter copy.
      if (closed) throw new StorageError('Message history is closed.');
      // The copy first: if the tab dies between here and the commit, the
      // encryptions already made are still counted.
      writeStoredCounter(storage, name, counter);
      puts.push({ store: STORE_META, record: encodeCounter(counter) });
      await writeAll(db, puts);
    };
    const result = queue.then(run, run);
    queue = result.catch(() => {});
    return result;
  }
  function close() { closed = true; db.close(); }
  // Delete-from-this-device under the wallet's storage Web Lock (§1.7). The
  // counter copy in localStorage is KEPT: K does not change, so its count
  // must not restart (NC-RT2 D).
  async function erase() {
    close();
    if (!navigator.locks) throw new StorageError('This browser cannot safely delete saved data.');
    await navigator.locks.request('nodus.wallet.storage', () => deleteDatabase(name));
  }
  return { persistent: true, state, messages, profiles, vaults, save, close, erase };
}

// An unsaved wallet (words typed in, or a new account): nothing is written
// anywhere; everything is gone when Messages locks (S8).
export function memoryHistoryStore() {
  let closed = false;
  return {
    persistent: false, state: emptyState(), messages: [], profiles: [], vaults: [],
    async save(nextState) { if (closed) throw new StorageError('Message history is closed.'); checkState(nextState); },
    close() { closed = true; },
    async erase() { closed = true; }
  };
}
