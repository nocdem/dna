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
//   docs/plans/2026-10-13-connect-core-p7-state-design.md rev 2 + 2.1 (P7
//     stage 2; Kurultay #19, decisions/2026-10-13-kurultay-19-summary.md):
//     the state is kept as schema v2 (§2.1) — a header and one record per
//     known ID, their canonical bytes made by the core (connect/nc_state.h);
//     a v1 state is migrated once after the open (§2.2); every save is ONE
//     commit (§2.3): snapshot at the call, diff against the last COMMITTED
//     records at the run, a counter reservation before the first seal, one
//     transaction, aborted when queuing it throws; the header and the
//     known-ID records fail closed (§2.5). Rev 2.2 (after the code
//     red-team): the caller's rollback is handed to save() (`undo`) and run
//     inside the queue on a failure, and every save queued behind a failed
//     one is rebuilt from the state (§2.3 item 3); a save first checks that
//     this build could load what it commits; a cut `removed` list is
//     reported and written back.
//
// Naming: database = the vault id as 32 lowercase hex characters (the same 16
// bytes as the vault's base64 `id`). Object stores: 'messages' (one record per
// message, id 'm' + 20-digit local sequence), 'state' (since P7 schema v2:
// the record id 'state' is the HEADER — the known-ID ids, the next local
// sequence, removed / declined, the vault and group indexes, the own-record
// latches — and one record per known ID, 'c' + 20 digits: its contact flag,
// pending request, kept-profile index, chain name, salts, ACK and check
// times (nc_state.h); a v1 database holds the whole v1 state in 'state'
// instead; plus one record per kept contact profile, id 'p' + 20-digit
// local sequence, one per shared vault, id 'v' + 20-digit local sequence —
// src/vaults/ — and the group records 'g' / 'k' / 'x' + 20 digits —
// src/connect/groups/), 'meta' (the counter record). Record ids are opaque
// on purpose: who you talk to is inside the ciphertext, not in an id or the
// AAD (the NUMBER of 'c' records shows how many IDs this wallet keeps
// something for — the khan's decision 2026-10-13, design G1). The counter is
// also kept in localStorage ('nodus.connect.counter.v1.<database name>', a
// decimal string) so deleting the history does not restart it (NC-RT2 D).
//
// Core calls used (src/connect/core.js, NC-4b):
//   core.historyKey(vaultIdHex)             32 lowercase hex
//   core.historyEncrypt({ store, id, plaintext, counter }) -> { nonce, ct, tag, counter }
//     store = the object-store name (nc_history.h: the AAD's "store");
//     plaintext: Uint8Array (UTF-8 JSON here), 1..1048576 bytes
//     (nc_wasm.c NC_HIST_PT_MAX); counter: decimal string in, the new value
//     out (checked here to be exactly in + 1); nonce / ct / tag: Uint8Array
//   core.historyDecrypt({ store, id, nonce, ct, tag }) -> { plaintext: Uint8Array }
//   core.stateProject(v1State, idMap) -> { status, nextSeq, header, records:
//     [{ id, fp, json }], dropped }   synchronous (P7)
//   core.stateLoad({ header, records: [{ id, json }] }) -> { status, state, map }
//     synchronous (P7)

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
// The core seals at most this many plaintext bytes per record (nc_wasm.c
// NC_HIST_PT_MAX). 64 KiB until web 0.1.112: the one 'state' record (every
// contact's entries in one record, ~1 KB per contact) outgrew it at about 60
// contacts and every save failed (BUGS W-15). P7 (stage 2) splits it: a
// header and one record of ~1 KB per known ID, each under this cap.
export const PLAINTEXT_MAX = 1048576;
const U64 = /^(0|[1-9]\d{0,19})$/;
// A known-ID record of the state schema v2 (connect/nc_state.h).
export const KNOWN_ID_RECORD_ID = /^c\d{20}$/;
// The schema version of the header record 'state' (nc_state.h NC_STATE_VERSION).
const STATE_SCHEMA_V2 = 2;
export const DAMAGED_STATE_TEXT = 'The stored contact list is damaged.';
const SAVE_PREPARE_TEXT = 'Message history could not be saved: the contact list could not be prepared.';
// A save whose records this build could not open again (design rev 2.2
// item 2: the load check at save) — never the damaged-history text.
export const HISTORY_TOO_LARGE_TEXT = 'Your message history is too large to save on this device.';
// nc_state.h NC_STATE_REMOVED_MAX (§2.1 Bounds): the projection keeps the
// last this many `removed` entries and lists the path 'removed' as dropped;
// save() then cuts the page's list the same way (design rev 2.2 item 3).
export const STATE_REMOVED_MAX = 1000;
const SEAL_TEXT = 'Message history could not be saved: the message could not be sealed.';
const BUDGET_TEXT = 'This device has stored the maximum number of messages for this wallet. Nothing more can be saved here.';
const READ_TEXT = 'A stored message could not be read.';

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
// days); only a found name is kept here (a name is permanent — decision
// 2026-10-02-onchain-names.md item 4 — while "no name" can change any
// block). `chainNoName` (web 0.1.74): fp -> unix seconds of a CONTACT's
// last ANSWERED "no name" lookup (never a failed one, never the own ID):
// the sync round does not ask that contact again before it is a day old
// (ui/chain-names.js CHAIN_NO_NAME_RECHECK_SECONDS, chainNoNameFresh). A
// map of its own, not a '' name inside `chainNames`: an older version's
// checkState refuses a chainNames entry without a valid name (the whole
// state would read as damaged after a rollback) and ignores a key it does
// not know. `removed`: IDs the user removed from the contacts on THIS device
// (text.js removeContact); the own list on the network is merge-only
// (nc_core.h nc_contactlist_add), so it still lists them and they must not
// be added back from it (text.js mergeListedContacts). Adding the person
// again (request accepted, theirs or ours) takes the ID off this list.
// `groups` (package G3): group id (64 hex) -> { id: 'g' + 20 digits, at }
// — the group's own record in the 'state' store (src/connect/groups/
// model.js checkGroup), like state.vaults. A group record points to its key
// version records ('k' + 20 digits, one per version — decision 14 keeps
// every old key, and one version of 64 members is ~8.5 KB) and, while an
// owner's rotation is staged, to the staged key packet split in pieces
// ('x' + 20 digits — R2-2: the owner keeps the exact bytes, 107,795 B at
// 64 members, more than one record holds). Group messages are records of
// the 'messages' store with a `group` field (openHistoryStore returns them
// apart from the 1:1 messages). `seenOwn` (web 0.1.88, W-04): kind -> unix
// seconds this device first read this account's own record of that kind on
// the network ('profile', 'list') — the device memory of ui/text.js
// firstRecordAllowed: once seen, an EMPTY answer never creates that record
// again from this device. An older version ignores the key.
export function emptyState() {
  return { version: 1, nextSeq: '1', contacts: [], outgoing: [], declined: [], removed: [], acks: {}, ackSent: {}, profileCache: {}, dmSync: {}, chainNames: {}, chainNoName: {}, vaults: {}, groups: {}, seenOwn: {} };
}
export const SEEN_OWN_KINDS = Object.freeze(['profile', 'list']);
const isMap = value => value && typeof value === 'object' && !Array.isArray(value);
const HEX128_KEY = /^[0-9a-f]{128}$/;
export const PROFILE_RECORD_ID = /^p\d{20}$/;
// Shared vaults (src/vaults/): state.vaults maps a vault address to the id
// of its own record in the 'state' store ({ id: 'v' + 20 digits, at }),
// like state.profileCache; the record holds what src/vaults/core.js
// checkVaultRecord accepts. Record ids stay opaque (the address is inside
// the ciphertext and the state, never in an id or the AAD).
export const VAULT_RECORD_ID = /^v\d{20}$/;
// Group records (state.groups above): 'g' group, 'k' key version, 'x' a
// piece of a staged key packet.
export const GROUP_RECORD_ID = /^[gkx]\d{20}$/;
const HEX64_KEY = /^[0-9a-f]{64}$/;
export function checkState(value) {
  // A state saved before `ackSent`, `profileCache`, `dmSync`, `chainNames`,
  // `chainNoName`, `vaults` or `groups` existed gets the default (same
  // version).
  if (value && value.version === 1) for (const key of ['ackSent', 'profileCache', 'dmSync', 'chainNames', 'chainNoName', 'vaults', 'groups', 'seenOwn']) if (value[key] === undefined) value[key] = {};
  // … and before `removed` existed, likewise (an empty list).
  if (value && value.version === 1 && value.removed === undefined) value.removed = [];
  if (!value || value.version !== 1 || !U64.test(String(value.nextSeq)) || !Array.isArray(value.contacts) ||
      !Array.isArray(value.outgoing) || !Array.isArray(value.declined) ||
      // a bare ID (before 0.1.96) or { fp, at } (text.js declinedNow)
      value.declined.some(d => !(typeof d === 'string' ? HEX128_KEY.test(d) : isMap(d) && typeof d.fp === 'string' && HEX128_KEY.test(d.fp) && U64.test(String(d.at)))) ||
      !Array.isArray(value.removed) || value.removed.some(fp => typeof fp !== 'string' || !HEX128_KEY.test(fp)) ||
      !value.acks || typeof value.acks !== 'object' ||
      !isMap(value.ackSent) || !isMap(value.profileCache) || !isMap(value.dmSync) || !isMap(value.chainNames) || !isMap(value.chainNoName) || !isMap(value.vaults) || !isMap(value.groups) ||
      !isMap(value.seenOwn) || Object.entries(value.seenOwn).some(([kind, at]) => !SEEN_OWN_KINDS.includes(kind) || !U64.test(String(at))) ||
      Object.entries(value.groups).some(([gid, e]) => !HEX64_KEY.test(gid) || !isMap(e) || typeof e.id !== 'string' || !/^g\d{20}$/.test(e.id) || !U64.test(String(e.at))) ||
      Object.values(value.profileCache).some(e => !isMap(e) || typeof e.id !== 'string' || !PROFILE_RECORD_ID.test(e.id) ||
        !U64.test(String(e.at)) || typeof e.name !== 'string') ||
      Object.values(value.dmSync).some(t => !U64.test(String(t))) ||
      Object.entries(value.chainNames).some(([fp, e]) => !HEX128_KEY.test(fp) || !isMap(e) || !chainNameOk(e.name) || !U64.test(String(e.at))) ||
      Object.entries(value.chainNoName).some(([fp, at]) => !HEX128_KEY.test(fp) || !U64.test(String(at))) ||
      Object.entries(value.vaults).some(([addr, e]) => !HEX128_KEY.test(addr) || !isMap(e) || typeof e.id !== 'string' || !VAULT_RECORD_ID.test(e.id) || !U64.test(String(e.at)))) throw new StorageError(DAMAGED_STATE_TEXT);
  return value;
}

// ── state schema v2 (P7 stage 2) ───────────────────────────────────────
// A SNAPSHOT of the state: the canonical text of every state record the
// core projects it to — 'state' (the header) first, then the 'c…' records
// ascending — with the fp -> id map, the advanced nextSeq and the paths the
// projection left out (nc_state.h DROPPED). Synchronous: taken when save()
// is called, so nothing the page changes afterwards leaks into that commit
// (design §2.3 item 1). `idMap`: fp -> id of the newest snapshot (ids stay
// stable, §2.1).
// The text core.js putState throws for a state input over its 8 MiB bound
// (src/connect/core.js STATE_IN_MAX): the history is too large to save,
// not a contact list that could not be prepared — mapped to
// HISTORY_TOO_LARGE_TEXT; every other projection error stays SAVE_PREPARE_TEXT.
const STATE_INPUT_TOO_LARGE = 'The message state is too large for this version.';
export function stateSnapshot(core, v1State, idMap) {
  let r;
  try { r = core.stateProject(v1State, idMap); }
  catch (error) {
    if (error instanceof StorageError) throw error;
    throw new StorageError(error?.message === STATE_INPUT_TOO_LARGE ? HISTORY_TOO_LARGE_TEXT : SAVE_PREPARE_TEXT);
  }
  if (r?.status === 'invalid' && r.reason === 'checkState') throw new StorageError(DAMAGED_STATE_TEXT);
  if (!r || r.status !== 'ok' || typeof r.header !== 'string' || typeof r.nextSeq !== 'string' || !U64.test(r.nextSeq) ||
      !Array.isArray(r.records) || !Array.isArray(r.dropped) || r.dropped.some(p => typeof p !== 'string')) throw new StorageError(SAVE_PREPARE_TEXT);
  const texts = new Map([[STATE_ID, r.header]]), map = {};
  for (const rec of r.records) {
    if (!rec || typeof rec.id !== 'string' || !KNOWN_ID_RECORD_ID.test(rec.id) || typeof rec.fp !== 'string' || !HEX128_KEY.test(rec.fp) ||
        typeof rec.json !== 'string' || texts.has(rec.id) || Object.hasOwn(map, rec.fp)) throw new StorageError(SAVE_PREPARE_TEXT);
    texts.set(rec.id, rec.json);
    map[rec.fp] = rec.id;
  }
  return { texts, map, nextSeq: r.nextSeq, dropped: r.dropped };
}

// What one commit writes to the 'state' store (design §2.3 item 2): every
// record of the snapshot whose text differs from the last COMMITTED one, or
// is new, is put; every known-ID record of the committed baseline the
// snapshot no longer has is deleted (§2.1 Lifetime). The header is always
// in a snapshot, so it is never deleted. `baseline`, `texts`: Map id -> text.
export function stateDiff(baseline, texts) {
  const puts = [], deletes = [];
  for (const [id, text] of texts) if (baseline.get(id) !== text) puts.push({ id, text });
  for (const id of baseline.keys()) if (!texts.has(id) && KNOWN_ID_RECORD_ID.test(id)) deletes.push(id);
  deletes.sort();
  return { puts, deletes };
}

// The v2 records -> { state (the canonical v1 object), map }, or a
// StorageError: fail closed (design §2.5).
export function stateLoaded(core, header, records) {
  let r;
  try { r = core.stateLoad({ header, records }); }
  catch (error) { throw error instanceof StorageError ? error : new StorageError(DAMAGED_STATE_TEXT); }
  if (!r || r.status !== 'ok' || !isMap(r.state) || !isMap(r.map)) throw new StorageError(DAMAGED_STATE_TEXT);
  return { state: checkState(r.state), map: r.map };
}
// A snapshot's known-ID records in the shape stateLoaded takes (the header
// is the 'state' text; the records follow it ascending, as projected).
const snapshotRecords = texts => [...texts].filter(([id]) => id !== STATE_ID).map(([id, json]) => ({ id, json }));

// A record text -> the plaintext bytes handed to the core (UTF-8).
export function textBytes(text) {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length === 0 || bytes.length > PLAINTEXT_MAX) throw new StorageError('This is too large to save on this device.');
  return bytes;
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

// ONE readwrite transaction (design §2.3 items 5-6). `puts`: [{ store,
// record }], `deletes`: [{ store, id }] — every byte already prepared; the
// body only puts and deletes. Resolves on oncomplete (= Committed). A
// synchronous throw while the requests are queued aborts the transaction,
// so the requests queued before it never commit without the rest (Kurultay
// #19 item 13).
export function writeAll(db, puts, deletes = []) {
  return new Promise((resolve, reject) => {
    let tx;
    try { tx = db.transaction([STORE_MESSAGES, STORE_STATE, STORE_META], 'readwrite'); }
    catch (error) { reject(new StorageError(`Message history could not be saved: ${error.message}.`)); return; }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(txError(tx, 'Message history could not be saved'));
    tx.onabort = () => reject(txError(tx, 'Message history could not be saved'));
    try {
      for (const { store, record } of puts) tx.objectStore(store).put(record);
      for (const { store, id } of deletes) tx.objectStore(store).delete(id);
    } catch (error) {
      try { tx.abort(); } catch { /* already finished */ }
      reject(new StorageError(`Message history could not be saved: ${error?.message || 'the browser refused the change'}.`));
    }
  });
}

// The persistent store of a saved wallet. Resolves once the whole history
// has been read and decrypted; rejects (Messages stays closed) on any error.
// Returns { persistent: true, state, messages, profiles, vaults,
// groupRecords, groupMessages, dropped, save(state, newMessages, …),
// close(), erase() }.
// `signal` (optional): bounds the IndexedDB open and read, which resolve only
// when the browser answers — once it aborts the open rejects with a
// StorageError (HISTORY_SLOW_TEXT); a database handle that arrives later is
// closed and dropped, nothing is written. The bound covers the open and the
// read, not the opening of the records or the migration (design §2.2 item 1).
// `onMigrate(phase)` (optional): 'start' when a v1 state is about to be
// migrated (after the bounded read; the page shows its status line), 'done'
// once the migration's commit completed. `onDropped(paths)` (optional): the
// paths a projection left out (nc_state.h DROPPED — paths, never values),
// from the migration (also in the result's `dropped`) or from a save.
export async function openHistoryStore({ core, vaultId, storage = globalThis.localStorage, signal, onMigrate, onDropped }) {
  const name = databaseNameForVault(vaultId);
  await sealing(() => core.historyKey(name), 'The key for your message history could not be prepared.');
  const db = await bounded(openDatabase(name), signal, late => late.close());
  db.onversionchange = () => db.close();
  let counter, state, messages, profiles, vaults, groupRecords, groupMessages;
  // The last COMMITTED state records (Map id -> canonical text) and the fp
  // -> id map of the newest snapshot (design §2.3 item 2, §2.1).
  let baseline = new Map(), idMap = {}, dropped = [];
  const reportDropped = paths => { if (paths.length) { try { onDropped?.([...paths]); } catch { /* the page's log */ } } };

  // ONE reservation for `entries` ([{ store, id, bytes }]), then the seals
  // (design §2.3 item 4, Kurultay #19 item 5): the counter copy is advanced
  // by the number of seals BEFORE the first one, and the budget is tested on
  // that reserved value. A failure keeps the reservation: the numbers not
  // used are burned, never reused. The bytes are wiped on every path.
  // Returns the records to put, the counter record last.
  async function sealAll(entries) {
    try {
      if (!budgetAllows(counter, entries.length)) throw new StorageError(BUDGET_TEXT);
      const reserved = counter + BigInt(entries.length);
      writeStoredCounter(storage, name, reserved);
      let at = counter;
      counter = reserved;
      const puts = [];
      for (const entry of entries) {
        const sealed = await sealing(() => core.historyEncrypt({ store: entry.store, id: entry.id, plaintext: entry.bytes, counter: at.toString() }), SEAL_TEXT);
        at = nextCounter(at, sealed.counter);
        puts.push({ store: entry.store, record: encodeRecord(entry.id, sealed) });
      }
      if (at !== reserved) throw new StorageError('Message history could not be saved (counter mismatch).');
      puts.push({ store: STORE_META, record: encodeCounter(reserved) });
      return puts;
    } finally { for (const entry of entries) entry.bytes.fill(0); }
  }
  // [{ store, id, value | text }] -> [{ store, id, bytes }]; every plaintext
  // is built and size-checked before the first seal (wiped if one fails).
  function plainEntries(list) {
    const out = [];
    try {
      for (const e of list) out.push({ store: e.store, id: e.id, bytes: e.text !== undefined ? textBytes(e.text) : plaintextBytes(e.value) });
      return out;
    } catch (error) { for (const e of out) e.bytes.fill(0); throw error; }
  }

  try {
    const raw = await bounded(readAll(db), signal);
    // The larger of the database record and the copy that survives a
    // history delete (counterStorageKey above).
    counter = openingCounter(decodeCounter(raw.counter), readStoredCounter(storage, name));
    const openBytes = async (store, record) => {
      const args = decodeRecord(record);
      const { plaintext } = await sealing(() => core.historyDecrypt({ store, ...args }), 'A stored message could not be opened. It may be damaged or from a different wallet.');
      return plaintext;
    };
    const open = async (store, record) => parsePlaintext(await openBytes(store, record));
    // The exact text (the v2 load compares bytes).
    const openText = async (store, record) => {
      const bytes = await openBytes(store, record);
      try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      catch { throw new StorageError(READ_TEXT); }
      finally { bytes.fill(0); }
    };
    const stateRecords = raw.stateRecords || [];
    const stateRecord = stateRecords.find(r => r?.id === STATE_ID);
    if (stateRecord === undefined) {
      // Nothing kept yet: the first save writes the header.
      state = emptyState();
    } else {
      const header = await openText(STORE_STATE, stateRecord);
      let parsed;
      try { parsed = JSON.parse(header); } catch { throw new StorageError(READ_TEXT); }
      if (isMap(parsed) && parsed.version === STATE_SCHEMA_V2) {
        // v2: the header and EVERY known-ID record it lists; one that is
        // missing or does not open keeps Messages closed (design §2.5) —
        // the core refuses a missing one, a duplicate fp, anything not
        // canonical. Records the header does not list are not opened.
        const byId = new Map();
        for (const r of stateRecords) if (r && typeof r.id === 'string' && KNOWN_ID_RECORD_ID.test(r.id)) byId.set(r.id, r);
        const records = [];
        for (const id of Array.isArray(parsed.ids) ? parsed.ids : []) {
          const record = typeof id === 'string' ? byId.get(id) : undefined;
          if (record) records.push({ id, json: await openText(STORE_STATE, record) });
        }
        ({ state, map: idMap } = stateLoaded(core, header, records));
        baseline = new Map([[STATE_ID, header], ...records.map(r => [r.id, r.json])]);
      } else {
        // v1 (anything else is refused here as damaged): migrated once,
        // after the bounded read (design §2.2) — the projection with no
        // previous map, ONE commit of the header and every known-ID record
        // (N+1 seals), nothing deleted. The state handed to the page is
        // what loading those records gives (the canonical v1 form, with the
        // advanced nextSeq).
        const v1 = checkState(parsed);
        try { onMigrate?.('start'); } catch { /* the page's status line */ }
        const snap = stateSnapshot(core, v1, {});
        const loaded = stateLoaded(core, snap.texts.get(STATE_ID), snapshotRecords(snap.texts));
        const puts = await sealAll(plainEntries([...snap.texts].map(([id, text]) => ({ store: STORE_STATE, id, text }))));
        await writeAll(db, puts);
        ({ state, map: idMap } = loaded);
        baseline = snap.texts;
        dropped = snap.dropped;
        reportDropped(dropped);
        try { onMigrate?.('done'); } catch { /* the page's status line */ }
      }
    }
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
    // Group records (state.groups): every 'g' / 'k' / 'x' record that opens
    // is handed over; the groups module keeps those its group records point
    // to and checks their shape (src/connect/groups/model.js). One that
    // fails to open is dropped here; it does not keep Messages closed.
    groupRecords = [];
    for (const record of stateRecords) {
      if (!record || typeof record.id !== 'string' || !GROUP_RECORD_ID.test(record.id)) continue;
      try {
        const kept = await open(STORE_STATE, record);
        if (isMap(kept)) groupRecords.push({ id: record.id, value: kept });
      } catch { /* not used */ }
    }
    messages = [];
    groupMessages = [];
    for (const record of raw.messages || []) {
      const message = await open(STORE_MESSAGES, record);
      if (!message || messageRecordId(String(message.seq)) !== record.id) throw new StorageError('A stored message record is damaged.');
      // A group message never joins the 1:1 list: every 1:1 helper
      // (src/connect/ui/text.js) selects by `fp` and `dir` alone.
      if (message.group !== undefined) groupMessages.push(message); else messages.push(message);
    }
  } catch (error) { db.close(); throw error; }

  let queue = Promise.resolve(), closed = false;
  // How many queued runs have failed so far (design rev 2.2 item 1): a save
  // keeps the value it saw at its call; a different value at its run means a
  // run failed after the call, so its call-time snapshot may hold what that
  // failure's undo took back — it is rebuilt. Counted in queue order, never
  // by time.
  let failures = 0;
  // Another tab deleting this history (the wallet page's vault delete) closes
  // the store for good: a save already sealing must not write the counter
  // copy back after the delete (Connect RT2 L3 F1).
  db.onversionchange = () => { closed = true; db.close(); };
  // The snapshot of `nextState` (synchronous): refused when closed, when
  // checkState refuses, when the core cannot project it, or when the records
  // it projects to could not be loaded again by this build (design rev 2.2
  // item 2: the same check the migration makes, stateLoaded — the 8 MiB load
  // input bound included — so a save never commits a history that would
  // keep Messages closed; HISTORY_TOO_LARGE_TEXT). Only once all of that
  // passed is anything written back: the advanced nextSeq into `nextState`
  // (the page's local sequence shares it, messages.js takeSeq), a `removed`
  // list the projection cut (its path in `dropped`) to the same last
  // STATE_REMOVED_MAX entries (rev 2.2 item 3: the session log shows the cut
  // once), the newest fp -> id map; then the dropped paths are reported.
  function prepare(nextState) {
    if (closed) throw new StorageError('Message history is closed.');
    checkState(nextState);
    const snap = stateSnapshot(core, nextState, idMap);
    try { stateLoaded(core, snap.texts.get(STATE_ID), snapshotRecords(snap.texts)); }
    catch { throw new StorageError(HISTORY_TOO_LARGE_TEXT); }
    nextState.nextSeq = snap.nextSeq;
    if (snap.dropped.includes('removed')) nextState.removed = nextState.removed.slice(-STATE_REMOVED_MAX);
    idMap = snap.map;
    reportDropped(snap.dropped);
    return snap;
  }
  // The caller's rollback, run at most once; its own throw never replaces
  // the save's error and never stops the queue.
  const runUndo = undo => { if (typeof undo === 'function') { try { undo(); } catch { /* the save's error stands */ } } };
  // ONE commit per save (design §2.3), serialised: one in flight.
  //   At the call, synchronously, before anything yields: prepare() above.
  //   A mutation of the state after the call cannot leak into this commit
  //   (store.js:441 before P7). A refusal here rejects at once, after the
  //   caller's `undo` ran; nothing was queued, so nothing is rebuilt.
  //   At the run (after the commits before it): if a run failed since the
  //   call, the snapshot is taken again from `nextState` as it is now
  //   (prepare, with the same refusals) — design §2.3 item 3, Kurultay #19
  //   item 6; otherwise the call-time snapshot is used. It is diffed
  //   against the last COMMITTED records (stateDiff): changed or new records
  //   are put, known-ID records no longer projected are deleted; plus the
  //   new messages, kept profiles, vaults and group records as before P7.
  //   One reservation for every seal (sealAll), then ONE transaction of the
  //   puts, the deletes and the counter record (writeAll). On its
  //   oncomplete the baseline becomes this snapshot. On a failure (any throw
  //   of the run) the reservation stays used, the baseline is unchanged (the
  //   next save diffs against what is really committed), the failure count
  //   grows, and the caller's `undo` runs — synchronously, inside the
  //   queue, before the next run starts and before this save's promise
  //   rejects with the error.
  // `keptProfiles`: [{ id, fp, record }] written to the 'state' store next
  // to the state that points to them (state.profileCache).
  // `keptVaults`: [{ id, address, value }] likewise (state.vaults).
  // `keptGroups`: [{ id, value }] group / key version / staged packet piece
  // records (GROUP_RECORD_ID; state.groups, src/connect/groups/).
  // `undo` (optional, synchronous): takes back the caller's own change to
  // the state when this save fails, at the call or at the run — exactly
  // once, before the caller sees the error (design rev 2.2 item 1).
  function save(nextState, newMessages = [], keptProfiles = [], keptVaults = [], keptGroups = [], { undo } = {}) {
    let snap;
    try {
      snap = prepare(nextState);
    } catch (error) {
      runUndo(undo);
      return Promise.reject(error instanceof StorageError ? error : new StorageError(SAVE_PREPARE_TEXT));
    }
    const seen = failures;
    const run = async () => {
      try {
        if (closed) throw new StorageError('Message history is closed.');
        if (seen !== failures) {
          try { snap = prepare(nextState); }
          catch (error) { throw error instanceof StorageError ? error : new StorageError(SAVE_PREPARE_TEXT); }
        }
        await commitSnapshot(snap, newMessages, keptProfiles, keptVaults, keptGroups);
      } catch (error) {
        failures++;
        runUndo(undo);
        throw error;
      }
    };
    const result = queue.then(run, run);
    queue = result.catch(() => {});
    return result;
  }
  // The run's commit of one snapshot (above): the diff, the seals, ONE
  // transaction; the baseline moves only on its oncomplete.
  async function commitSnapshot(snap, newMessages, keptProfiles, keptVaults, keptGroups) {
    const diff = stateDiff(baseline, snap.texts);
    const list = [
      ...newMessages.map(m => ({ store: STORE_MESSAGES, id: messageRecordId(String(m.seq)), value: m })),
      ...keptProfiles.map(p => {
        if (typeof p?.id !== 'string' || !PROFILE_RECORD_ID.test(p.id)) throw new StorageError('Invalid profile record.');
        return { store: STORE_STATE, id: p.id, value: checkProfileRecord({ fp: p.fp, record: p.record }) };
      }),
      ...keptVaults.map(v => {
        if (typeof v?.id !== 'string' || !VAULT_RECORD_ID.test(v.id)) throw new StorageError('Invalid vault record.');
        return { store: STORE_STATE, id: v.id, value: checkVaultRecord({ address: v.address, value: v.value }) };
      }),
      ...keptGroups.map(g => {
        if (typeof g?.id !== 'string' || !GROUP_RECORD_ID.test(g.id) || !isMap(g.value)) throw new StorageError('Invalid group record.');
        return { store: STORE_STATE, id: g.id, value: g.value };
      }),
      ...diff.puts.map(p => ({ store: STORE_STATE, id: p.id, text: p.text }))
    ];
    const deletes = diff.deletes.map(id => ({ store: STORE_STATE, id }));
    // Nothing changed: nothing is sealed or written.
    if (list.length === 0 && deletes.length === 0) return;
    // The reservation is written before the first seal (sealAll); closed
    // was checked by the run just before, with nothing awaited in between.
    const puts = await sealAll(plainEntries(list));
    // Closed while sealing (lock, or the history deleted by another tab):
    // nothing is written to the database (the counter copy already holds
    // the reservation: conservative).
    if (closed) throw new StorageError('Message history is closed.');
    await writeAll(db, puts, deletes);
    baseline = snap.texts;
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
  return { persistent: true, state, messages, profiles, vaults, groupRecords, groupMessages, dropped, save, close, erase };
}

// An unsaved wallet (words typed in, or a new account): nothing is written
// anywhere; everything is gone when Messages locks (S8).
export function memoryHistoryStore() {
  let closed = false;
  return {
    persistent: false, state: emptyState(), messages: [], profiles: [], vaults: [], groupRecords: [], groupMessages: [],
    // The same arguments as the persistent save(); nothing is written. A
    // refusal runs the caller's `undo` first, as there.
    async save(nextState, newMessages = [], keptProfiles = [], keptVaults = [], keptGroups = [], { undo } = {}) {
      try {
        if (closed) throw new StorageError('Message history is closed.');
        checkState(nextState);
      } catch (error) {
        if (typeof undo === 'function') { try { undo(); } catch { /* the save's error stands */ } }
        throw error;
      }
    },
    close() { closed = true; },
    async erase() { closed = true; }
  };
}
