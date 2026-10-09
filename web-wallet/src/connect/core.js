// Nodus Connect thin core — JS glue (packages NC-2 / NC-4b of
// docs/plans/2026-09-24-web-connect-design.md rev 5, §1.1, §1.8, §1.9).
// No UI: the Messages screens are package NC-4.
//
// ONE MODULE, ONE SESSION, ONE QUEUE (NC-4b). The C side (web-wallet/
// connect/, rules in nc_core.h, JSON exports in nc_wasm.c) is linked into
// the wallet's NODUS module (src/nodus/send.wasm, scripts/build-nodus-send-
// wasm.sh) and runs on that module's tier-2 session: two sessions of one
// identity evict each other on a node (nodus_auth.c:95-116). This file
// therefore never loads or instantiates a module. It is handed the wallet's
// NODUS client (src/nodus/client.js createNodusClient, identified or ready) and
// runs every waiting export through THAT client's one operation queue
// (client.connect) — Asyncify keeps a single suspended-call state, a second
// export entered while one is suspended corrupts it (design §1.1). What it
// adds: the (generation, requestId) stamp on every result (§1.9) and the
// Messages lock.
//
// LOCK. The wallet's lock (client.lock: queue stops -> nsw_cancel ->
// nsw_lock, which also wipes every Messages secret (nc_session_wipe) ->
// linear memory zeroed -> instance released; design §1.8) ends Messages
// too: every later call here rejects. core.lock() closes Messages alone:
// its pending calls are rejected, and nc_lock wipes the Messages keys,
// peer keys and history key now (or, if a Messages export is suspended, as
// soon as it returns); the wallet's session stays. Closing is terminal for
// this module instance: Messages reopens after the wallet is locked and
// unlocked again.
//
// API (every async call runs through the wallet's queue; results are plain
// objects, u64 values are decimal strings, bytes are lowercase hex unless
// said otherwise):
//   createNodusConnectCore({ nodus }) -> core
//     nodus: the wallet's NODUS client, at least identified (src/nodus/
//     client.js identify; nodus.localConnectable), whose module carries the
//     Messages exports. LOCAL calls — unlock, profileLoad, historyKey,
//     historyEncrypt, historyDecrypt — run once it is identified
//     (nodus.connectLocal); every other async call needs it 'ready'
//     (nodus.connect) and rejects before ("Nodus connection is not
//     ready."); the module refuses them on its own too (nc_wasm.c
//     session_ok).
//   core.unlock({ words, fresh }) -> { fingerprint, fresh }
//     words: Uint8Array of the NORMALISED phrase's UTF-8 bytes (wiped here
//     after the copy; the C copy is wiped on every path). The Messages KEM
//     keys are derived from them; they must belong to the wallet session's
//     address or nothing is connected. fresh: true ONLY for words this
//     session generated (decision Q1): a restored identity never creates a
//     record.
//   core.profileGet(fp) -> { outcome, why, profile?, record? }
//     outcome 'found' | 'empty' | 'unreadable'. 'empty' is NOT proof of
//     absence (design §2.1). profile.claimed_name is a claim (G9).
//     record (found only): the signed row as read, for a profile cache.
//   core.profileLoad(fp, record, name) -> { profile }   no network: a
//     record kept from profileGet passes the same checks again (signature,
//     fingerprint) and its keys are held as after a read; `name` (the
//     verified name of that read, or '') is kept only if it is still the
//     record's registered name. Rejects when the record fails.
//   core.profileUpdate(patch, { firstOk }?) -> { status, read, created, putRc, version }
//     firstOk (default false): an EMPTY read may create the FIRST profile —
//     the page passes it when this device never saw the own profile on the
//     network (ui/text.js firstRecordAllowed; W-04, nc_wasm.c first_begin).
//     status 'published' | 'wait' (nothing written: retry later) |
//     'taken' (the key is owned by someone else: terminal, show "profile
//     address taken", never retry) | 'failed' | 'bad_patch'.
//   core.requestsFetch() -> { outcome, why, partial: true, dropped, requests }
//     requests[i]: { sender, claimed_name (never show as a name), message,
//     timestamp, expiry, salt (hex | null), acceptance }. A get_all answer is
//     never complete (design §6.4 F5).
//   core.requestSend(fp, message) -> { salt }   store salt as pending-outgoing
//   core.requestAccept(fp, saltHex | null)      the app's ACCEPT (F3)
//   core.requestCancel(fp)                      withdraw own request
//   core.saltGet(fp) -> { outcome, why, partial, found, salt, authenticated }
//     needs profileGet(fp) first (keys come from the verified profile)
//   core.saltPick(localHex | null, dhtHex | null) -> { choice, salt,
//     republish_wanted }   synchronous, the native reconcile rule
//   core.saltReconcile(fp, localHex | null) -> { status, outcome, why,
//     choice, salt, putRc }   read + reconcile + gated publish (packet v1,
//     the app's builder): status 'nothing_to_write' | 'published' |
//     'wait' (nothing written; keep the local salt, retry later) | 'failed'.
//     An EMPTY read publishes the local salt for every identity (W-04).
//     Store `salt` unless status is 'wait'. Needs profileGet(fp) first.
//   core.contactsGet() -> { outcome, why, invalid, timestamp,
//     contacts: [{ fp, salt | null }] }   the own list; 'empty' is NOT proof
//     of absence
//   core.contactsAdd([{ fp, salt? }], { firstOk }?) -> { status, outcome, why, created,
//     countBefore, countAfter, saltKept, putRc }   MERGE ONLY into the list
//     read in the same call: status 'published' | 'unchanged' | 'wait'
//     (unreadable, or empty without firstOk) | 'taken' (terminal) |
//     'failed' | 'refused'. firstOk: as profileUpdate, for the own list.
//   core.dayToday() -> '<unix day>'             synchronous
//   core.outboxPublish(fp, saltHex, [{ seq, ts, text }]) -> { day, alg, count }
//     one 1:1 message send: the WHOLE pending set for that contact for today
//     (the blob replaces the previous one); needs profileGet(fp) first.
//   core.outboxFetchDay(fp, saltHex, day?, skipBlob?) -> { outcome, why, day,
//     blob, unchanged, dropped, other, messages: [{ seq, senderTs, text }] }
//     blob (found only): 64 hex of the bucket value; pass it back as
//     skipBlob ONLY once that answer's messages are stored — an equal
//     bucket is then not decoded (unchanged: true, no messages; the app's
//     blob cache, dht_dm_outbox.c:30-80). senderTs = sender's
//     clock; messages are chat text only — the app's control payloads and
//     card payloads are counted in `other` and never returned
//     (nc_core.h nc_plaintext_is_chat)
//   core.outboxFetchDays(fp, saltHex, [{ day, skipBlob? }]) -> { days: [
//     <the outboxFetchDay answer of each day>, ... ] } in the order asked;
//     1..8 days of ONE contact in one call (web 0.1.73): each day is read
//     with the same strict request and checked by the same code as
//     outboxFetchDay; the requests are pipelined in the module, 4 in flight
//     at once (nc_core.h nc_read_owner_many), not batched. `day` is
//     required (decimal); skipBlob as outboxFetchDay's. A day that
//     outboxFetchDay would reject rejects the whole call.
//   core.contactReads([{ fp, salt, days: [{ day, skipBlob? }] }]) ->
//     { contacts: [{ ack, days } | { error }, ...] } in the order asked;
//     the READ phase of 1..4 contacts' message checks in one call (web
//     0.1.74, connect/nc_wasm.c nc_contact_reads): per contact `ack` is
//     the ackGet answer and `days` the outboxFetchDays answer for the same
//     arguments — every key read with the same strict request and checks,
//     the requests of all the contacts pipelined in the module, 4 in flight
//     at once (never more). `error` (a string): that contact only, what its
//     outboxFetchDays call would have rejected with (no verified profile
//     loaded, or a day that could not be processed). Needs profileGet(fp)
//     of every contact first. No write.
//   core.ackPublish(fp, saltHex, ackTs)  ONLY after the store transaction's
//     oncomplete (G11) and only when that contact's fetch dropped nothing.
//     ackTs (decimal, > 0): the NEWEST sender timestamp stored from that
//     contact — never a clock — so the ACK covers only what was received.
//     The sender drops ACKed messages from its blob one hour after
//     marking them delivered (ui/text.js DELIVERED_GRACE_SECONDS).
//   core.ackGet(fp, saltHex) -> { outcome, why, ack_ts }   a watermark: a
//     message counts as delivered only if it was in a blob published before
//     this read and its timestamp is < ack_ts (ui/text.js markDelivered)
//   core.historyKey(vaultIdHex)  K = the history key of this vault
//     (decision 2026-09-30-connect-history-at-rest.md rev 2: from the
//     session's ML-DSA-87 secret key and the vault's 16-byte id, 32 hex).
//     K stays in module memory; it is wiped by lock.
//   core.historyEncrypt({ store, id, plaintext, counter }) -> { nonce, ct,
//     tag, counter }   store / id: strings (the AAD; no NUL character);
//     plaintext: Uint8Array, 1..65536 bytes; counter: the vault's invocation
//     counter as a decimal string. nonce / ct / tag: Uint8Array, stored
//     SEPARATELY (decision Ek 2); counter: the new value to persist.
//     Refused once the counter reaches 2^32 (SP 800-38D §8.3).
//   core.historyDecrypt({ store, id, nonce, ct, tag }) -> { plaintext }
//     plaintext: Uint8Array; rejects when the record does not authenticate.
//   core.lock()                synchronous; see LOCK above
//
// GROUPS (packages G2 + G3; connect/nc_wasm.c "groups codec" and "groups
// (package G3)", rules in connect/nc_group.h). Bytes are lowercase hex,
// versions / days / millisecond times decimal strings, fingerprints 128 hex.
// No member's, owner's or sender's key is ever passed from here: the module
// takes them from the profiles it verified (profileGet / profileLoad).
//   synchronous (no session key, never suspends):
//     core.groupRandom() -> { group_id, group_key, addr_secret }
//     core.groupSalt(gid, key, v) -> salt_v (hex)
//     core.groupAcceptJson(gid, inviteId) / core.groupLeaveJson(gid) -> json
//     core.groupJsonRead(text) -> { status: 'ok' | 'refused', type, … }
//     core.groupRecordRead({ record, key, gid, v, digest, count, owner })
//   local (the session's keys, no network):
//     core.groupKpNew / groupKpRead / groupRecordNew / groupHeadNew /
//     groupHeadRead / groupMsgNew / groupInvite / groupWelcome
//   network (ONE gated step each; the writes read the own row first, in the
//   same call — nc_wasm.c nc_group_put / nc_group_bucket_send):
//     core.groupGet({ purpose, gid, secret, x, owner }) -> { outcome, why,
//       foreign, data? }   purpose 'head' | 'packet' | 'record'
//     core.groupPut({ purpose, gid, secret, x, value: Uint8Array }) ->
//       { status: 'published' | 'unchanged' | 'wait' | 'stale' |
//         'conflict' | 'taken' | 'failed', outcome, why, putRc }
//     core.groupBucketSend({ gid, salt, v, day, items: [itemHex] }) ->
//       { status: 'published' | 'unchanged' | 'wait' | 'refused' | 'full' |
//         'failed', ids: [message_id] }   items: EVERY own item this device
//       keeps for that bucket
//     core.groupBucketFetch({ gid, salt, v, day, key }) -> { outcome, why,
//       truncated, dropped, buckets: [{ owner, status, sender?, messages:
//       [{ messageId, timestampMs, status, text? }] }] }
//   Large inputs (a packet, a bucket's items) cross through the module's
//   heap input buffer (nc_group_in_alloc), filled and consumed in ONE queue
//   slot.
//
// Queue slots (design §6.4 F7): every async call is ONE bounded network
// step in C (one GET, one GET_ALL or one PUT) — except the gated writes
// profileUpdate, saltReconcile and contactsAdd: a read then at most one
// write (at most two request timeouts; the write must not be split from
// the read it is based on, F4). The history calls and unlock do no network
// I/O. outboxFetchDays (one contact, up to 8 days) and contactReads (up to
// 4 contacts, up to 36 keys, 9 waves of 4) read several keys in one slot;
// their worst-case bounds are in connect/nc_wasm.c's header. A caller that
// syncs many contacts / days must await each step before
// enqueueing the next, so a wallet operation enqueued meanwhile runs between
// two steps and waits at most the step in flight.

const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/, HEX32 = /^[0-9a-f]{32}$/, U64 = /^(0|[1-9]\d{0,19})$/;
export const CONTACT_ACCEPTED_MSG = 'Contact request accepted';
const HISTORY_MAX_BYTES = 65536;           // connect/nc_wasm.c NC_HIST_PT_MAX
const HISTORY_NAME_MAX = 65535;            // connect/nc_history.h NC_HISTORY_NAME_MAX
const lockedError = () => new Error('Wallet is locked.');

// The frozen app's auto-approve rule (dna_engine_contacts.c:555-562, HIGH-7):
// an acceptance is honoured only when this identity has a pending outgoing
// request to that sender. `pendingOutgoing`: a Set of fingerprints.
export function acceptanceMayAutoApprove(request, pendingOutgoing) {
  return !!request && request.acceptance === true && request.message === CONTACT_ACCEPTED_MSG &&
    typeof request.sender === 'string' && HEX128.test(request.sender) &&
    pendingOutgoing instanceof Set && pendingOutgoing.has(request.sender);
}

function fp(value) {
  if (typeof value !== 'string' || !HEX128.test(value)) throw new Error('Invalid Nodus address.');
  return value;
}
function salt(value, { optional = false } = {}) {
  if (optional && (value === null || value === undefined || value === '')) return '';
  if (typeof value !== 'string' || !HEX64.test(value)) throw new Error('Invalid salt.');
  return value;
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
function hexToText(hex) {
  const bytes = hexToBytes(hex);
  try { return new TextDecoder('utf-8', { fatal: false }).decode(bytes); } finally { bytes.fill(0); }
}
// Day buckets one outboxFetchDays call reads at most (connect/nc_core.h
// NC_READ_MANY_MAX).
const OUTBOX_DAYS_MAX = 8;
// Contacts one contactReads call reads at most (connect/nc_core.h
// NC_CONTACT_READS_MAX).
export const CONTACT_READS_MAX = 4;
// A day list of outboxFetchDays / contactReads -> the module's
// [{ day, skip }] (connect/nc_wasm.c nc_outbox_get_days days_json).
function dayList(items) {
  if (!Array.isArray(items) || items.length === 0 || items.length > OUTBOX_DAYS_MAX) throw new Error('Invalid day list.');
  return items.map(item => {
    const day = String(item?.day ?? ''), skip = item?.skipBlob ?? '';
    if (!U64.test(day)) throw new Error('Invalid day.');
    if (typeof skip !== 'string' || (skip !== '' && !HEX64.test(skip))) throw new Error('Invalid blob.');
    return { day, skip };
  });
}
// One day bucket's answer of nc_outbox_get / nc_outbox_get_days, as
// outboxFetchDay returns it.
function dayResult(r) {
  const messages = (r.messages || []).map(m => ({ seq: m.seq, senderTs: m.sender_ts, text: hexToText(m.text_hex) }));
  return { outcome: r.outcome, why: r.why, day: r.day, blob: r.blob, unchanged: r.unchanged === true, dropped: r.dropped, other: r.other, messages };
}
// The AAD names cross into C as NUL-terminated strings (strlen): a NUL
// inside one would silently shorten the AAD, so it is refused here.
function aadName(value, what) {
  if (typeof value !== 'string' || value.includes('\u0000') || new TextEncoder().encode(value).length > HISTORY_NAME_MAX) throw new Error(`Invalid history ${what}.`);
  return value;
}
function recordBytes(value, what, { exact } = {}) {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > HISTORY_MAX_BYTES || (exact !== undefined && value.length !== exact)) throw new Error(`Invalid history ${what}.`);
  return bytesToHex(value);
}

// ── groups (G2 + G3) ───────────────────────────────────────────────────
const GROUP_PURPOSE = { head: 1, packet: 2, record: 3 };
const GROUP_IN_MAX = 1048576;              // connect/nc_wasm.c nc_group_in_alloc (NC_GROUP_BUCKET_MAX)
const GROUP_JSON_MAX = 2048;               // connect/nc_group.h NC_GROUP_JSON_MAX
const HEX = /^[0-9a-f]*$/;
function hexN(value, n, what) {
  if (typeof value !== 'string' || value.length !== n || !HEX.test(value)) throw new Error(`Invalid ${what}.`);
  return value;
}
function hexAny(value, what) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !HEX.test(value)) throw new Error(`Invalid ${what}.`);
  return value;
}
// A decimal u32 (versions, days); `min` 1 for a version.
function dec32(value, what, min = 0) {
  const s = String(value);
  if (!U64.test(s) || BigInt(s) < BigInt(min) || BigInt(s) > 4294967295n) throw new Error(`Invalid ${what}.`);
  return s;
}
function dec64(value, what) {
  const s = String(value);
  if (!U64.test(s)) throw new Error(`Invalid ${what}.`);
  return s;
}
function memberList(list) {
  if (!Array.isArray(list) || list.length === 0 || list.length > 64) throw new Error('Invalid member list.');
  return JSON.stringify(list.map(fp));
}
// Bytes into the module's heap input buffer; consumed by the next export
// called in the same queue slot.
function putIn(b, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > GROUP_IN_MAX) throw new Error('Invalid group data.');
  const at = b.num('nc_group_in_alloc', ['number'], [bytes.length]);
  if (!at) throw new Error('Out of memory.');
  b.heap().set(bytes, at);
}
function purposeOf(name) {
  const p = GROUP_PURPOSE[name];
  if (!p) throw new Error('Invalid group address.');
  return p;
}

export function createNodusConnectCore({ nodus } = {}) {
  if (!nodus || typeof nodus.connect !== 'function' || typeof nodus.connectLocal !== 'function' || typeof nodus.connectSync !== 'function') throw new Error('The Messages module is not available.');
  if (!nodus.localConnectable) throw new Error('Messages is not available in this wallet version, or the wallet is not open.');

  let state = 'idle', stopped = false, started = false, fingerprint;
  let generation = 0, nextRequestId = 1;
  const pending = new Set();

  const bridge = api => {
    const failure = () => new Error(api.str('nc_error') || 'The Messages module failed.');
    const check = rc => { if (rc !== 0) throw failure(); };
    const result = () => JSON.parse(api.str('nc_result'));
    return { ...api, check, result };
  };

  // Every waiting call: stamped, then queued in the WALLET'S queue. A call
  // that reaches the queue after lock() does not touch the module.
  // `local`: an export that needs only the identity (no network), allowed
  // once the wallet client is identified (nodus.connectLocal); every other
  // one needs the client 'ready' (nodus.connect).
  function enqueue(run, { local = false } = {}) {
    if (stopped) return Promise.reject(lockedError());
    const entry = { generation, requestId: nextRequestId++ };
    const promise = new Promise((resolve, reject) => { entry.resolve = resolve; entry.reject = reject; });
    pending.add(entry);
    (local ? nodus.connectLocal : nodus.connect)(async api => {
      if (stopped || entry.generation !== generation) throw lockedError();
      return run(bridge(api));
    }).then(value => {
      // A result from an older generation (a lock happened meanwhile) is dropped.
      if (stopped || entry.generation !== generation) throw lockedError();
      entry.resolve({ ...value, generation: entry.generation, requestId: entry.requestId });
    }).catch(error => entry.reject(stopped ? lockedError() : error))
      .finally(() => pending.delete(entry));
    return promise;
  }
  const ready = () => { if (state !== 'ready') throw new Error('Messages is not connected.'); };
  const op = fn => (...args) => { try { ready(); } catch (error) { return Promise.reject(error); } return enqueue(b => fn(b, ...args)); };
  const localOp = fn => (...args) => { try { ready(); } catch (error) { return Promise.reject(error); } return enqueue(b => fn(b, ...args), { local: true }); };
  const sync = fn => { if (stopped) throw lockedError(); return nodus.connectSync(api => fn(bridge(api))); };

  function lock() {
    if (stopped) return;
    stopped = true;
    generation++;
    for (const entry of pending) entry.reject(lockedError());
    pending.clear();
    fingerprint = undefined;
    // nc_lock is synchronous and never suspends; if the wallet itself is
    // already locked its lock has wiped the Messages state (nsw_lock).
    try { nodus.connectSync(api => api.num('nc_lock')); } catch { /* wallet already locked */ }
    state = 'locked';
  }

  async function unlock({ words, fresh = false } = {}) {
    if (started || stopped) { if (words instanceof Uint8Array) words.fill(0); throw new Error('This Messages connection was already used.'); }
    if (!(words instanceof Uint8Array) || words.length === 0 || words.length > 4096) { if (words instanceof Uint8Array) words.fill(0); throw new Error('Recovery phrase is missing.'); }
    started = true;
    state = 'connecting';
    try {
      const value = await enqueue(async b => {
        const at = b.num('nc_words_alloc', ['number'], [words.length]);
        if (!at) throw new Error('Out of memory.');
        b.heap().set(words, at);
        words.fill(0);
        b.check(await b.call('nc_unlock', ['number'], [fresh === true ? 1 : 0]));
        return b.result();
      }, { local: true });
      if (typeof value.fingerprint !== 'string' || !HEX128.test(value.fingerprint)) throw new Error('The Messages module returned an invalid identity.');
      if (nodus.fingerprint !== undefined && value.fingerprint !== nodus.fingerprint) throw new Error('Messages derived a different address. Nothing was connected.');
      fingerprint = value.fingerprint;
      state = 'ready';
      return { fingerprint, fresh: value.fresh === true };
    } catch (error) {
      if (!stopped) { lock(); state = 'error'; }
      throw error;
    } finally { words.fill(0); }
  }

  return {
    get state() { return state; },
    get fingerprint() { return fingerprint; },
    get generation() { return generation; },
    unlock,
    profileGet: op(async (b, who) => { b.check(await b.call('nc_profile_get', ['string'], [fp(who)])); return b.result(); }),
    profileLoad: localOp(async (b, who, record, name = '') => {
      if (typeof record !== 'string' || record.length === 0 || record.length > 65536 || typeof name !== 'string') throw new Error('Invalid stored profile.');
      b.check(b.num('nc_profile_load', ['string', 'string', 'string'], [fp(who), record, name]));
      return b.result();
    }),
    profileUpdate: op(async (b, patch, { firstOk = false } = {}) => {
      if (!patch || typeof patch !== 'object') throw new Error('Invalid profile edit.');
      b.check(await b.call('nc_profile_update', ['string', 'number'], [JSON.stringify(patch), firstOk === true ? 1 : 0]));
      const r = b.result();
      return { status: r.status, read: r.read, created: r.created, putRc: r.put_rc, version: r.version };
    }),
    requestsFetch: op(async b => { b.check(await b.call('nc_requests_get')); return b.result(); }),
    requestSend: op(async (b, who, message = '') => {
      if (typeof message !== 'string' || new TextEncoder().encode(message).length > 255) throw new Error('Message is too long.');
      b.check(await b.call('nc_request_new', ['string', 'string'], [fp(who), message]));
      return b.result();
    }),
    requestAccept: op(async (b, who, saltHex = null) => { b.check(await b.call('nc_request_approve', ['string', 'string'], [fp(who), salt(saltHex, { optional: true })])); return {}; }),
    requestCancel: op(async (b, who) => { b.check(await b.call('nc_request_withdraw', ['string'], [fp(who)])); return {}; }),
    saltGet: op(async (b, who) => { b.check(await b.call('nc_salt_get', ['string'], [fp(who)])); return b.result(); }),
    saltReconcile: op(async (b, who, localHex = null) => {
      b.check(await b.call('nc_salt_reconcile', ['string', 'string'], [fp(who), salt(localHex, { optional: true })]));
      const r = b.result();
      return { status: r.status, outcome: r.outcome, why: r.why, choice: r.choice, salt: r.salt, putRc: r.put_rc };
    }),
    contactsGet: op(async b => { b.check(await b.call('nc_contacts_get')); return b.result(); }),
    contactsAdd: op(async (b, entries, { firstOk = false } = {}) => {
      if (!Array.isArray(entries) || entries.length === 0 || entries.length > 4096) throw new Error('Invalid contact list.');
      const list = entries.map(e => {
        if (!e) throw new Error('Invalid contact list.');
        return { fp: fp(e.fp), salt: salt(e.salt, { optional: true }) || null };
      });
      b.check(await b.call('nc_contacts_add', ['string', 'number'], [JSON.stringify(list), firstOk === true ? 1 : 0]));
      const r = b.result();
      return { status: r.status, outcome: r.outcome, why: r.why, created: r.created,
        countBefore: r.count_before, countAfter: r.count_after, saltKept: r.salt_kept, putRc: r.put_rc };
    }),
    saltPick(localHex = null, dhtHex = null) {
      return sync(b => {
        b.check(b.num('nc_salt_pick', ['string', 'string'], [salt(localHex, { optional: true }), salt(dhtHex, { optional: true })]));
        return b.result();
      });
    },
    dayToday() { return sync(b => b.str('nc_day_today')); },
    outboxPublish: op(async (b, who, saltHex, messages) => {
      if (!Array.isArray(messages) || messages.length === 0 || messages.length > 1000) throw new Error('Invalid message list.');
      const list = messages.map(m => {
        if (!m || !U64.test(String(m.seq)) || !U64.test(String(m.ts)) || typeof m.text !== 'string') throw new Error('Invalid message list.');
        return { seq: String(m.seq), ts: String(m.ts), text: m.text };
      });
      b.check(await b.call('nc_outbox_send', ['string', 'string', 'string'], [fp(who), salt(saltHex), JSON.stringify(list)]));
      return b.result();
    }),
    outboxFetchDay: op(async (b, who, saltHex, day = '', skipBlob = '') => {
      if (day !== '' && !U64.test(String(day))) throw new Error('Invalid day.');
      if (skipBlob !== '' && !HEX64.test(skipBlob)) throw new Error('Invalid blob.');
      b.check(await b.call('nc_outbox_get', ['string', 'string', 'string', 'string'], [fp(who), salt(saltHex), String(day), skipBlob]));
      return dayResult(b.result());
    }),
    outboxFetchDays: op(async (b, who, saltHex, items) => {
      const list = dayList(items);
      b.check(await b.call('nc_outbox_get_days', ['string', 'string', 'string'], [fp(who), salt(saltHex), JSON.stringify(list)]));
      const days = b.result().days;
      if (!Array.isArray(days) || days.length !== list.length) throw new Error('The Messages module returned an invalid answer.');
      // An object, not the array itself: enqueue spreads the result into
      // the stamped answer ({ ...value, generation, requestId }).
      return { days: days.map(dayResult) };
    }),
    ackPublish: op(async (b, who, saltHex, ackTs) => {
      if (!U64.test(String(ackTs)) || String(ackTs) === '0') throw new Error('Invalid delivery confirmation.');
      b.check(await b.call('nc_ack_send', ['string', 'string', 'string'], [fp(who), salt(saltHex), String(ackTs)]));
      return {};
    }),
    ackGet: op(async (b, who, saltHex) => { b.check(await b.call('nc_ack_get', ['string', 'string'], [fp(who), salt(saltHex)])); return b.result(); }),
    contactReads: op(async (b, items) => {
      if (!Array.isArray(items) || items.length === 0 || items.length > CONTACT_READS_MAX) throw new Error('Invalid contact list.');
      const list = items.map(item => ({ fp: fp(item?.fp), salt: salt(item?.salt), days: dayList(item?.days) }));
      b.check(await b.call('nc_contact_reads', ['string'], [JSON.stringify(list)]));
      const contacts = b.result().contacts;
      if (!Array.isArray(contacts) || contacts.length !== list.length) throw new Error('The Messages module returned an invalid answer.');
      return {
        contacts: contacts.map((c, i) => {
          if (c && typeof c.error === 'string') return { error: c.error };
          if (!c || !c.ack || !Array.isArray(c.days) || c.days.length !== list[i].days.length) throw new Error('The Messages module returned an invalid answer.');
          return { ack: c.ack, days: c.days.map(dayResult) };
        })
      };
    }),
    historyKey: localOp(async (b, vaultIdHex) => {
      if (typeof vaultIdHex !== 'string' || !HEX32.test(vaultIdHex)) throw new Error('Invalid vault id.');
      b.check(b.num('nc_hist_key', ['string'], [vaultIdHex]));
      return {};
    }),
    historyEncrypt: localOp(async (b, { store, id, plaintext, counter } = {}) => {
      if (typeof counter !== 'string' || !U64.test(counter)) throw new Error('Invalid history counter.');
      b.check(b.num('nc_hist_encrypt', ['string', 'string', 'string', 'string'], [aadName(store, 'store'), aadName(id, 'id'), recordBytes(plaintext, 'record'), counter]));
      const r = b.result();
      return { nonce: hexToBytes(r.nonce), ct: hexToBytes(r.ct), tag: hexToBytes(r.tag), counter: r.counter };
    }),
    historyDecrypt: localOp(async (b, { store, id, nonce, ct, tag } = {}) => {
      b.check(b.num('nc_hist_decrypt', ['string', 'string', 'string', 'string', 'string'],
        [aadName(store, 'store'), aadName(id, 'id'), recordBytes(nonce, 'nonce', { exact: 12 }), recordBytes(ct, 'record'), recordBytes(tag, 'tag', { exact: 16 })]));
      return { plaintext: hexToBytes(b.result().pt) };
    }),
    // ── groups: synchronous ──
    groupRandom() { return sync(b => { b.check(b.num('nc_group_random')); return b.result(); }); },
    groupSalt(gid, key, v) {
      return sync(b => {
        b.check(b.num('nc_group_salt', ['string', 'string', 'string'], [hexN(gid, 64, 'group id'), hexN(key, 64, 'group key'), dec32(v, 'key version', 1)]));
        return b.result().salt;
      });
    },
    groupAcceptJson(gid, inviteId) {
      return sync(b => { b.check(b.num('nc_group_accept', ['string', 'string'], [hexN(gid, 64, 'group id'), hexN(inviteId, 32, 'invite')])); return b.result().json; });
    },
    groupLeaveJson(gid) { return sync(b => { b.check(b.num('nc_group_leave', ['string'], [hexN(gid, 64, 'group id')])); return b.result().json; }); },
    // A text that is not a group message (too long, a NUL inside — the C
    // string would end there) is answered 'refused' without the module.
    groupJsonRead(text) {
      if (typeof text !== 'string' || text.includes('\u0000') || new TextEncoder().encode(text).length > GROUP_JSON_MAX) return { status: 'refused' };
      return sync(b => { b.check(b.num('nc_group_json_read', ['string'], [text])); return b.result(); });
    },
    groupRecordRead({ record, key, gid, v, digest, count, owner } = {}) {
      return sync(b => {
        b.check(b.num('nc_group_record_read', ['string', 'string', 'string', 'string', 'string', 'string', 'string'],
          [hexAny(record, 'group record'), hexN(key, 64, 'group key'), hexN(gid, 64, 'group id'), dec32(v, 'key version', 1), hexN(digest, 128, 'record digest'), dec32(count, 'member count', 1), fp(owner)]));
        return b.result();
      });
    },
    // ── groups: local (session keys, no network) ──
    groupKpNew: localOp(async (b, { gid, v, prev = '', rdigest, issued, key, members } = {}) => {
      b.check(b.num('nc_group_kp_new', ['string', 'string', 'string', 'string', 'string', 'string', 'string'],
        [hexN(gid, 64, 'group id'), dec32(v, 'key version', 1), prev === '' ? '' : hexN(prev, 128, 'digest'), hexN(rdigest, 128, 'record digest'), dec64(issued, 'time'), hexN(key, 64, 'group key'), memberList(members)]));
      return b.result();
    }),
    groupKpRead: localOp(async (b, { packet, owner, gid, v, prev = '', pinned = '' } = {}) => {
      b.check(b.num('nc_group_kp_read', ['string', 'string', 'string', 'string', 'string', 'string'],
        [hexAny(packet, 'key packet'), fp(owner), hexN(gid, 64, 'group id'), dec32(v, 'key version', 1), prev === '' ? '' : hexN(prev, 128, 'digest'), pinned === '' ? '' : hexN(pinned, 128, 'digest')]));
      return b.result();
    }),
    groupRecordNew: localOp(async (b, { gid, v, key, name, members, created } = {}) => {
      if (typeof name !== 'string' || name.includes('\u0000') || new TextEncoder().encode(name).length > 64) throw new Error('A group name is at most 64 bytes.');
      b.check(b.num('nc_group_record_new', ['string', 'string', 'string', 'string', 'string', 'string'],
        [hexN(gid, 64, 'group id'), dec32(v, 'key version', 1), hexN(key, 64, 'group key'), name, memberList(members), dec64(created, 'time')]));
      return b.result();
    }),
    groupHeadNew: localOp(async (b, { gid, v, digest, issued } = {}) => {
      b.check(b.num('nc_group_head_new', ['string', 'string', 'string', 'string'], [hexN(gid, 64, 'group id'), dec32(v, 'key version', 1), hexN(digest, 128, 'digest'), dec64(issued, 'time')]));
      return b.result();
    }),
    groupHeadRead: localOp(async (b, { head, owner, gid } = {}) => {
      b.check(b.num('nc_group_head_read', ['string', 'string', 'string'], [hexAny(head, 'group head'), fp(owner), hexN(gid, 64, 'group id')]));
      return b.result();
    }),
    groupMsgNew: localOp(async (b, { key, gid, v, ts, text } = {}) => {
      if (typeof text !== 'string' || text.includes('\u0000')) throw new Error('Invalid message.');
      b.check(b.num('nc_group_msg_new', ['string', 'string', 'string', 'string', 'string'], [hexN(key, 64, 'group key'), hexN(gid, 64, 'group id'), dec32(v, 'key version', 1), dec64(ts, 'time'), text]));
      return b.result();
    }),
    groupInvite: localOp(async (b, gid, name) => {
      if (typeof name !== 'string' || name.includes('\u0000')) throw new Error('Invalid group name.');
      b.check(b.num('nc_group_invite', ['string', 'string'], [hexN(gid, 64, 'group id'), name]));
      return b.result();
    }),
    groupWelcome: localOp(async (b, { gid, addr, v, digest, inviteId } = {}) => {
      b.check(b.num('nc_group_welcome', ['string', 'string', 'string', 'string', 'string'],
        [hexN(gid, 64, 'group id'), hexN(addr, 64, 'group address secret'), dec32(v, 'key version', 1), hexN(digest, 128, 'digest'), hexN(inviteId, 32, 'invite')]));
      return b.result().json;
    }),
    // ── groups: network ──
    groupGet: op(async (b, { purpose, gid, secret, x, owner } = {}) => {
      b.check(await b.call('nc_group_get', ['number', 'string', 'string', 'string', 'string'],
        [purposeOf(purpose), hexN(gid, 64, 'group id'), hexN(secret, 64, 'group secret'), dec64(x, 'group address'), fp(owner)]));
      return b.result();
    }),
    groupPut: op(async (b, { purpose, gid, secret, x, value } = {}) => {
      const args = [purposeOf(purpose), hexN(gid, 64, 'group id'), hexN(secret, 64, 'group secret'), dec64(x, 'group address')];
      putIn(b, value);
      b.check(await b.call('nc_group_put', ['number', 'string', 'string', 'string'], args));
      const r = b.result();
      return { status: r.status, outcome: r.outcome, why: r.why, foreign: r.foreign, putRc: r.put_rc };
    }),
    groupBucketSend: op(async (b, { gid, salt: saltV, v, day, items } = {}) => {
      if (!Array.isArray(items) || items.length === 0 || items.length > 100) throw new Error('Invalid group message list.');
      const args = [hexN(gid, 64, 'group id'), hexN(saltV, 64, 'group salt'), dec32(v, 'key version', 1), dec32(day, 'day')];
      const parts = items.map(item => hexToBytes(hexAny(item, 'group message')));
      const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let at = 0;
      for (const p of parts) { all.set(p, at); at += p.length; }
      putIn(b, all);
      b.check(await b.call('nc_group_bucket_send', ['string', 'string', 'string', 'string'], args));
      const r = b.result();
      return { status: r.status, outcome: r.outcome, why: r.why, count: r.count, putRc: r.put_rc, ids: Array.isArray(r.ids) ? r.ids : [] };
    }),
    groupBucketFetch: op(async (b, { gid, salt: saltV, v, day, key } = {}) => {
      b.check(await b.call('nc_group_bucket_fetch', ['string', 'string', 'string', 'string', 'string'],
        [hexN(gid, 64, 'group id'), hexN(saltV, 64, 'group salt'), dec32(v, 'key version', 1), dec32(day, 'day'), hexN(key, 64, 'group key')]));
      const r = b.result();
      const buckets = (r.buckets || []).map(e => ({
        owner: e.owner, status: e.status, sender: e.sender,
        messages: (e.messages || []).map(m => ({ messageId: m.message_id, timestampMs: m.timestamp_ms, status: m.status, text: m.status === 'ok' && typeof m.text_hex === 'string' ? hexToText(m.text_hex) : undefined }))
      }));
      return { outcome: r.outcome, why: r.why, truncated: r.truncated === true, dropped: r.dropped, buckets };
    }),
    lock
  };
}
