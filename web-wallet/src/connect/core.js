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
// NODUS client (src/nodus/client.js createNodusClient, already unlocked) and
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
//     nodus: the wallet's NODUS client, state 'ready', whose module carries
//     the Messages exports (nodus.connectable).
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
//   core.profileUpdate(patch) -> { status, read, created, putRc, version }
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
//     Store `salt` unless status is 'wait'. Needs profileGet(fp) first.
//   core.contactsGet() -> { outcome, why, invalid, timestamp,
//     contacts: [{ fp, salt | null }] }   the own list; 'empty' is NOT proof
//     of absence
//   core.contactsAdd([{ fp, salt? }]) -> { status, outcome, why, created,
//     countBefore, countAfter, saltKept, putRc }   MERGE ONLY into the list
//     read in the same call: status 'published' | 'unchanged' | 'wait'
//     (unreadable, or empty for a restored identity — Q1) | 'taken'
//     (terminal) | 'failed' | 'refused'.
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
// Queue slots (design §6.4 F7): every async call is ONE bounded network
// step in C (one GET, one GET_ALL or one PUT) — except the gated writes
// profileUpdate, saltReconcile and contactsAdd: a read then at most one
// write (at most two request timeouts; the write must not be split from
// the read it is based on, F4). The history calls and unlock do no network
// I/O. A caller that syncs many contacts / days must await each step before
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

export function createNodusConnectCore({ nodus } = {}) {
  if (!nodus || typeof nodus.connect !== 'function' || typeof nodus.connectSync !== 'function') throw new Error('The Messages module is not available.');
  if (!nodus.connectable) throw new Error('Messages is not available in this wallet version, or the wallet is not connected to Nodus.');

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
  function enqueue(run) {
    if (stopped) return Promise.reject(lockedError());
    const entry = { generation, requestId: nextRequestId++ };
    const promise = new Promise((resolve, reject) => { entry.resolve = resolve; entry.reject = reject; });
    pending.add(entry);
    nodus.connect(async api => {
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
      });
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
    profileLoad: op(async (b, who, record, name = '') => {
      if (typeof record !== 'string' || record.length === 0 || record.length > 65536 || typeof name !== 'string') throw new Error('Invalid stored profile.');
      b.check(b.num('nc_profile_load', ['string', 'string', 'string'], [fp(who), record, name]));
      return b.result();
    }),
    profileUpdate: op(async (b, patch) => {
      if (!patch || typeof patch !== 'object') throw new Error('Invalid profile edit.');
      b.check(await b.call('nc_profile_update', ['string'], [JSON.stringify(patch)]));
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
    contactsAdd: op(async (b, entries) => {
      if (!Array.isArray(entries) || entries.length === 0 || entries.length > 4096) throw new Error('Invalid contact list.');
      const list = entries.map(e => {
        if (!e) throw new Error('Invalid contact list.');
        return { fp: fp(e.fp), salt: salt(e.salt, { optional: true }) || null };
      });
      b.check(await b.call('nc_contacts_add', ['string'], [JSON.stringify(list)]));
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
      const r = b.result();
      const messages = (r.messages || []).map(m => ({ seq: m.seq, senderTs: m.sender_ts, text: hexToText(m.text_hex) }));
      return { outcome: r.outcome, why: r.why, day: r.day, blob: r.blob, unchanged: r.unchanged === true, dropped: r.dropped, other: r.other, messages };
    }),
    ackPublish: op(async (b, who, saltHex, ackTs) => {
      if (!U64.test(String(ackTs)) || String(ackTs) === '0') throw new Error('Invalid delivery confirmation.');
      b.check(await b.call('nc_ack_send', ['string', 'string', 'string'], [fp(who), salt(saltHex), String(ackTs)]));
      return {};
    }),
    ackGet: op(async (b, who, saltHex) => { b.check(await b.call('nc_ack_get', ['string', 'string'], [fp(who), salt(saltHex)])); return b.result(); }),
    historyKey: op(async (b, vaultIdHex) => {
      if (typeof vaultIdHex !== 'string' || !HEX32.test(vaultIdHex)) throw new Error('Invalid vault id.');
      b.check(b.num('nc_hist_key', ['string'], [vaultIdHex]));
      return {};
    }),
    historyEncrypt: op(async (b, { store, id, plaintext, counter } = {}) => {
      if (typeof counter !== 'string' || !U64.test(counter)) throw new Error('Invalid history counter.');
      b.check(b.num('nc_hist_encrypt', ['string', 'string', 'string', 'string'], [aadName(store, 'store'), aadName(id, 'id'), recordBytes(plaintext, 'record'), counter]));
      const r = b.result();
      return { nonce: hexToBytes(r.nonce), ct: hexToBytes(r.ct), tag: hexToBytes(r.tag), counter: r.counter };
    }),
    historyDecrypt: op(async (b, { store, id, nonce, ct, tag } = {}) => {
      b.check(b.num('nc_hist_decrypt', ['string', 'string', 'string', 'string', 'string'],
        [aadName(store, 'store'), aadName(id, 'id'), recordBytes(nonce, 'nonce', { exact: 12 }), recordBytes(ct, 'record'), recordBytes(tag, 'tag', { exact: 16 })]));
      return { plaintext: hexToBytes(b.result().pt) };
    }),
    lock
  };
}
