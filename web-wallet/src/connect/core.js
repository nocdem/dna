// Nodus Connect thin core — JS glue (package NC-2 of
// docs/plans/2026-09-24-web-connect-design.md rev 5, §1.1, §1.8, §1.9).
// No UI: the Messages screens are package NC-4.
//
// The C side is web-wallet/connect/ (nc_core.h documents every rule). This
// file adds only what JS must own: ONE operation queue in front of every
// export (Asyncify keeps a single suspended-call state — a second export
// entered while one is suspended corrupts it; design §1.1), the
// (generation, requestId) stamp on every result (§1.9), and the lock order
// (§1.8): stop the queue -> cancel -> lock (WebSocket closed) -> zero the
// whole linear memory -> release the instance.
//
// THE MODULE BUILT BY scripts/build-connect-wasm.sh IS A TEST ARTIFACT: it
// opens its own tier-2 session. In the wallet the same identity already has
// the NODUS send module's session, and two sessions of one identity evict
// each other on a node (nodus_auth.c:95-116). Package NC-4 links the C
// library into the one shared module; this glue then drives that module.
// `loadGlue` is therefore REQUIRED — nothing here imports a module by
// default, and nothing under src/ ships one.
//
// API (every async call runs through the queue; results are plain objects,
// u64 values are decimal strings, bytes are lowercase hex):
//   createNodusConnectCore({ servers, loadGlue }) -> Promise<core>
//     servers: the embedded list, a JSON-serialisable object
//       { format: 'nodus-connect-servers', version: 1,
//         entries: [{ kind: 'validator-checkpoint', pin: <128 hex>,
//                     host?: <IPv4>, port?: 1..65535 }, ...] }
//       (validated in C: nc_servers_parse; unknown kinds are skipped, an
//       empty list connects nowhere).
//   core.unlock({ words, fresh }) -> { fingerprint, fresh }
//     words: Uint8Array of the NORMALISED phrase's UTF-8 bytes (wiped here
//     after the copy; the C copy is wiped on every path). fresh: true ONLY
//     for words this session generated (decision Q1): a restored identity
//     never creates a record.
//   core.profileGet(fp) -> { outcome, why, profile? }
//     outcome 'found' | 'empty' | 'unreadable'. 'empty' is NOT proof of
//     absence (design §2.1). profile.claimed_name is a claim (G9).
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
//   core.dayToday() -> '<unix day>'             synchronous
//   core.outboxSend(fp, saltHex, [{ seq, ts, text }]) -> { day, alg, count }
//     the WHOLE pending set for that contact for today (the blob replaces
//     the previous one); needs profileGet(fp) first.
//   core.outboxGet(fp, saltHex, day?) -> { outcome, why, day, dropped,
//     messages: [{ seq, senderTs, text }] }   senderTs = sender's clock
//   core.ackSend(fp, saltHex)  ONLY after the store transaction's oncomplete
//     (G11) — the sender drops ACKed messages from its blob.
//   core.ackGet(fp, saltHex) -> { outcome, why, ack_ts }
//   core.tick()                keepalive, every NODUS_CONNECT_TICK_MS
//   core.lock()                synchronous; see the lock order above
//
// Queue slots (design §6.4 F7): every async call is ONE bounded network
// step in C (one GET, one GET_ALL or one PUT). A caller that syncs many
// contacts / days must await each step before enqueueing the next, so a
// wallet operation enqueued meanwhile runs between two steps and waits at
// most one request timeout.

const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/, U64 = /^(0|[1-9]\d{0,19})$/;
export const NODUS_CONNECT_TICK_MS = 60000;
export const CONTACT_ACCEPTED_MSG = 'Contact request accepted';
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
function hexToText(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  try { return new TextDecoder('utf-8', { fatal: false }).decode(bytes); } finally { bytes.fill(0); }
}

export async function createNodusConnectCore({ servers, loadGlue } = {}) {
  if (typeof loadGlue !== 'function') throw new Error('The Messages module is not available.');
  const { default: createNodusConnectWasm } = await loadGlue();
  const M = await createNodusConnectWasm({ websocket: { url: 'wss://', subprotocol: 'binary' } });
  const num = (name, types = [], args = []) => M.ccall(name, 'number', types, args);
  const str = (name, types = [], args = []) => M.ccall(name, 'string', types, args);
  const call = (name, types = [], args = []) => M.ccall(name, 'number', types, args, { async: true });
  const failure = () => new Error(str('nc_error') || 'The Messages module failed.');
  const check = rc => { if (rc !== 0) throw failure(); };
  const result = () => JSON.parse(str('nc_result'));

  check(num('nc_net_load', ['string'], [JSON.stringify(servers ?? null)]));

  let state = 'idle', stopped = false, started = false, fingerprint;
  let generation = 0, nextRequestId = 1, tail = Promise.resolve(), inFlight;
  const waiting = new Set();

  // ONE queue. `tail` settles only when the module call itself returned.
  function enqueue(run) {
    if (stopped) return Promise.reject(lockedError());
    const entry = { generation, requestId: nextRequestId++ };
    const promise = new Promise((resolve, reject) => { entry.resolve = resolve; entry.reject = reject; });
    waiting.add(entry);
    tail = tail.then(async () => {
      if (!waiting.delete(entry)) return;
      if (stopped || entry.generation !== generation) { entry.reject(lockedError()); return; }
      inFlight = entry;
      try {
        const value = await run();
        // A result from an older generation (a lock happened meanwhile) is dropped.
        if (stopped || entry.generation !== generation) throw lockedError();
        entry.resolve({ ...value, generation: entry.generation, requestId: entry.requestId });
      } catch (error) { entry.reject(stopped ? lockedError() : error); }
      finally { if (inFlight === entry) inFlight = undefined; }
    });
    return promise;
  }
  const ready = () => { if (state !== 'ready') throw new Error('Messages is not connected.'); };
  const op = fn => (...args) => { try { ready(); } catch (error) { return Promise.reject(error); } return enqueue(() => fn(...args)); };

  function lock() {
    stopped = true;
    generation++;
    for (const entry of waiting) entry.reject(lockedError());
    waiting.clear();
    inFlight?.reject(lockedError()); inFlight = undefined;
    fingerprint = undefined;
    try { M.ccall('nc_cancel', null, [], []); } catch { /* the wipe below must still run */ }
    try { M.ccall('nc_lock', null, [], []); } catch { /* the wipe below must still run */ }
    try { M.HEAPU8.fill(0); } catch { /* release below must still run */ }
    try { M.abort('Nodus Connect module released'); } catch { /* aborted, as intended */ }
    state = 'locked';
  }

  async function unlock({ words, fresh = false } = {}) {
    if (started || stopped) { if (words instanceof Uint8Array) words.fill(0); throw new Error('This Messages connection was already used.'); }
    if (!(words instanceof Uint8Array) || words.length === 0 || words.length > 4096) { if (words instanceof Uint8Array) words.fill(0); throw new Error('Recovery phrase is missing.'); }
    started = true;
    state = 'connecting';
    try {
      const value = await enqueue(async () => {
        const at = num('nc_words_alloc', ['number'], [words.length]);
        if (!at) throw new Error('Out of memory.');
        M.HEAPU8.set(words, at);
        words.fill(0);
        check(await call('nc_unlock', ['number'], [fresh === true ? 1 : 0]));
        return result();
      });
      if (typeof value.fingerprint !== 'string' || !HEX128.test(value.fingerprint)) throw new Error('The Messages module returned an invalid identity.');
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
    tick: op(async () => { check(await call('nc_tick')); return {}; }),
    profileGet: op(async who => { check(await call('nc_profile_get', ['string'], [fp(who)])); return result(); }),
    profileUpdate: op(async patch => {
      if (!patch || typeof patch !== 'object') throw new Error('Invalid profile edit.');
      check(await call('nc_profile_update', ['string'], [JSON.stringify(patch)]));
      const r = result();
      return { status: r.status, read: r.read, created: r.created, putRc: r.put_rc, version: r.version };
    }),
    requestsFetch: op(async () => { check(await call('nc_requests_get')); return result(); }),
    requestSend: op(async (who, message = '') => {
      if (typeof message !== 'string' || new TextEncoder().encode(message).length > 255) throw new Error('Message is too long.');
      check(await call('nc_request_new', ['string', 'string'], [fp(who), message]));
      return result();
    }),
    requestAccept: op(async (who, saltHex = null) => { check(await call('nc_request_approve', ['string', 'string'], [fp(who), salt(saltHex, { optional: true })])); return {}; }),
    requestCancel: op(async who => { check(await call('nc_request_withdraw', ['string'], [fp(who)])); return {}; }),
    saltGet: op(async who => { check(await call('nc_salt_get', ['string'], [fp(who)])); return result(); }),
    saltPick(localHex = null, dhtHex = null) {
      if (stopped) throw lockedError();
      check(num('nc_salt_pick', ['string', 'string'], [salt(localHex, { optional: true }), salt(dhtHex, { optional: true })]));
      return result();
    },
    dayToday() { if (stopped) throw lockedError(); return str('nc_day_today'); },
    outboxSend: op(async (who, saltHex, messages) => {
      if (!Array.isArray(messages) || messages.length === 0 || messages.length > 1000) throw new Error('Invalid message list.');
      const list = messages.map(m => {
        if (!m || !U64.test(String(m.seq)) || !U64.test(String(m.ts)) || typeof m.text !== 'string') throw new Error('Invalid message list.');
        return { seq: String(m.seq), ts: String(m.ts), text: m.text };
      });
      check(await call('nc_outbox_send', ['string', 'string', 'string'], [fp(who), salt(saltHex), JSON.stringify(list)]));
      return result();
    }),
    outboxGet: op(async (who, saltHex, day = '') => {
      if (day !== '' && !U64.test(String(day))) throw new Error('Invalid day.');
      check(await call('nc_outbox_get', ['string', 'string', 'string'], [fp(who), salt(saltHex), String(day)]));
      const r = result();
      const messages = (r.messages || []).map(m => ({ seq: m.seq, senderTs: m.sender_ts, text: hexToText(m.text_hex) }));
      return { outcome: r.outcome, why: r.why, day: r.day, dropped: r.dropped, messages };
    }),
    ackSend: op(async (who, saltHex) => { check(await call('nc_ack_send', ['string', 'string'], [fp(who), salt(saltHex)])); return {}; }),
    ackGet: op(async (who, saltHex) => { check(await call('nc_ack_get', ['string', 'string'], [fp(who), salt(saltHex)])); return result(); }),
    lock
  };
}
