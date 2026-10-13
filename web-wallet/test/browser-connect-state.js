// P7 stage 2 — the Messages history on schema v2, end to end, in a real
// browser: Chromium's REAL IndexedDB and the REAL built module
// (src/nodus/send.wasm, src/connect/core.js, src/connect/store.js). Design
// docs/plans/2026-10-13-connect-core-p7-state-design.md rev 2 §2.2, §2.3,
// §2.5 and rev 2.1.
//
// What it proves:
//   - a v1 database (as store.js kept it before P7: the whole state sealed
//     in the record 'state', with groups, vaults, a kept profile, two
//     contacts, a pending request, ACK values, an ID found only in a per-ID
//     map, listTaken, one message, and the counter record + its
//     localStorage copy) is MIGRATED by openHistoryStore: onMigrate
//     'start' then 'done'; the state handed back equals the v1 state with
//     nextSeq advanced by the four allocated ids (the documented
//     normalisation — every other value was already in canonical form);
//     the database then holds the header and exactly the four 'c…'
//     records, the kept profile / vault / group records and the message
//     unchanged and still opening; the counter (record and copy) grew by
//     exactly the five seals; nothing is dropped;
//   - closed and opened again: v2 is loaded, nothing migrates, the same
//     state;
//   - a save() after moving ONE contact's check time (dmSync) rewrites
//     only that contact's 'c…' record — the header does not hold dmSync, so
//     its bytes are unchanged and it is not rewritten (store.js stateDiff)
//     — and the counter grows by one; reopening gives that state;
//   - rev 2.2 item 2: a save of 38,000 contacts holding only an ID — whose
//     records project fine but whose load input is over the module's 8 MiB
//     bound (checked in the harness first) — is refused with the
//     too-large text (store.js HISTORY_TOO_LARGE_TEXT), hands out no id,
//     writes nothing (same records, nonces, counter and copy), and the next
//     open gives the previous state;
//   - a 'c…' record with one ciphertext bit flipped keeps the history
//     closed (fail closed, §2.5).
// How it mounts: a harness page served by vite (the real sources); the send
// module is created with the network settings present (src/nodus/send-module.js
// NODUS_SEND_NETWORK) and identified from a fixed phrase — no connection is
// made (every request off the dev server is refused and reported). The
// Messages core runs on that module through a minimal client object (one
// serial queue for connect / connectLocal, connectSync direct — the shape
// src/nodus/client.js gives it), not through src/nodus/client.js itself.
// Requires: the built module in src/nodus (scripts/build-nodus-send-wasm.sh
// release), `npm ci`, a Chromium (CHROMIUM_PATH). Run: npm run test:state.
// Leaves behind: nothing (a fresh browser profile).
// How it can lie: it covers the web backend only; the vault id and the
// phrase are fixed test values; the interleavings of two saves and the
// failure paths are covered by test/connect-store.test.js with fakes, not
// here.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const PORT = 4195;
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'], PORT);
const url = server.url;
const harness = `${url}/__state-harness.html`;
// The sites' policy (connect-site/index.html <meta http-equiv>).
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' https: wss:; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'";
const HTML = `<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="${CSP}"><title>Messages state (harness)</title></head><body></body></html>`;
const errors = [], unexpected = [];
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const page = await browser.newPage();
  page.setDefaultTimeout(60000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
    const req = route.request();
    if (req.url() === harness) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: HTML });
    if (req.url().startsWith(`${url}/`) && req.method() === 'GET' && !req.postData()) return route.continue();
    unexpected.push(req.url());
    return route.abort();
  });
  await page.goto(harness);

  // ── module, identity, core, history key; a v1 database written as before P7 ──
  const first = await page.evaluate(async () => {
    const { createNodusSendModule, NODUS_SEND_NETWORK } = await import('/src/nodus/send-module.js');
    const { nodusSigningSeed } = await import('/src/nodus/derive.js');
    const { normalizePhrase } = await import('/src/recovery.js');
    const { createNodusConnectCore } = await import('/src/connect/core.js');
    const S = await import('/src/connect/store.js');
    const PHRASE = normalizePhrase('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art');
    const mod = await createNodusSendModule(NODUS_SEND_NETWORK, {});
    const { fingerprint } = await mod.identify({ seed: nodusSigningSeed(PHRASE) });
    let queue = Promise.resolve();
    const serial = run => { const p = queue.then(() => mod.connect(run)); queue = p.catch(() => {}); return p; };
    const core = createNodusConnectCore({ nodus: { localConnectable: true, fingerprint, connect: serial, connectLocal: serial, connectSync: run => mod.connectSync(run) } });
    await core.unlock({ words: new TextEncoder().encode(PHRASE), fresh: false });

    const VAULT = btoa(String.fromCharCode(...new Uint8Array(16).fill(7)));
    const name = S.databaseNameForVault(VAULT);
    await core.historyKey(name);
    const id = (p, n) => p + String(n).padStart(20, '0');
    const A = 'a1'.repeat(64), B = 'b2'.repeat(64), C = 'c3'.repeat(64), D = 'd4'.repeat(64), E = 'e5'.repeat(64), V = 'f6'.repeat(64), G = '07'.repeat(32);
    const SA = '5a'.repeat(32), SC = '5c'.repeat(32);
    const P = id('p', 10), VR = id('v', 11), GR = id('g', 12), M = id('m', 13);
    const v1 = {
      version: 1, nextSeq: '20',
      contacts: [{ fp: A, salt: SA, listed: true }, { fp: B, salt: null, listed: false }],
      outgoing: [{ fp: C, salt: SC, at: '1791000000' }],
      declined: [{ fp: E, at: '1791000400' }],
      removed: [E],
      acks: { [A]: '1791000100' }, ackSent: { [A]: '1791000050' },
      profileCache: { [A]: { id: P, at: '1791000700', name: 'alice' } },
      dmSync: { [A]: '1791000500' },
      chainNames: { [A]: { name: 'alice', at: '1791000600' } },
      chainNoName: { [D]: '1791000200' },                     // D: an ID found only in a per-ID map
      vaults: { [V]: { id: VR, at: '1791000800' } },
      groups: { [G]: { id: GR, at: '1791000900' } },
      seenOwn: { profile: '1791000300' },
      listTaken: true
    };
    // Sealed and stored as store.js did before P7 (four fields per record,
    // the counter record in the same transaction, its localStorage copy).
    let counter = 0n;
    const seal = async (store, rid, value) => {
      const sealed = await core.historyEncrypt({ store, id: rid, plaintext: S.plaintextBytes(value), counter: counter.toString() });
      counter = BigInt(sealed.counter);
      return [store, S.encodeRecord(rid, sealed)];
    };
    const puts = [
      await seal(S.STORE_STATE, S.STATE_ID, v1),
      await seal(S.STORE_STATE, P, { fp: A, record: '{"kept":"row"}' }),
      await seal(S.STORE_STATE, VR, { address: V, value: { name: 'family' } }),
      await seal(S.STORE_STATE, GR, { gid: G, name: 'friends' }),
      await seal(S.STORE_MESSAGES, M, { seq: '13', fp: A, dir: 'in', text: 'hello', senderTs: '1791000000' })
    ];
    const openDb = () => new Promise((resolve, reject) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => { for (const s of [S.STORE_MESSAGES, S.STORE_STATE, S.STORE_META]) r.result.createObjectStore(s, { keyPath: 'id' }); };
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    const tx = (db, mode, body) => new Promise((resolve, reject) => {
      const t = db.transaction([S.STORE_MESSAGES, S.STORE_STATE, S.STORE_META], mode);
      const out = {};
      body(t, out);
      t.oncomplete = () => resolve(out);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
    const db = await openDb();
    await tx(db, 'readwrite', t => {
      for (const [store, record] of puts) t.objectStore(store).put(record);
      t.objectStore(S.STORE_META).put(S.encodeCounter(counter));
    });
    db.close();
    S.writeStoredCounter(localStorage, name, counter);
    const seeded = counter.toString();

    // What the database holds: record ids, each record's nonce (a rewritten
    // record has a new one), the counter record and its copy.
    const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    const raw = async () => {
      const d = await openDb();
      const out = await tx(d, 'readonly', (t, o) => {
        t.objectStore(S.STORE_STATE).getAll().onsuccess = e => { o.state = e.target.result; };
        t.objectStore(S.STORE_MESSAGES).getAll().onsuccess = e => { o.messages = e.target.result; };
        t.objectStore(S.STORE_META).get(S.COUNTER_ID).onsuccess = e => { o.counter = e.target.result; };
      });
      d.close();
      return {
        stateIds: out.state.map(r => r.id).sort(), messageIds: out.messages.map(r => r.id),
        nonces: Object.fromEntries(out.state.map(r => [r.id, hex(r.nonce)])),
        counter: out.counter?.value, copy: localStorage.getItem(S.counterStorageKey(name))
      };
    };
    // Flips one ciphertext bit of a stored record.
    const tamper = async rid => {
      const d = await openDb();
      await tx(d, 'readwrite', t => {
        t.objectStore(S.STORE_STATE).get(rid).onsuccess = e => { const r = e.target.result; r.ct[0] ^= 1; t.objectStore(S.STORE_STATE).put(r); };
      });
      d.close();
    };

    const steps = [], dropped = [];
    const store = await S.openHistoryStore({ core, vaultId: VAULT, onMigrate: step => steps.push(step), onDropped: paths => dropped.push(paths) });
    const after = await raw();
    const result = {
      v1, seeded, steps, dropped, storeDropped: store.dropped, state: store.state, after,
      profiles: store.profiles.map(p => p.id), vaults: store.vaults.map(v => v.id), groups: store.groupRecords.map(g => g.id), messages: store.messages.map(m => m.text)
    };
    store.close();
    window.__t = { S, core, VAULT, raw, tamper, A };
    return result;
  });

  const id = (p, n) => p + String(n).padStart(20, '0');
  assert.deepEqual(first.steps, ['start', 'done'], 'the v1 state was migrated, with its status');
  assert.deepEqual(first.dropped, [], 'nothing dropped');
  assert.deepEqual(first.storeDropped, []);
  // D1: A, B (contacts), C (pending only), D (map only) -> c20..c23; nextSeq 20 -> 24.
  assert.deepEqual(first.state, { ...first.v1, nextSeq: '24' }, 'the state equals the v1 state, nextSeq advanced by the four ids');
  assert.deepEqual(first.after.stateIds, [id('c', 20), id('c', 21), id('c', 22), id('c', 23), id('g', 12), id('p', 10), 'state', id('v', 11)]);
  assert.deepEqual(first.after.messageIds, [id('m', 13)]);
  assert.equal(first.seeded, '5');
  assert.equal(first.after.counter, '10', 'the counter record grew by exactly the five seals');
  assert.equal(first.after.copy, '10', 'and its copy too');
  assert.deepEqual(first.profiles, [id('p', 10)]);
  assert.deepEqual(first.vaults, [id('v', 11)]);
  assert.deepEqual(first.groups, [id('g', 12)]);
  assert.deepEqual(first.messages, ['hello']);

  // ── reopen: v2 loads, nothing migrates; one contact's check time moved ──
  const second = await page.evaluate(async () => {
    const { S, core, VAULT, raw, A } = window.__t;
    const steps = [];
    const store = await S.openHistoryStore({ core, vaultId: VAULT, onMigrate: step => steps.push(step) });
    const reopened = store.state;
    const before = await raw();
    const next = structuredClone(store.state);
    next.dmSync[A] = '1791009999';
    await store.save(next);
    const after = await raw();
    store.close();
    const again = await S.openHistoryStore({ core, vaultId: VAULT, onMigrate: step => steps.push(step) });
    const changed = Object.keys(after.nonces).filter(k => after.nonces[k] !== before.nonces[k]).sort();
    const result = { steps, reopened, next, againState: again.state, changed, before: before.counter, after: after.counter, copy: after.copy, stateIds: after.stateIds };
    again.close();
    return result;
  });
  assert.deepEqual(second.steps, [], 'a v2 database does not migrate again');
  assert.deepEqual(second.reopened, first.state, 'the same state after reopening');
  assert.deepEqual(second.changed, [id('c', 20)], "only A's known-ID record was rewritten (the header holds no check time)");
  assert.equal(second.before, '10');
  assert.equal(second.after, '11', 'one seal');
  assert.equal(second.copy, '11');
  assert.deepEqual(second.stateIds, first.after.stateIds, 'no record added or deleted');
  assert.deepEqual(second.againState, second.next, 'reopening gives the saved state');

  // ── a save this build could not open again is refused (rev 2.2 item 2) ──
  // 38,000 contacts holding only an ID: projecting them is fine (the input
  // {"state":…,"map":…} is about 5.4 MB), but the LOAD input of the records
  // they project to is over the module's 8 MiB bound. Per such contact the
  // load input grows by 223 B: its record {"fp":"<128>","contact":{}} is
  // 150 B, 156 B once escaped inside the wrapper, plus {"id":"c<20>","json":""}
  // and a comma (41 B), plus its id in the header's ids, escaped (26 B);
  // 8,388,608 / 223 > 37,616, so 38,000 crosses it with room (the
  // ORCHESTRATOR measured 8,474,149 B for 38,000 on the parity build).
  // The harness checks that premise itself before it trusts the refusal.
  const fourth = await page.evaluate(async () => {
    const { S, core, VAULT, raw } = window.__t;
    const store = await S.openHistoryStore({ core, vaultId: VAULT });
    const previous = structuredClone(store.state);
    const big = structuredClone(store.state);
    for (let i = 0; i < 38000; i++) big.contacts.push({ fp: (i + 1).toString(16).padStart(128, '0') });
    const snap = S.stateSnapshot(core, structuredClone(big), {});
    const loadInput = new TextEncoder().encode(JSON.stringify({ header: snap.texts.get(S.STATE_ID), records: [...snap.texts].filter(([rid]) => rid !== S.STATE_ID).map(([rid, json]) => ({ id: rid, json })) })).length;
    const before = await raw();
    const nextSeqBefore = big.nextSeq;
    let refused;
    try { await store.save(big); refused = { saved: true }; }
    catch (error) { refused = { saved: false, storageError: error instanceof S.StorageError, message: error.message }; }
    const after = await raw();
    store.close();
    const again = await S.openHistoryStore({ core, vaultId: VAULT });
    const result = { loadInput, refused, nextSeqBefore, nextSeqAfter: big.nextSeq, before, after, previous, againState: again.state, text: S.HISTORY_TOO_LARGE_TEXT };
    again.close();
    return result;
  });
  assert.ok(fourth.loadInput > 8388608, `the premise: the load input (${fourth.loadInput} B) is over the 8 MiB bound`);
  assert.equal(fourth.refused.saved, false, 'the save is refused');
  assert.equal(fourth.refused.storageError, true, fourth.refused.message);
  assert.equal(fourth.refused.message, fourth.text, 'with the too-large text, not the damaged-history text');
  assert.equal(fourth.nextSeqAfter, fourth.nextSeqBefore, 'no id handed out');
  assert.deepEqual(fourth.after, fourth.before, 'nothing written: the same records, nonces, counter and copy');
  assert.deepEqual(fourth.againState, fourth.previous, 'the next open gives the previous state');

  // ── a known-ID record with one bit flipped: the history stays closed ──
  const third = await page.evaluate(async () => {
    const { S, core, VAULT, tamper } = window.__t;
    await tamper('c00000000000000000021');
    try { const s = await S.openHistoryStore({ core, vaultId: VAULT }); s.close(); return { opened: true }; }
    catch (error) { return { opened: false, storageError: error instanceof S.StorageError, message: error.message }; }
  });
  assert.equal(third.opened, false, 'a tampered known-ID record keeps Messages closed');
  assert.equal(third.storageError, true, third.message);

  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, [], 'no request left the dev server (no connection was made)');
  console.log('Connect state test passed: a v1 history migrates to schema v2 on the real module and IndexedDB (counter + 5), reopens unchanged, a check-time save rewrites one record, a save over the load bound is refused and writes nothing, a tampered record keeps Messages closed.');
} finally {
  await browser?.close();
  server.stop();
}
