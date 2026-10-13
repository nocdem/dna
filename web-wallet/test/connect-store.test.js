// P7 stage 2 — the Messages storage backend's commit logic (src/connect/
// store.js; design docs/plans/2026-10-13-connect-core-p7-state-design.md
// rev 2 §2.2, §2.3, §2.5 and rev 2.1; Kurultay #19 items 5-7, 10, 13).
//
// What it proves, with a FAKE core and a FAKE IndexedDB modelled at the
// transaction level (fake-indexeddb is not a dependency):
//   - stateDiff: changed or new records are put, known-ID records no longer
//     projected are deleted, the header never;
//   - writeAll: a request that throws while the transaction is being queued
//     aborts it — nothing of it commits (Kurultay #19 item 13);
//   - save(): the state is projected at the CALL (nextSeq written back at
//     once; a mutation after the call does not reach that commit); the run
//     diffs against the last COMMITTED records (an unchanged header is not
//     rewritten, a dropped known ID is deleted); the counter copy is
//     advanced by every seal BEFORE the first seal, the budget is tested on
//     that reserved value, and the counter record is in the same
//     transaction; a failed commit keeps its reservation and the baseline,
//     and the next save carries its changes;
//   - the v1 -> v2 migration: once, after the read, onMigrate start/done,
//     the header and every known-ID record in ONE commit, nothing deleted,
//     the counter grown by exactly N+1, the dropped paths reported; a
//     reopen loads v2 and does not migrate again;
//   - fail closed (§2.5): a listed known-ID record that does not open, or
//     is missing, keeps the history closed.
// Requires: nothing (pure node).
// Leaves behind: nothing.
// How it can lie: the core is a fake — its "projection" is a reversible
// toy, not the codec (that is test_nc_state / test/connect-state-wasm.test.js
// and the end-to-end test/browser-connect-state.js, which runs the real
// module on Chromium's real IndexedDB); the fake IndexedDB orders events
// like the specification (requests, then complete / abort) but is not one.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  openHistoryStore, stateDiff, writeAll, StorageError, DAMAGED_STATE_TEXT, emptyState, counterStorageKey,
  MAX_INVOCATIONS, STATE_ID, STORE_STATE, STORE_MESSAGES, STORE_META, COUNTER_ID
} from '../src/connect/store.js';

const A = 'aa'.repeat(64), B = 'bb'.repeat(64), C = 'cc'.repeat(64);
const VAULT = btoa(String.fromCharCode(...new Uint8Array(16).fill(7)));
const NAME = '07'.repeat(16);
const cid = n => `c${String(n).padStart(20, '0')}`;

// localStorage stand-in; every write is logged into `log`.
function memoryStorage(log = []) {
  const map = new Map();
  return {
    getItem: key => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { log.push(`counter ${value}`); map.set(key, String(value)); },
    removeItem: key => { map.delete(key); },
    map
  };
}

// A minimal IndexedDB: requests answer on a later task, the transaction
// completes (or aborts) after them. `ctl.failCommit`: how many readwrite
// transactions to come fail (onerror, then onabort); `ctl.throwOnOp`: the
// index of the put/delete inside a transaction that throws synchronously.
function fakeIndexedDB(log = []) {
  const dbs = new Map(), ctl = { failCommit: 0, throwOnOp: -1 };
  const later = fn => setTimeout(fn, 0);
  function makeDb(data) {
    const db = {
      objectStoreNames: { contains: s => data.stores.has(s) },
      createObjectStore: s => { data.stores.set(s, new Map()); },
      close() { db.closed = true; },
      transaction(names, mode) {
        if (db.closed) throw new Error('The database connection is closing.');
        const ops = [];
        let aborted = false, opIndex = 0;
        const tx = {
          error: null,
          objectStore(s) {
            const store = data.stores.get(s);
            const request = run => {
              const r = {};
              later(() => { if (!aborted) { r.result = run(); r.onsuccess?.({ target: r }); } });
              return r;
            };
            return {
              getAll: () => request(() => [...store.values()].map(v => structuredClone(v))),
              get: id => request(() => (store.has(id) ? structuredClone(store.get(id)) : undefined)),
              put(record) { if (opIndex++ === ctl.throwOnOp) throw new Error('put refused'); ops.push(['put', s, structuredClone(record)]); },
              delete(id) { if (opIndex++ === ctl.throwOnOp) throw new Error('delete refused'); ops.push(['delete', s, id]); }
            };
          },
          abort() { aborted = true; log.push('abort'); }
        };
        later(() => later(() => {
          if (aborted) { tx.error = { name: 'AbortError', message: 'aborted' }; tx.onabort?.(); return; }
          if (mode === 'readwrite' && ctl.failCommit > 0) {
            ctl.failCommit--;
            tx.error = { name: 'QuotaExceededError', message: 'quota' };
            log.push('commit failed');
            tx.onerror?.(); tx.onabort?.();
            return;
          }
          for (const [kind, s, x] of ops) { if (kind === 'put') data.stores.get(s).set(x.id, x); else data.stores.get(s).delete(x); }
          if (mode === 'readwrite') log.push({ commit: ops.map(([kind, s, x]) => (kind === 'put' ? `put ${s}/${x.id}` : `delete ${s}/${x}`)) });
          tx.oncomplete?.();
        }));
        return tx;
      }
    };
    return db;
  }
  return {
    log, ctl, dbs,
    open(name) {
      const req = {};
      later(() => {
        const fresh = !dbs.has(name);
        if (fresh) dbs.set(name, { stores: new Map() });
        req.result = makeDb(dbs.get(name));
        if (fresh) req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
    deleteDatabase(name) { const req = {}; later(() => { dbs.delete(name); req.onsuccess?.(); }); return req; }
  };
}

// A FAKE core: "sealing" keeps the bytes; the state "projection" is a
// reversible toy with the real call shapes — one known-ID record per
// contact (its salt and check time), everything else in the header, ids
// kept from the map or allocated from nextSeq. A state whose listTaken is
// 'odd' reports the path 'listTaken' as dropped.
function fakeCore(log = []) {
  const tamper = new Set();
  return {
    tamper,
    async historyKey() { return {}; },
    async historyEncrypt({ store, id, plaintext, counter }) {
      log.push(`seal ${store}/${id} @${counter}`);
      return { nonce: new Uint8Array(12).fill(1), ct: plaintext.slice(), tag: new Uint8Array(16).fill(2), counter: String(BigInt(counter) + 1n) };
    },
    async historyDecrypt({ id, ct }) {
      if (tamper.has(id)) throw new Error('The record does not authenticate.');
      return { plaintext: ct.slice() };
    },
    stateProject(v1, map) {
      log.push('project');
      let next = BigInt(v1.nextSeq);
      const records = [];
      for (const c of v1.contacts) {
        const id = map[c.fp] ?? cid(next++);
        records.push({ id, fp: c.fp, json: JSON.stringify({ fp: c.fp, salt: c.salt ?? null, dmSync: v1.dmSync?.[c.fp] ?? null }) });
      }
      records.sort((x, y) => (x.id < y.id ? -1 : 1));
      const { contacts, dmSync, nextSeq, ...rest } = v1;
      const header = JSON.stringify({ version: 2, nextSeq: String(next), ids: records.map(r => r.id), rest });
      return { status: 'ok', nextSeq: String(next), header, records, dropped: v1.listTaken === 'odd' ? ['listTaken'] : [] };
    },
    stateLoad({ header, records }) {
      const h = JSON.parse(header);
      if (h.ids.length !== records.length || h.ids.some((id, i) => records[i].id !== id)) return { status: 'damaged', reason: 'missing record' };
      const recs = records.map(r => JSON.parse(r.json));
      const state = { ...h.rest, nextSeq: h.nextSeq, contacts: recs.map(r => ({ fp: r.fp, salt: r.salt, listed: false })),
        dmSync: Object.fromEntries(recs.filter(r => r.dmSync !== null).map(r => [r.fp, r.dmSync])) };
      return { status: 'ok', state, map: Object.fromEntries(recs.map((r, i) => [r.fp, records[i].id])) };
    }
  };
}

// A "sealed" record as the fake core seals it.
const sealedRecord = (id, value) => ({ id, nonce: new Uint8Array(12).fill(1), ct: new TextEncoder().encode(JSON.stringify(value)), tag: new Uint8Array(16).fill(2) });
const contact = fp => ({ fp, salt: null, listed: false });
const commits = log => log.filter(e => e && e.commit).map(e => e.commit);

async function withFake(run) {
  const saved = globalThis.indexedDB;
  const log = [];
  const idb = fakeIndexedDB(log);
  globalThis.indexedDB = idb;
  try { return await run({ log, idb, core: fakeCore(log), storage: memoryStorage(log) }); }
  finally { globalThis.indexedDB = saved; }
}

test('stateDiff: changed or new records are put, known-ID records gone from the snapshot are deleted, the header never', () => {
  const baseline = new Map([[STATE_ID, 'h1'], [cid(1), 'a'], [cid(2), 'b'], [cid(3), 'c']]);
  const texts = new Map([[STATE_ID, 'h1'], [cid(1), 'a'], [cid(3), 'c2'], [cid(4), 'd']]);
  assert.deepEqual(stateDiff(baseline, texts), { puts: [{ id: cid(3), text: 'c2' }, { id: cid(4), text: 'd' }], deletes: [cid(2)] });
  assert.deepEqual(stateDiff(new Map(), new Map([[STATE_ID, 'h']])), { puts: [{ id: STATE_ID, text: 'h' }], deletes: [] });
  // only 'c…' ids are ever deleted
  assert.deepEqual(stateDiff(new Map([['p00000000000000000001', 'x']]), new Map()).deletes, []);
});

test('writeAll: a request that throws while the transaction is queued aborts it; nothing of it commits', async () => {
  await withFake(async ({ log, idb }) => {
    const db = await new Promise(resolve => { const r = idb.open(NAME); r.onupgradeneeded = () => { for (const s of [STORE_MESSAGES, STORE_STATE, STORE_META]) r.result.createObjectStore(s); }; r.onsuccess = () => resolve(r.result); });
    idb.ctl.throwOnOp = 1;
    const puts = [{ store: STORE_STATE, record: { id: 'a' } }, { store: STORE_STATE, record: { id: 'b' } }];
    await assert.rejects(writeAll(db, puts, [{ store: STORE_STATE, id: 'c' }]), err => err instanceof StorageError && /put refused/.test(err.message));
    assert.ok(log.includes('abort'), 'the transaction was aborted');
    await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(idb.dbs.get(NAME).stores.get(STORE_STATE).size, 0, 'the put queued before the throw did not commit');
    assert.deepEqual(commits(log), []);
    // and a transaction that queues cleanly commits puts and deletes together
    idb.ctl.throwOnOp = -1;
    await writeAll(db, puts, [{ store: STORE_STATE, id: 'a' }]);
    assert.deepEqual(commits(log), [['put state/a', 'put state/b', 'delete state/a']]);
  });
});

test('save: projected at the call (nextSeq written back at once), reserved before the first seal, ONE transaction with the counter record', async () => {
  await withFake(async ({ log, core, storage }) => {
    const store = await openHistoryStore({ core, vaultId: VAULT, storage });
    assert.deepEqual(store.state, emptyState(), 'a new database: the empty state, nothing written');
    assert.deepEqual(commits(log), []);
    const state = structuredClone(store.state);
    state.contacts.push(contact(A));
    log.length = 0;
    const saving = store.save(state);
    assert.equal(state.nextSeq, '2', 'the id allocated for A advances nextSeq before save() yields');
    // A change after the call does not reach this commit.
    state.contacts.push(contact(B));
    await saving;
    assert.deepEqual(log.filter(e => typeof e === 'string'), ['project', 'counter 2', `seal state/state @0`, `seal state/${cid(1)} @1`]);
    assert.deepEqual(commits(log), [[`put state/state`, `put state/${cid(1)}`, 'put meta/counter']]);
    assert.equal(storage.getItem(counterStorageKey(NAME)), '2');
    // The next save carries B (and only what changed: the header and B's record).
    log.length = 0;
    await store.save(state);
    assert.equal(state.nextSeq, '3');
    assert.deepEqual(commits(log), [[`put state/state`, `put state/${cid(2)}`, 'put meta/counter']]);
    assert.ok(log.includes('counter 4'));
  });
});

test('save: an unchanged header is not rewritten; a known ID no longer projected is deleted with the header that drops it', async () => {
  await withFake(async ({ log, core, storage }) => {
    const store = await openHistoryStore({ core, vaultId: VAULT, storage });
    const state = structuredClone(store.state);
    state.contacts.push(contact(A), contact(B));
    await store.save(state);
    log.length = 0;
    state.dmSync[A] = '1791500000';
    await store.save(state);
    assert.deepEqual(commits(log), [[`put state/${cid(1)}`, 'put meta/counter']], 'only A\'s record (and the counter)');
    log.length = 0;
    state.contacts = [contact(A)];
    await store.save(state);
    assert.deepEqual(commits(log), [['put state/state', 'put meta/counter', `delete state/${cid(2)}`]]);
    // Nothing changed: nothing sealed, nothing written.
    log.length = 0;
    await store.save(state);
    assert.deepEqual(log.filter(e => typeof e !== 'string' || !e.startsWith('project')), []);
  });
});

test('save: a failed commit keeps its reservation and the committed baseline; the next save carries its changes', async () => {
  await withFake(async ({ log, idb, core, storage }) => {
    const store = await openHistoryStore({ core, vaultId: VAULT, storage });
    const state = structuredClone(store.state);
    state.contacts.push(contact(A));
    await store.save(state);                                   // counter 2
    idb.ctl.failCommit = 1;
    state.dmSync[A] = '5';
    log.length = 0;
    await assert.rejects(store.save(state), err => err instanceof StorageError && /could not be saved/.test(err.message));
    assert.ok(log.includes('commit failed'));
    assert.equal(storage.getItem(counterStorageKey(NAME)), '3', 'the reservation stays used');
    // Nothing changed since, yet A's record is written again: the baseline
    // is what is really committed. The seal starts after the burned number.
    log.length = 0;
    await store.save(state);
    assert.deepEqual(log.filter(e => typeof e === 'string' && e.startsWith('seal')), [`seal state/${cid(1)} @3`]);
    assert.deepEqual(commits(log), [[`put state/${cid(1)}`, 'put meta/counter']]);
    assert.equal(storage.getItem(counterStorageKey(NAME)), '4');
  });
});

test('save: the budget is tested on the reserved value — past it nothing is reserved, sealed or written', async () => {
  await withFake(async ({ log, core, storage }) => {
    storage.setItem(counterStorageKey(NAME), (MAX_INVOCATIONS - 1n).toString());
    const store = await openHistoryStore({ core, vaultId: VAULT, storage });
    const state = structuredClone(store.state);
    state.contacts.push(contact(A));                         // header + A = 2 seals: one too many
    log.length = 0;
    await assert.rejects(store.save(state), /maximum number of messages/);
    assert.deepEqual(log, ['project']);
    assert.equal(storage.getItem(counterStorageKey(NAME)), (MAX_INVOCATIONS - 1n).toString());
  });
});

test('save: refused at the call once the store is closed; nothing projected', async () => {
  await withFake(async ({ log, core, storage }) => {
    const store = await openHistoryStore({ core, vaultId: VAULT, storage });
    store.close();
    log.length = 0;
    const state = emptyState();
    await assert.rejects(store.save(state), /closed/);
    assert.deepEqual(log, []);
  });
});

// A v1 database as store.js kept it before P7: the whole state in 'state',
// a kept profile, one message and the counter record.
function seedV1(idb, v1, counter = '10') {
  const stores = new Map([[STORE_MESSAGES, new Map()], [STORE_STATE, new Map()], [STORE_META, new Map()]]);
  stores.get(STORE_STATE).set(STATE_ID, sealedRecord(STATE_ID, v1));
  stores.get(STORE_STATE).set('p00000000000000000003', sealedRecord('p00000000000000000003', { fp: A, record: '{"row":1}' }));
  stores.get(STORE_MESSAGES).set('m00000000000000000004', sealedRecord('m00000000000000000004', { seq: '4', fp: A, dir: 'in', text: 'hi' }));
  stores.get(STORE_META).set(COUNTER_ID, { id: COUNTER_ID, value: counter });
  idb.dbs.set(NAME, { stores });
}

test('migration: a v1 state migrates once after the read — header and every known-ID record in ONE commit, nothing deleted, counter + N+1', async () => {
  await withFake(async ({ log, idb, core, storage }) => {
    const v1 = { ...emptyState(), nextSeq: '5', contacts: [contact(A), contact(B)], profileCache: { [A]: { id: 'p00000000000000000003', at: '1', name: '' } }, listTaken: 'odd' };
    seedV1(idb, v1);
    const steps = [], dropped = [];
    const store = await openHistoryStore({ core, vaultId: VAULT, storage, onMigrate: step => steps.push(step), onDropped: paths => dropped.push(paths) });
    assert.deepEqual(steps, ['start', 'done']);
    assert.deepEqual(store.dropped, ['listTaken']);
    assert.deepEqual(dropped, [['listTaken']]);
    assert.deepEqual(commits(log), [[`put state/state`, `put state/${cid(5)}`, `put state/${cid(6)}`, 'put meta/counter']], 'one commit, nothing deleted');
    assert.equal(storage.getItem(counterStorageKey(NAME)), '13', '10 + 3 seals, reserved before the first');
    assert.equal(idb.dbs.get(NAME).stores.get(STORE_META).get(COUNTER_ID).value, '13');
    assert.ok(idb.dbs.get(NAME).stores.get(STORE_STATE).has('p00000000000000000003'), 'the kept profile record stays');
    assert.equal(store.state.nextSeq, '7');
    assert.deepEqual(store.state.contacts.map(c => c.fp), [A, B]);
    assert.equal(store.profiles.length, 1, 'the kept profile still opens');
    assert.equal(store.messages.length, 1, 'the message still opens');
    store.close();
    // Reopen: v2 is loaded, nothing migrates or is written again.
    log.length = 0;
    steps.length = 0;
    const again = await openHistoryStore({ core, vaultId: VAULT, storage, onMigrate: step => steps.push(step) });
    assert.deepEqual(steps, []);
    assert.deepEqual(commits(log), []);
    assert.deepEqual(again.state, store.state);
    assert.deepEqual(again.dropped, []);
    // A save after the migration keeps the ids (the loaded map).
    log.length = 0;
    const state = structuredClone(again.state);
    state.dmSync[B] = '9';
    await again.save(state);
    assert.deepEqual(commits(log), [[`put state/${cid(6)}`, 'put meta/counter']]);
  });
});

test('v2 open fails closed: a listed known-ID record that does not open, or is missing, keeps the history closed', async () => {
  await withFake(async ({ idb, core, storage }) => {
    seedV1(idb, { ...emptyState(), nextSeq: '5', contacts: [contact(A), contact(B)] });
    (await openHistoryStore({ core, vaultId: VAULT, storage })).close();
    core.tamper.add(cid(6));
    await assert.rejects(openHistoryStore({ core, vaultId: VAULT, storage }), err => err instanceof StorageError);
    core.tamper.clear();
    idb.dbs.get(NAME).stores.get(STORE_STATE).delete(cid(5));
    await assert.rejects(openHistoryStore({ core, vaultId: VAULT, storage }), err => err instanceof StorageError && err.message === DAMAGED_STATE_TEXT);
  });
});

test('migration refuses what checkState refuses: the history stays closed and nothing is written', async () => {
  await withFake(async ({ log, idb, core, storage }) => {
    seedV1(idb, { ...emptyState(), nextSeq: 'x' });
    const steps = [];
    await assert.rejects(openHistoryStore({ core, vaultId: VAULT, storage, onMigrate: step => steps.push(step) }), err => err.message === DAMAGED_STATE_TEXT);
    assert.deepEqual(steps, []);
    assert.deepEqual(commits(log), []);
    assert.equal(storage.getItem(counterStorageKey(NAME)), null);
  });
});

test('save: the dropped paths of a projection are reported; C is a third contact allocated after the others', async () => {
  await withFake(async ({ core, storage }) => {
    const seen = [];
    const store = await openHistoryStore({ core, vaultId: VAULT, storage, onDropped: paths => seen.push(paths) });
    const state = structuredClone(store.state);
    state.contacts.push(contact(A), contact(B), contact(C));
    state.listTaken = 'odd';
    await store.save(state);
    assert.deepEqual(seen, [['listTaken']]);
    assert.equal(state.nextSeq, '4');
  });
});
