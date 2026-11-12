// Real worker Connect wrapper; injected session/storage model slow and failed
// operations deterministically. No browser/network/credentials/files or flags.
// This proves lifecycle/capability boundaries and counter ordering, not native
// crypto or actual IndexedDB durability; those need packaged browser coverage.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createConnect } from '../src/background/connect.js';
import { counterStorageKey, MAX_INVOCATIONS } from '../../src/connect/store.js';

const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
function fixture(options = {}) {
  const instances = [], events = [], values = {};
  const storage = { async get(key) { return { [key]: values[key] }; }, async set(next) { Object.assign(values, next); }, async remove(key) { delete values[key]; } };
  let changed = 0;
  const connect = createConnect({ storage, onChange() { changed++; }, ...options,
    sessionFactory(config) {
      const index = instances.length;
      const s = { config, closed: false, readyClients: [], calls: [],
        async open(detail) { s.detail = detail; events.push(`open:${index}`); await options.open?.(s); },
        close() { s.closed = true; events.push(`close:${index}`); options.close?.(s); },
        ready({ client }) { s.readyClients.push(client); },
        unread() { return options.unread ?? { count: 42, caughtUp: true }; },
        snapshot() { return { phase: 'open', ownFp: s.detail.client.fp, contacts: [], messages: [] }; },
        async action(name, fields) { s.calls.push({ name, fields }); return options.action ? options.action(s, name, fields) : { accepted: true }; },
        walletExtension: { nodusSent(detail) { events.push(detail); } },
      };
      instances.push(s); return s;
    }
  });
  return { connect, instances, events, values, storage, get changed() { return changed; } };
}

test('one worker session survives UI reads; ready/open for the same client does not reopen it', async () => {
  const f = fixture(), client = { fp: 'first' };
  await f.connect.open({ client });
  const state = f.connect.getState();
  await f.connect.open({ client });
  assert.deepEqual(f.connect.getState(), state);
  assert.equal(f.instances.length, 1);
  f.connect.ready({ fp: 'unrelated' });
  assert.deepEqual(f.instances[0].readyClients, []);
  f.connect.ready(client);
  assert.deepEqual(f.instances[0].readyClients, [client]);
  f.connect.close();
  const before = f.changed;
  f.instances[0].config.onChange();
  assert.equal(f.changed, before, 'Closed session callbacks cannot invalidate the new UI');
});

// Proves the worker wrapper hands the toolbar badge the open session's own unread value, and the closed value
// ({ count: 0, caughtUp: false }) before the first open and after a lock. A fake session without `unread` would
// pass the closed half only; the fixture's session returns a distinctive value (42, then an injected 7), so a wrapper that
// invented its own number or kept the value after close() fails.
test('unread() returns the open session value and the closed value otherwise', async () => {
  const closed = { count: 0, caughtUp: false }, f = fixture();
  assert.deepEqual(f.connect.unread(), closed, 'before any session');
  await f.connect.open({ client: { fp: 'first' } });
  assert.deepEqual(f.connect.unread(), { count: 42, caughtUp: true });
  f.connect.close();
  assert.deepEqual(f.connect.unread(), closed, 'after the lock');
  const g = fixture({ unread: { count: 7, caughtUp: false } });
  await g.connect.open({ client: { fp: 'second' } });
  assert.deepEqual(g.connect.unread(), { count: 7, caughtUp: false });
  g.connect.close();
});

test('reconnect closes the prior core before opening the next; stale actions and callbacks cannot cross epochs', async () => {
  const action = deferred(), f = fixture({ action: () => action.promise });
  await f.connect.open({ client: { fp: 'first' } });
  const epoch = f.connect.getState().epoch;
  const pending = f.connect.action(epoch, 'messageSend', { fp: 'peer', text: 'waiting' });
  const rejected = assert.rejects(pending, /closed/);
  await f.connect.open({ client: { fp: 'second' } });
  assert.deepEqual(f.events, ['open:0', 'close:0', 'open:1']);
  const replacement = f.connect.getState();
  f.connect.close(f.instances[0].detail.client);
  assert.deepEqual(f.connect.getState(), replacement, 'A late old-client lock cannot close its replacement');
  action.resolve({ oldConversation: 'must not escape' });
  await rejected;
  const before = f.changed;
  f.instances[0].config.onChange();
  assert.equal(f.changed, before);
  await assert.rejects(f.connect.action(epoch, 'sync', {}), /closed/);
  assert.equal(f.instances[1].calls.length, 0);
  assert.equal(f.connect.getState().ownFp, 'second');
  f.connect.close();
});

test('lock during asynchronous open remains closed when that open completes', async () => {
  const gate = deferred(), f = fixture({ open: () => gate.promise });
  const opening = f.connect.open({ client: { fp: 'first' } });
  f.connect.close();
  const state = f.connect.getState(), changes = f.changed;
  gate.resolve(); await opening;
  assert.deepEqual(f.connect.getState(), state);
  assert.equal(f.changed, changes);
  assert.equal(state.ownFp, null);
  assert.deepEqual(state.messages, []);
  await assert.rejects(f.connect.action(state.epoch, 'sync', {}), /closed/);
});

test('worker independently rejects undeclared and malformed actions before session dispatch', async () => {
  const f = fixture(); await f.connect.open({ client: { fp: 'first' } });
  const epoch = f.connect.getState().epoch;
  for (const name of ['__proto__', 'constructor', 'connectSync', 'unlock', 'getRecoveryPhrase', 'historyEncrypt', null, {}]) {
    await assert.rejects(f.connect.action(epoch, name, {}), /Invalid/);
  }
  for (const fields of [null, [], 'text', 7]) await assert.rejects(f.connect.action(epoch, 'sync', fields), /Invalid/);
  assert.equal(f.instances[0].calls.length, 0);
  await f.connect.action(epoch, 'sync', {});
  assert.deepEqual(f.instances[0].calls, [{ name: 'sync', fields: {} }]);
  f.connect.close();
});

test('counter adapter refuses corruption, accepts the exact budget, and reports write failures', async () => {
  const f = fixture(); await f.connect.open({ client: { fp: 'first' } });
  const adapter = f.instances[0].config.counterStorage, key = counterStorageKey('fixture');
  assert.equal(await adapter.read('fixture'), 0n);
  for (const corrupt of [null, 1, '-1', '01', '1.0', '1e3', '', (MAX_INVOCATIONS + 1n).toString()]) {
    f.values[key] = corrupt;
    await assert.rejects(adapter.read('fixture'), /damaged/);
  }
  await adapter.write('fixture', MAX_INVOCATIONS);
  assert.equal(f.values[key], MAX_INVOCATIONS.toString());
  assert.equal(await adapter.read('fixture'), MAX_INVOCATIONS);
  for (const invalid of [-1n, MAX_INVOCATIONS + 1n, 4, '4']) await assert.rejects(adapter.write('fixture', invalid), /Invalid counter/);
  f.storage.set = async () => { throw new Error('quota failure'); };
  await assert.rejects(adapter.write('fixture', 7n), /counter could not be stored/);
  f.connect.close();
});

test('saved-wallet deletion closes first and serializes counter removal after pending writes', async () => {
  const events = [], gate = deferred();
  const f = fixture({ async deleteHistory(id, webStorage, counter) {
    assert.equal(f.instances[0].closed, true);
    assert.equal(id, 'vault-id'); assert.equal(webStorage, undefined);
    events.push('delete-database'); await counter.remove('fixture'); events.push('deleted');
  } });
  await f.connect.open({ client: { fp: 'first' } });
  f.storage.set = async () => { events.push('write-start'); await gate.promise; events.push('write-end'); };
  f.storage.remove = async () => { events.push('counter-remove'); };
  const writing = f.instances[0].config.counterStorage.write('fixture', 1n);
  await turn();
  const deleting = f.connect.deleteHistory('vault-id');
  await turn();
  assert.deepEqual(events, ['write-start', 'delete-database']);
  assert.equal(f.connect.getState().ownFp, null);
  gate.resolve(); await Promise.all([writing, deleting]);
  assert.deepEqual(events, ['write-start', 'delete-database', 'write-end', 'counter-remove', 'deleted']);
});
