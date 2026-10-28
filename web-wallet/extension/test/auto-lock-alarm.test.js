import test from 'node:test';
import assert from 'node:assert/strict';
import { AUTO_LOCK_KEY, AUTO_LOCK_CHOICES, AUTO_LOCK_DEFAULT } from '../../src/auto-lock.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { AUTO_LOCK_TIMEOUT_ALARM, createAutoLockAlarm } from '../src/background/auto-lock-alarm.js';

function memoryStorage(initial = {}) {
  const values = structuredClone(initial), writes = [];
  return {
    values, writes,
    async get(key) { return Object.hasOwn(values, key) ? { [key]: values[key] } : {}; },
    async set(items) { writes.push(structuredClone(items)); Object.assign(values, structuredClone(items)); },
    async remove(key) { delete values[key]; },
  };
}
function fakeAlarms() {
  const scheduled = new Map(), calls = [], listeners = new Set();
  return {
    scheduled, calls,
    async create(name, info) { calls.push(['create', name, { ...info }]); scheduled.set(name, { ...info }); },
    async clear(name) { calls.push(['clear', name]); return scheduled.delete(name); },
    onAlarm: { addListener(listener) { listeners.add(listener); }, removeListener(listener) { listeners.delete(listener); } },
    async fire(name) { for (const listener of listeners) await listener({ name }); },
  };
}
async function setup(initial = {}) {
  const storage = memoryStorage(initial), alarms = fakeAlarms(), lockCoordinator = createLockCoordinator();
  await lockCoordinator.unlock(async () => {});
  const controller = await createAutoLockAlarm({ storage, alarms, lockCoordinator });
  return { storage, alarms, lockCoordinator, controller };
}

// Proves the production default and reference alarm parameters; counting creations alone could accept a wrong timeout or a page timer.
test('missing preference arms the default background alarm', async () => {
  const { storage, alarms, controller } = await setup();
  assert.equal(controller.minutes, AUTO_LOCK_DEFAULT);
  assert.equal(AUTO_LOCK_DEFAULT, 15);
  assert.deepEqual(alarms.calls, [['clear', AUTO_LOCK_TIMEOUT_ALARM], ['create', AUTO_LOCK_TIMEOUT_ALARM, { delayInMinutes: 15, periodInMinutes: 15 }]]);
  assert.deepEqual(storage.values, {});
});

// Proves every stored choice uses the existing key and 0 creates no alarm; checking only the final map could miss create-then-clear for never.
test('stored web-wallet choices including never are honored', async () => {
  assert.deepEqual(AUTO_LOCK_CHOICES, [5, 10, 15, 30, 60, 0]);
  for (const minutes of AUTO_LOCK_CHOICES) {
    const { alarms, controller } = await setup({ [AUTO_LOCK_KEY]: String(minutes) });
    assert.equal(controller.minutes, minutes);
    assert.equal(alarms.calls.filter(([kind]) => kind === 'create').length, minutes === 0 ? 0 : 1);
    if (minutes) assert.deepEqual(alarms.scheduled.get(AUTO_LOCK_TIMEOUT_ALARM), { delayInMinutes: minutes, periodInMinutes: minutes });
    else assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false);
  }
});

// Proves malformed or unreadable preferences fail to 15 rather than never; testing only missing storage would miss read failures and coercion.
test('invalid and unreadable stored preferences use the web-wallet default', async () => {
  for (const value of [null, '', 'garbage', '05', '7', ' 0', 0, 5]) {
    const { controller } = await setup({ [AUTO_LOCK_KEY]: value });
    assert.equal(controller.minutes, 15);
  }
  const alarms = fakeAlarms(), lockCoordinator = createLockCoordinator();
  const storage = { async get() { throw new Error('denied'); } };
  const controller = await createAutoLockAlarm({ storage, alarms, lockCoordinator });
  assert.equal(controller.minutes, 15);
  assert.equal(alarms.scheduled.get(AUTO_LOCK_TIMEOUT_ALARM).delayInMinutes, 15);
});

// Proves selected values persist as web-wallet strings and choosing 0 clears an existing alarm; an initially-empty map would hide a failed clear.
test('setting minutes persists only the preference and choosing never cancels the current alarm', async () => {
  const { storage, alarms, controller } = await setup();
  assert.equal(await controller.setMinutes(30), true);
  assert.deepEqual(storage.values, { [AUTO_LOCK_KEY]: '30' });
  assert.equal(alarms.scheduled.get(AUTO_LOCK_TIMEOUT_ALARM).delayInMinutes, 30);
  const created = alarms.calls.filter(([kind]) => kind === 'create').length;
  assert.equal(await controller.setMinutes(0), true);
  assert.deepEqual(storage.values, { [AUTO_LOCK_KEY]: '0' });
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false);
  const ui = controller.openTrustedInterface();
  await ui.activity();
  assert.equal(alarms.calls.filter(([kind]) => kind === 'create').length, created);
  assert.equal(await controller.setMinutes(7), false);
  assert.equal(controller.minutes, 0);
  assert.deepEqual(storage.writes, [{ [AUTO_LOCK_KEY]: '30' }, { [AUTO_LOCK_KEY]: '0' }]);
});

// Proves refused preference persistence still applies for this worker like writeAutoLock; merely checking false could leave the old timer active.
test('a failed preference write keeps the selected timeout for this worker', async () => {
  const { storage, alarms, controller } = await setup();
  storage.set = async () => { throw new Error('denied'); };
  assert.equal(await controller.setMinutes(10), false);
  assert.equal(controller.minutes, 10);
  assert.equal(alarms.scheduled.get(AUTO_LOCK_TIMEOUT_ALARM).delayInMinutes, 10);
});

// Proves trusted activity resets and an unrelated background event does not; checking unchanged delay alone could miss a missing reset.
test('only a trusted interface activity handle resets inactivity', async () => {
  const { alarms, lockCoordinator, controller } = await setup({ [AUTO_LOCK_KEY]: '5' });
  const ui = controller.openTrustedInterface(), before = alarms.calls.length;
  await alarms.fire('site-rpc-traffic');
  assert.equal(alarms.calls.length, before);
  lockCoordinator.assertUnlocked();
  assert.equal(await ui.activity(), true);
  assert.deepEqual(alarms.calls.slice(before), [['clear', AUTO_LOCK_TIMEOUT_ALARM], ['create', AUTO_LOCK_TIMEOUT_ALARM, { delayInMinutes: 5, periodInMinutes: 5 }]]);
});

// Proves closing every trusted interface preserves expiry and disposes every holder; calling lock directly would falsely bypass the alarm listener.
test('interface close keeps the alarm and expiry runs the one lock operation', async () => {
  const { alarms, lockCoordinator, controller } = await setup({ [AUTO_LOCK_KEY]: '10' }), calls = [];
  for (const name of ['tron', 'solana', 'nodus', 'webWallet', 'keyring']) lockCoordinator.register(name, { lock() { calls.push(name); } });
  const popup = controller.openTrustedInterface(), notification = controller.openTrustedInterface();
  await popup.activity();
  const before = alarms.calls.length;
  popup.close(); notification.close();
  assert.equal(alarms.calls.length, before);
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), true);
  assert.equal(await popup.activity(), false);
  assert.equal(await notification.activity(), false);
  assert.equal(alarms.calls.length, before);
  await alarms.fire(AUTO_LOCK_TIMEOUT_ALARM);
  assert.deepEqual(calls, ['keyring', 'webWallet', 'nodus', 'solana', 'tron']);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false);
});

// Proves alarm lock survives a rejecting holder and blocks queued signing; testing only manual lock would miss alarm-to-coordinator wiring.
test('expiry blocks queued signing even when a holder fails', async () => {
  const { alarms, lockCoordinator } = await setup(), calls = [];
  lockCoordinator.register('keyring', { lock() { calls.push('keyring'); throw new Error('failed'); } });
  lockCoordinator.register('tron', { lock() { calls.push('tron'); } });
  let release, signed = false;
  const queued = new Promise(resolve => { release = resolve; }).then(() => { lockCoordinator.assertUnlocked(); signed = true; });
  const rejected = assert.rejects(queued, /locked/);
  await alarms.fire(AUTO_LOCK_TIMEOUT_ALARM);
  release(); await rejected;
  assert.equal(signed, false);
  assert.deepEqual(calls, ['keyring', 'tron']);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false);
});

// Proves overlapping activity resets finish with an armed alarm; immediately-resolving fake APIs alone could hide interleaved clear/create calls.
test('concurrent trusted activity serializes asynchronous alarm resets', async () => {
  const { alarms, controller } = await setup(), ui = controller.openTrustedInterface();
  const clear = alarms.clear.bind(alarms);
  let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  alarms.clear = async name => { await new Promise(resolve => { release = resolve; entered(); }); return clear(name); };
  const first = ui.activity();
  await started;
  const second = ui.activity();
  alarms.clear = clear;
  release();
  assert.equal(await first, true);
  assert.equal(await second, true);
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), true);
  assert.deepEqual(alarms.calls.slice(-4).map(([kind]) => kind), ['clear', 'create', 'clear', 'create']);
});

// Proves expiry closes signing before a slow preference write settles; awaiting fire() alone could hide a signing window while it is queued.
test('expiry locks immediately while a preference write is pending', async () => {
  const { storage, alarms, controller, lockCoordinator } = await setup();
  let release, entered;
  const writing = new Promise(resolve => { entered = resolve; });
  storage.set = async () => { entered(); await new Promise(resolve => { release = resolve; }); };
  const setting = controller.setMinutes(30);
  await writing;
  const expiring = alarms.fire(AUTO_LOCK_TIMEOUT_ALARM);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
  release();
  await setting;
  await expiring;
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false);
});

// Proves trusted activity rearms after expiry and a later unlock; testing only the first alarm would miss an unusable post-lock activity handle.
test('trusted activity rearms inactivity after an expiry and another unlock', async () => {
  const { alarms, controller, lockCoordinator } = await setup();
  const ui = controller.openTrustedInterface();
  await alarms.fire(AUTO_LOCK_TIMEOUT_ALARM);
  assert.equal(alarms.scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false);
  await lockCoordinator.unlock(async () => {});
  await ui.activity();
  assert.equal(alarms.scheduled.get(AUTO_LOCK_TIMEOUT_ALARM).delayInMinutes, 15);
  await alarms.fire(AUTO_LOCK_TIMEOUT_ALARM);
  assert.throws(() => lockCoordinator.assertUnlocked(), /locked/);
});
