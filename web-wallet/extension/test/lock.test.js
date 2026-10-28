import test from 'node:test';
import assert from 'node:assert/strict';
import { LOCK_ORDER, createLockCoordinator } from '../src/background/lock.js';

const order = ['keyring', 'webWallet', 'nodus', 'solana', 'tron'];

// Proves startup/restart denies signing and failed unlock stays locked; an already-locked-only assertion could miss successful unlock entirely.
test('a new coordinator starts locked and only successful unlock opens the guard', async () => {
  const coordinator = createLockCoordinator();
  assert.equal(coordinator.isLocked, true);
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
  await assert.rejects(coordinator.unlock(async () => { throw new Error('bad password'); }), /bad password/);
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
  assert.equal(await coordinator.unlock(async () => 'restored'), 'restored');
  assert.equal(coordinator.isLocked, false);
  coordinator.assertUnlocked();
  assert.throws(() => createLockCoordinator().assertUnlocked(), /locked/);
});

// Proves every holder is awaited in the specified order despite reverse registration; sorting both actual and expected would hide wrong ordering.
test('manual lock awaits all five holders in a fixed order and closes signing immediately', async () => {
  assert.deepEqual(LOCK_ORDER, order);
  const coordinator = createLockCoordinator(), calls = [];
  let release, started, finishLast, lastStarted, settled = false;
  const entered = new Promise(resolve => { started = resolve; });
  const lastEntered = new Promise(resolve => { lastStarted = resolve; });
  for (const name of [...order].reverse()) coordinator.register(name, {
    name,
    async lock() {
      assert.equal(this.name, name);
      calls.push(name);
      if (name === 'keyring') { started(); await new Promise(resolve => { release = resolve; }); }
      if (name === 'tron') { lastStarted(); await new Promise(resolve => { finishLast = resolve; }); }
    },
  });
  await coordinator.unlock(async () => {});
  const locking = coordinator.lock().then(errors => { settled = true; return errors; });
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
  await entered;
  assert.deepEqual(calls, ['keyring']);
  await assert.rejects(coordinator.unlock(async () => {}), /locked/);
  release();
  await lastEntered;
  assert.equal(settled, false);
  finishLast();
  assert.deepEqual(await locking, []);
  assert.deepEqual(calls, order);
  assert.equal(coordinator.isLocked, true);
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
});

// Proves synchronous and asynchronous holder failures do not skip later holders; only checking the guard could hide undisposed key owners.
test('throwing holders are reported while every remaining holder still locks', async () => {
  const coordinator = createLockCoordinator(), calls = [], syncError = new Error('keyring failed'), asyncError = new Error('Nodus failed');
  for (const name of order) coordinator.register(name, {
    lock() {
      calls.push(name);
      if (name === 'keyring') throw syncError;
      if (name === 'nodus') return Promise.reject(asyncError);
    },
  });
  await coordinator.unlock(async () => {});
  assert.deepEqual(await coordinator.lock(), [{ name: 'keyring', error: syncError }, { name: 'nodus', error: asyncError }]);
  assert.deepEqual(calls, order);
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
});

// Proves concurrent lock callers join the same disposal; merely checking the final locked state could hide double-running keyring lock.
test('concurrent manual and inactivity locks join one holder pass', async () => {
  const coordinator = createLockCoordinator();
  let release, calls = 0;
  coordinator.register('keyring', { lock() { calls++; return new Promise(resolve => { release = resolve; }); } });
  await coordinator.unlock(async () => {});
  const first = coordinator.lock(), second = coordinator.lock();
  assert.equal(calls, 1);
  release();
  assert.deepEqual(await first, []);
  assert.deepEqual(await second, []);
  assert.equal(calls, 1);
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
});

// Proves late unlock completion cannot reverse manual lock; checking only after the lock promise resolves would miss the later reopening.
test('an unlock in flight is invalidated by lock', async () => {
  const coordinator = createLockCoordinator();
  let finish;
  const unlocking = coordinator.unlock(() => new Promise(resolve => { finish = resolve; }));
  const rejected = assert.rejects(unlocking, /locked/);
  await coordinator.lock();
  finish('stale phrase');
  await rejected;
  assert.throws(() => coordinator.assertUnlocked(), /locked/);
});

// Proves queued signing reads the shared guard when it executes; rejecting a request created only after lock would miss queued work.
test('work queued before lock cannot pass the signing guard after lock', async () => {
  const coordinator = createLockCoordinator();
  await coordinator.unlock(async () => {});
  let release, signed = false;
  const queued = new Promise(resolve => { release = resolve; }).then(() => { coordinator.assertUnlocked(); signed = true; });
  const rejected = assert.rejects(queued, /locked/);
  await coordinator.lock();
  release();
  await rejected;
  assert.equal(signed, false);
});

// Proves invalid/duplicate registrations cannot silently omit a holder; happy-path calls would not expose a misspelled custody stage.
test('registration rejects unknown stages, duplicate holders and missing lock methods', () => {
  const coordinator = createLockCoordinator();
  assert.throws(() => coordinator.register('unknown', { lock() {} }), /holder/);
  assert.throws(() => coordinator.register('nodus', {}), /lock/);
  coordinator.register('nodus', { lock() {} });
  assert.throws(() => coordinator.register('nodus', { lock() {} }), /registered/);
});
