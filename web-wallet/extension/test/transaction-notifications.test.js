import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransactionNotifications, TRANSACTION_NOTIFICATIONS_KEY, TRANSACTION_NOTIFICATIONS_ALARM } from '../src/background/transaction-notifications.js';

// Node >=22.14; no flags, network, browser, timers or generated artifacts.
// Storage, alarm and notification fixtures model only Chrome's public APIs.
function fixture() {
  const values = {}, shown = [], scheduled = new Map(), listeners = new Set();
  let refuse = false;
  const options = {
    storage: { async get(key) { return { [key]: structuredClone(values[key]) }; }, async set(items) { Object.assign(values, structuredClone(items)); } },
    runtime: { getURL: path => `chrome-extension://notification-test/${path}` },
    notifications: { async create(id, value) { if (refuse) throw new Error('Notification fixture unavailable.'); shown.push({ id, ...value }); return id; } },
    alarms: { async create(name, value) { scheduled.set(name, value); }, async clear(name) { scheduled.delete(name); },
      onAlarm: { addListener: listener => listeners.add(listener), removeListener: listener => listeners.delete(listener) } },
  };
  return { values, shown, scheduled, options, setRefuse: value => { refuse = value; },
    alarm: name => Promise.all([...listeners].map(listener => listener({ name }))) };
}
const row = (chain = 'nodus', status = 'pending') => ({ chain, hash: chain === 'nodus' ? 'ab'.repeat(64) : chain === 'solana' ? '1'.repeat(88) : chain === 'tron' ? 'ab'.repeat(32) : '0x' + 'ab'.repeat(32), status });

// Pins both events for each Activity chain without requiring a popup. A test
// of only the final title could miss a missing submission notification.
test('each sent Activity transaction produces pending and final system notifications', async t => {
  const f = fixture(), notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  for (const chain of ['nodus', 'ethereum', 'bsc', 'solana', 'tron']) {
    await notifier.observe([row(chain)]);
    await notifier.observe([row(chain, 'confirmed')]);
  }
  assert.equal(f.shown.length, 10);
  for (let index = 0; index < f.shown.length; index += 2) {
    assert.match(f.shown[index].title, /pending/u);
    assert.match(f.shown[index + 1].title, /confirmed/u);
    assert.equal(f.shown[index].type, 'basic');
    assert.equal(f.shown[index].iconUrl, 'chrome-extension://notification-test/icons/nodus-128.png');
    assert.notEqual(f.shown[index].id, f.shown[index + 1].id);
  }
});

// Pins failure and the other existing terminal states literally. Unknown and
// included remain pending; a network error must never become a failed send.
test('notifications preserve Activity outcomes and do not invent finality', async t => {
  const f = fixture(), notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  await notifier.observe([row('ethereum')]);
  await notifier.observe([row('ethereum', 'included')]);
  await notifier.observe([row('ethereum', 'unknown')]);
  assert.equal(f.shown.length, 1);
  for (const status of ['failed', 'expired', 'replaced', 'abandoned']) {
    const sent = { ...row('ethereum'), hash: '0x' + String(f.shown.length).repeat(64) };
    await notifier.observe([sent]);
    await notifier.observe([{ ...sent, status }]);
    assert.match(f.shown.at(-1).title, new RegExp(status, 'u'));
  }
});

// Pins serialized duplicate suppression across concurrent updates and worker
// recreation. Reusing one instance alone would miss loss of the session ledger.
test('the same transaction and state are notified once across worker restarts', async t => {
  const f = fixture(); let notifier = await createTransactionNotifications(f.options);
  await Promise.all([notifier.observe([row()]), notifier.observe([row()])]);
  notifier.destroy(); notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  await notifier.observe([row()]);
  await Promise.all([notifier.observe([row('nodus', 'confirmed')]), notifier.observe([row('nodus', 'confirmed')])]);
  assert.equal(f.shown.length, 2);
  assert.equal(new Set(f.shown.map(value => value.id)).size, 2);
});

// Pins network identity and restore baselines. Old final history must not be
// replayed as new sends, while an observed pending send still gets its result.
test('restore skips old history and keeps networks distinct', async t => {
  const f = fixture(), notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  await notifier.observe([row('solana', 'confirmed')], { restored: true });
  await notifier.observe([row('solana', 'confirmed')]);
  assert.equal(f.shown.length, 0);
  await notifier.observe([row('solana')], { network: 'devnet' });
  await notifier.observe([row('solana')], { network: 'testnet' });
  await notifier.observe([row('solana', 'confirmed')], { restored: true, network: 'devnet' });
  assert.equal(f.shown.length, 3);
  assert.notEqual(f.shown[0].id, f.shown[1].id);
});

// parseActivity resets saved final rows to pending, except abandoned, and
// preserves savedStatus. Using a live confirmed restore would miss the replay.
// Emptying only the notification ledger models a new browser session; worker
// recreation with the ledger retained must also keep those rows ineligible.
test('saved final rows never notify when Activity re-verifies them after restore', async () => {
  for (const chain of ['nodus', 'ethereum', 'bsc', 'solana', 'tron']) {
    for (const savedStatus of ['confirmed', 'failed', 'expired', 'replaced', 'abandoned']) {
      const f = fixture();
      for (let session = 0; session < 2; session++) {
        delete f.values[TRANSACTION_NOTIFICATIONS_KEY];
        let notifier = await createTransactionNotifications(f.options);
        try {
          const restored = { ...row(chain, savedStatus === 'abandoned' ? 'abandoned' : 'pending'), savedStatus };
          await notifier.observe([restored], { restored: true });
          // Activity persistence snapshots omit savedStatus. Eligibility must
          // survive those snapshots and a worker stop, rather than re-enroll.
          await notifier.observe([row(chain)]);
          notifier.destroy(); notifier = await createTransactionNotifications(f.options);
          await notifier.observe([row(chain, savedStatus)]);
          await notifier.observe([row(chain, 'confirmed')]);
          assert.deepEqual(f.shown, [], `${chain}: saved ${savedStatus}, session ${session}`);
        } finally { notifier.destroy(); }
      }
    }
  }
});

// An unresolved saved row is eligible even with an empty session ledger.
// Restoration itself is silent; its later final result is delivered once.
test('restored pending transactions still notify their final state once', async t => {
  const f = fixture(), notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  for (const chain of ['nodus', 'ethereum', 'bsc', 'solana', 'tron']) {
    await notifier.observe([{ ...row(chain), savedStatus: 'pending' }], { restored: true });
    await notifier.observe([row(chain, 'confirmed')]);
    await notifier.observe([row(chain, 'confirmed')]);
  }
  assert.equal(f.shown.length, 5);
  for (const notification of f.shown) assert.match(notification.title, /confirmed/u);
});

// A first observation of a final row is history, not evidence of a send or
// an observed pending transaction. Only enrolled transactions can notify.
test('an unobserved final transaction does not create a notification', async t => {
  const f = fixture(), notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  await notifier.observe([row('nodus', 'confirmed')]);
  await notifier.observe([row('nodus', 'failed')]);
  assert.deepEqual(f.shown, []);
});

// Pins delivery recovery from the stored queue using an alarm after worker
// recreation. This does not claim the locked wallet can read new chain status.
test('an alarm delivers queued states after worker restart without a live page', async t => {
  const f = fixture(); let notifier = await createTransactionNotifications(f.options);
  f.setRefuse(true);
  await notifier.observe([row()]);
  await notifier.observe([row('nodus', 'confirmed')]);
  assert.equal(f.shown.length, 0);
  assert.ok(f.values[TRANSACTION_NOTIFICATIONS_KEY]);
  assert.ok(f.scheduled.has(TRANSACTION_NOTIFICATIONS_ALARM));
  notifier.destroy(); notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  f.setRefuse(false);
  await f.alarm('AUTO_LOCK_TIMEOUT_ALARM'); assert.equal(f.shown.length, 0);
  await f.alarm(TRANSACTION_NOTIFICATIONS_ALARM);
  await f.alarm(TRANSACTION_NOTIFICATIONS_ALARM);
  assert.equal(f.shown.length, 2);
  assert.match(f.shown[0].title, /pending/u); assert.match(f.shown[1].title, /confirmed/u);
  assert.equal(f.scheduled.has(TRANSACTION_NOTIFICATIONS_ALARM), false);
});

// The notification projection must never persist Activity's spending material
// in session storage, even when the observer receives the complete live row.
test('the notification ledger contains only notification identity and states', async t => {
  const f = fixture(), notifier = await createTransactionNotifications(f.options); t.after(() => notifier.destroy());
  await notifier.observe([{ ...row(), envelope: new Uint8Array([1, 2, 3]), inputs: ['secret-input'], address: 'private-owner', amount: '12345' }]);
  const kept = JSON.stringify(f.values);
  for (const field of ['envelope', 'inputs', 'secret-input', 'address', 'private-owner', 'amount', '12345']) assert.equal(kept.includes(field), false, field);
});
