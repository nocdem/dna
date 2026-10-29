import { AUTO_LOCK_KEY, AUTO_LOCK_CHOICES, AUTO_LOCK_DEFAULT, parseAutoLock } from '../../../src/auto-lock.js';

// MetaMask v13.54.0 shared/constants/alarms.js:1 and
// app/scripts/controllers/app-state-controller.ts:837-845, 1225-1261.
export const AUTO_LOCK_TIMEOUT_ALARM = 'AUTO_LOCK_TIMEOUT_ALARM';

export async function createAutoLockAlarm({ storage, alarms, lockCoordinator }) {
  let minutes = AUTO_LOCK_DEFAULT;
  try { minutes = parseAutoLock((await storage.get(AUTO_LOCK_KEY))[AUTO_LOCK_KEY]); }
  catch { minutes = AUTO_LOCK_DEFAULT; }
  let pending = Promise.resolve();

  function enqueue(operation) {
    const result = pending.then(operation);
    pending = result.catch(() => {});
    return result;
  }

  async function reset() {
    await alarms.clear(AUTO_LOCK_TIMEOUT_ALARM);
    if (minutes === 0) return;
    await alarms.create(AUTO_LOCK_TIMEOUT_ALARM, { delayInMinutes: minutes, periodInMinutes: minutes });
  }

  async function setMinutes(value) {
    if (!AUTO_LOCK_CHOICES.includes(value)) return false;
    return enqueue(async () => {
      minutes = value;
      let kept = true;
      try { await storage.set({ [AUTO_LOCK_KEY]: String(minutes) }); }
      catch { kept = false; }
      await reset();
      return kept;
    });
  }

  // Only the background's authenticated extension-interface path may obtain
  // this handle. Site request handlers must never receive it. Sender checking
  // belongs to the later background/router package, not this injected module.
  function openTrustedInterface() {
    let closed = false;
    return {
      activity() {
        if (closed) return Promise.resolve(false);
        return enqueue(async () => { await reset(); return true; });
      },
      // Closing revokes this interface's activity handle, leaving expiry armed.
      close() { closed = true; },
    };
  }

  function onAlarm(alarm) {
    if (alarm.name !== AUTO_LOCK_TIMEOUT_ALARM) return;
    // Close the signing guard immediately, even if a preference write is pending.
    const locking = lockCoordinator.lock();
    return enqueue(async () => {
      try { return await locking; }
      finally { await alarms.clear(AUTO_LOCK_TIMEOUT_ALARM); }
    });
  }

  alarms.onAlarm.addListener(onAlarm);
  await enqueue(reset);
  return { get minutes() { return minutes; }, setMinutes, openTrustedInterface };
}
