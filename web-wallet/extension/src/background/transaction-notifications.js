import { terminal, validHash } from '../../../src/activity.js';
import { CHAINS } from '../../../src/config.js';
import { DEFAULT_NETWORKS } from '../constants/networks.js';

export const TRANSACTION_NOTIFICATIONS_KEY = 'nodus.extension.transactionNotifications';
export const TRANSACTION_NOTIFICATIONS_ALARM = 'TRANSACTION_NOTIFICATIONS_ALARM';

// Operator 2026-10-30: system notifications for every sent transaction,
// pending and its result. Activity alone determines the transaction status.
// Session storage survives worker stops without saving spending material or
// creating a second unencrypted transaction history on disk.
export async function createTransactionNotifications({ storage, notifications, runtime, alarms }) {
  const saved = await storage.get(TRANSACTION_NOTIFICATIONS_KEY);
  const entries = saved[TRANSACTION_NOTIFICATIONS_KEY] ?? [];
  let pending = Promise.resolve();
  function enqueue(work) {
    const job = pending.catch(() => {}).then(work); pending = job; return job;
  }
  const save = () => storage.set({ [TRANSACTION_NOTIFICATIONS_KEY]: entries });
  async function arm() {
    if (entries.some(entry => entry.queue.length)) {
      // Chrome's documented repeating-alarm example; no page timer is used
      // for delivery recovery: developer.chrome.com/docs/extensions/reference/api/alarms#concepts-and-usage.
      await alarms.create(TRANSACTION_NOTIFICATIONS_ALARM, { periodInMinutes: 1 });
    } else await alarms.clear(TRANSACTION_NOTIFICATIONS_ALARM);
  }
  async function deliver() {
    for (const entry of entries) {
      while (entry.queue.length) {
        const status = entry.queue[0];
        const id = `nodus-transaction:${entry.chain}:${entry.network}:${entry.hash}:${status}`;
        try {
          // MetaMask v13.54.0 platforms/extension.ts:266-288 and Chrome's
          // notifications.create API: a basic notification with a package icon.
          await notifications.create(id, { type: 'basic', iconUrl: runtime.getURL('icons/nodus-128.png'),
            title: `Nodus Wallet — ${status}`, message: `${entry.chain === 'nodus' ? 'Nodus' : CHAINS[entry.chain].name} (${entry.network})\n${entry.hash}` });
        } catch { break; }
        entry.seen.push(status); entry.queue.shift(); await save();
      }
    }
    await arm();
  }
  function observe(rows, { restored = false, network } = {}) {
    // Capture now: trackers mutate their live rows while storage yields.
    const updates = rows.filter(row => Object.hasOwn(DEFAULT_NETWORKS, row.chain) && validHash(row.chain, row.hash))
      .map(row => ({ chain: row.chain, hash: row.hash, network: network ?? DEFAULT_NETWORKS[row.chain],
        status: terminal(row.status) ? row.status : 'pending',
        // parseActivity resets final history to pending for re-verification.
        // Only a new pending send or an unresolved saved row is eligible.
        eligible: !terminal(restored ? (row.savedStatus ?? row.status) : row.status) }));
    return enqueue(async () => {
      let changed = false;
      for (const update of updates) {
        let entry = entries.find(value => value.chain === update.chain && value.network === update.network && value.hash === update.hash);
        if (!entry) {
          entry = { chain: update.chain, network: update.network, hash: update.hash, eligible: update.eligible,
            seen: restored ? [update.status] : [], queue: [] };
          entries.push(entry); changed = true;
        }
        if (entry.eligible === false) continue;
        if (!entry.seen.includes(update.status) && !entry.queue.includes(update.status)) {
          entry.queue.push(update.status); changed = true;
        }
      }
      if (changed) { await save(); await arm(); }
      await deliver();
    });
  }
  function onAlarm(alarm) {
    if (alarm.name === TRANSACTION_NOTIFICATIONS_ALARM) return enqueue(deliver).catch(() => {});
  }
  alarms.onAlarm.addListener(onAlarm);
  await arm();
  return { observe, flush: () => pending,
    destroy() { alarms.onAlarm.removeListener(onAlarm); } };
}
