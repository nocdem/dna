import { readHistory, mergeHistory, HISTORY_SOURCES, HISTORY_LIMIT } from '../../../src/history.js';
import { sentRowsToShow } from '../../../src/activity-storage.js';

// src/app.js:290-352: account-history cache and provider pacing. The caller
// supplies the session-bound authenticated history writer, never its key.
export function createChainHistory({ getActivity, getAddresses, assertCurrent, read = readHistory }) {
  const jobs = new Map();
  return {
    async getHistory(chain, { manual = false } = {}) {
      if (!['ethereum', 'cellframe'].includes(chain)) throw new Error('Unsupported account history.');
      assertCurrent();
      if (jobs.has(chain)) return jobs.get(chain);
      const activity = getActivity(chain), addresses = getAddresses(), address = addresses[chain === 'cellframe' ? 'cpunk' : chain];
      if (!address) throw new Error('Receive address is unavailable.');
      const kept = activity.history(), gap = manual ? 30000 : chain === 'ethereum' ? 1800000 : 300000;
      const snapshot = status => ({ rows: activity.history()?.rows ?? [], local: sentRowsToShow(activity.rows(), { historyRows: activity.history()?.rows ?? [] }).map(row => ({ ...row })),
        status, activityError: activity.error?.() ?? '' });
      if (kept && Date.now() - kept.readAt < gap) return snapshot(manual
        ? `Read ${new Date(kept.readAt).toLocaleString()}. Try again in a minute — the provider limits requests.`
        : `Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${new Date(kept.readAt).toLocaleString()}. Your own sends are tracked above.`);
      const job = (async () => {
        try {
          const rows = await read(chain, address); assertCurrent();
          await activity.saveHistory({ address, rows: mergeHistory(kept?.rows, rows), readAt: Date.now() }); assertCurrent();
          return snapshot(`Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${new Date().toLocaleString()}. Your own sends are tracked above.`);
        } catch (error) { assertCurrent(); return { ...snapshot(''), error: error.message }; }
      })().finally(() => { if (jobs.get(chain) === job) jobs.delete(chain); });
      jobs.set(chain, job); return job;
    },
  };
}
