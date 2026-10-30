import { readHistory, mergeHistory, HISTORY_SOURCES, HISTORY_LIMIT } from '../../../src/history.js';
import { sentRowsToShow } from '../../../src/activity-storage.js';

// src/app.js:290-352: account-history cache and provider pacing. The caller
// supplies the session-bound authenticated history writer, never its key.
export function createChainHistory({ getActivity, getAddresses, assertCurrent, read = readHistory }) {
  const jobs = new Map();
  return {
    async getHistory(chain, { manual = false, poll = false } = {}) {
      if (!['ethereum', 'cellframe'].includes(chain)) throw new Error('Unsupported account history.');
      assertCurrent();
      const activity = getActivity(chain), addresses = getAddresses(), address = addresses[chain === 'cellframe' ? 'cpunk' : chain];
      if (!address) throw new Error('Receive address is unavailable.');
      const kept = activity.history(), gap = manual ? 30000 : chain === 'ethereum' ? 1800000 : 300000;
      const snapshot = status => ({ rows: activity.history()?.rows ?? [], local: sentRowsToShow(activity.rows(), { historyRows: activity.history()?.rows ?? [] }).map(row => ({ ...row })),
        status, activityError: activity.error?.() ?? '' });
      // Status polling only reads this job's public snapshot. It never starts
      // a provider request, including after the original job has completed.
      if (poll) return snapshot(jobs.get(chain)?.status ?? '');
      if (jobs.has(chain)) return jobs.get(chain).promise;
      if (kept && Date.now() - kept.readAt < gap) return snapshot(manual
        ? `Read ${new Date(kept.readAt).toLocaleString()}. Try again in a minute — the provider limits requests.`
        : `Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${new Date(kept.readAt).toLocaleString()}.`);
      const reading = `Reading account history from ${HISTORY_SOURCES[chain]}…`;
      const job = { status: reading };
      job.promise = Promise.resolve().then(async () => {
        try {
          const rows = await read(chain, address, { onStatus(text) { assertCurrent(); job.status = text || reading; } }); assertCurrent();
          await activity.saveHistory({ address, rows: mergeHistory(kept?.rows, rows), readAt: Date.now() }); assertCurrent();
          return snapshot(`Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${new Date().toLocaleString()}.`);
        } catch (error) { assertCurrent(); return { ...snapshot(''), error: error.message }; }
      }).finally(() => { if (jobs.get(chain) === job) jobs.delete(chain); });
      jobs.set(chain, job); return job.promise;
    },
  };
}
