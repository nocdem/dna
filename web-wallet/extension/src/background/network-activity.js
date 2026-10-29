import { ACTIVITY_KEY, HISTORY_KEY, VAULT_KEY } from '../../../src/vault.js';
import { recordActivity } from '../../../src/activity.js';
import { parseActivity, serializeActivity, parseHistory, serializeHistory } from '../../../src/activity-storage.js';
import { endpointUrl } from '../../../src/core.js';

// src/activity.js:33-35 has no network field. activity-storage.js:258-262
// omits endpoint/network on save; :367 restores the mainnet endpoint. Keep
// the unchanged encrypted formats under separate testnet storage keys, then
// restore only the endpoint belonging to that bucket. Mainnet keeps the
// pre-existing shared keys in nodus.js, so old sends remain mainnet sends.
export function createNetworkActivity({ chain, network, session: s, storage, current }) {
  const activityKey = `${ACTIVITY_KEY}.${chain}.${network.id}`, historyKey = `${HISTORY_KEY}.${chain}.${network.id}`;
  let rows = [], page = null, blocked = false, error = '', writes = Promise.resolve();
  function checkedRows(value) {
    if (value.some(row => row.chain !== chain)) throw new Error('Saved activity belongs to a different chain.');
    return value.map(row => ({ ...row, endpoint: network.endpoint }));
  }
  const ready = (async () => {
    const saved = await storage.get([activityKey, historyKey]); current();
    try { rows = checkedRows(await parseActivity(saved[activityKey], s.id, s.addresses, s.key)); }
    catch (failure) { blocked = true; error = failure.message; }
    current();
    try { page = (await parseHistory(saved[historyKey], s.id, s.historyKey))[chain] ?? null; }
    catch { page = null; }
    current();
  })();
  ready.catch(() => {});
  function enqueue(work) {
    const job = writes.catch(() => {}).then(async () => {
      await ready; current();
      const saved = await storage.get([VAULT_KEY, activityKey]); current();
      if (saved[VAULT_KEY] !== s.vault) throw new Error('Wallet storage changed before broadcast. Review the transfer again.');
      return work(saved);
    });
    writes = job; return job;
  }
  return { ready,
    get client() { current(); return s.client; },
    error() { current(); return error; },
    get blocked() { return blocked; },
    assertSendable() {
      current();
      if (blocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
    },
    rows() { current(); return rows.filter(row => row.address === s.addresses[chain]); },
    append(transfer, details) {
      current();
      if (transfer.chain !== chain || transfer.from !== s.addresses[chain] || endpointUrl(transfer.endpoint) !== endpointUrl(network.endpoint)) throw new Error('Invalid activity owner or network.');
      const row = recordActivity(transfer, details); rows.push(row); return row;
    },
    persist() {
      return enqueue(async saved => {
        if (blocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
        const previous = checkedRows(await parseActivity(saved[activityKey], s.id, s.addresses, s.key)); current();
        const combined = [...new Map([...previous, ...rows].map(row => [row.hash, row])).values()]
          .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) || (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
        const encrypted = await serializeActivity(s.id, combined, s.key); current();
        await storage.set({ [activityKey]: encrypted }); current();
      });
    },
    history() { current(); return page?.address === s.addresses[chain] ? page : null; },
    saveHistory(value) {
      current(); page = value;
      return enqueue(async () => {
        const encrypted = await serializeHistory(s.id, { [chain]: page }, s.historyKey); current();
        await storage.set({ [historyKey]: encrypted }); current();
      });
    },
    discard() {
      return enqueue(async saved => {
        if (!blocked) return;
        const previous = saved[activityKey];
        const encrypted = await serializeActivity(s.id, [], s.key); current();
        // Same post-encryption check as nodus.js discardActivity and
        // web-wallet/src/app.js:2684: do not overwrite changed saved activity.
        const latest = await storage.get([VAULT_KEY, activityKey]); current();
        if (saved[VAULT_KEY] !== s.vault || latest[VAULT_KEY] !== s.vault || latest[activityKey] !== previous) throw new Error('Wallet or history changed. Unlock again before discarding history.');
        await storage.set({ [activityKey]: encrypted }); current();
        rows = []; blocked = false; error = '';
      });
    },
  };
}
