import { parseUnits, formatUnits } from 'ethers';
import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { NODUS_NETWORK } from '../../../src/nodus/network.js';
import { IXIOS_NETWORK } from '../../../src/ixios/network.js';

export const INCOMING_NOTIFICATIONS_ALARM = 'INCOMING_NOTIFICATIONS_ALARM';
export const INCOMING_CHECK_MINUTES = 1;

// Operator 2026-10-30: periodically notify incoming funds without replaying
// existing funds. Use the guarded background readers; never retain addresses
// or keys to extend their authority beyond lock. All baselines die on lock.
export async function createIncomingNotifications({ alarms, notifications, runtime, lockCoordinator,
  networks, nodus, evm, solana, tron, now = Date.now }) {
  let active = false, generation = 0, sequence = 0, states = new Map(), jobs = new Map(), scheduling = Promise.resolve();

  function sources() {
    const history = (chain, name, read) => {
      const network = networks.get(chain);
      return { chain, network: network.id, endpoint: network.endpoint, label: `${name} (${network.label})`, read, kind: 'history' };
    };
    return [
      history('nodus', NODUS_NETWORK.name, () => nodus.getHistory()),
      history('ethereum', CHAINS.ethereum.name, () => nodus.getChainHistory('ethereum', { manual: true })),
      history('solana', CHAINS.solana.name, () => solana.getHistory({ manual: true })),
      history('tron', CHAINS.tron.name, () => tron.getHistory({ manual: true })),
      history('cellframe', CELLFRAME.name, () => nodus.getChainHistory('cellframe', { manual: true })),
      { chain: 'bsc', network: 'mainnet', endpoint: evm.getState().endpoints.bsc,
        label: `${CHAINS.bsc.name} (Mainnet)`, kind: 'balance', assets: [CHAINS.bsc, ...CHAINS.bsc.tokens], read: () => evm.getBalances('bsc') },
      { chain: 'ixios', network: 'mainnet', endpoint: IXIOS_NETWORK.endpoint,
        label: `${IXIOS_NETWORK.name} (Mainnet)`, kind: 'balance', assets: [IXIOS_NETWORK], read: () => nodus.getIxiosBalance() },
    ];
  }
  const identity = source => JSON.stringify([source.chain, source.network, source.endpoint]);
  function current(entry, started) {
    return active && !lockCoordinator.isLocked && generation === started && states.get(entry.source.chain) === entry
      && sources().some(source => identity(source) === identity(entry.source));
  }
  function schedule() {
    // Serialize create/clear so a lock racing the asynchronous alarm API
    // cannot leave a newly armed alarm behind it. No UI activity is generated.
    scheduling = scheduling.catch(() => {}).then(() => active && !lockCoordinator.isLocked
      ? alarms.create(INCOMING_NOTIFICATIONS_ALARM, { periodInMinutes: INCOMING_CHECK_MINUTES })
      : alarms.clear(INCOMING_NOTIFICATIONS_ALARM));
    return scheduling;
  }
  function queue(entry, key, amount) {
    entry.queue.push({ id: `nodus-incoming:${entry.source.chain}:${entry.source.network}:${key}`,
      message: `${amount}\n${entry.source.label}` });
  }
  async function deliver(entry, started) {
    while (entry.queue.length && current(entry, started)) {
      const notice = entry.queue[0];
      try {
        // Same basic native notification and packaged icon as sent Activity.
        await notifications.create(notice.id, { type: 'basic', iconUrl: runtime.getURL('icons/nodus-128.png'),
          title: 'Nodus Wallet — funds received', message: notice.message });
      } catch { return; }
      entry.queue.shift();
    }
  }
  function observeHistory(entry, page) {
    if (page?.error || !Array.isArray(page?.rows)) return;
    for (const row of page.rows) {
      // history.js mergeHistory uses (hash, symbol, direction); Nodus history
      // supplies its checked (height, item, row) key, including boundary rows.
      const key = entry.source.chain === 'nodus' ? row.key : JSON.stringify([row.hash, row.symbol, row.dir]);
      if (typeof key !== 'string' || entry.seen.has(key)) continue;
      entry.seen.add(key);
      const quantity = typeof row.amount === 'string' ? row.amount.split(' ')[0] : '';
      if (!entry.ready || row.dir !== 'in' || (entry.source.chain !== 'nodus' && row.status !== 'confirmed')
          || !Number.isSafeInteger(row.time) || row.time <= entry.since
          || !/^\d+(?:\.\d+)?$/u.test(quantity) || !/[1-9]/u.test(quantity)) continue;
      queue(entry, key, entry.source.chain === 'nodus' ? row.amount : `${row.amount} ${row.symbol}`);
    }
    entry.ready = true;
  }
  function observeBalances(entry, rows) {
    if (!Array.isArray(rows)) { entry.balances.clear(); return; }
    const next = new Map();
    for (const asset of entry.source.assets) {
      const row = rows.find(row => row.symbol === asset.symbol);
      if (row?.error || typeof row?.balance !== 'string' || !/^\d+(?:\.\d+)?$/u.test(row.balance)) continue;
      let units;
      try { units = parseUnits(row.balance, asset.decimals); } catch { continue; }
      next.set(asset.symbol, units);
      const previous = entry.balances.get(asset.symbol);
      if (previous !== undefined && units > previous) queue(entry, `balance:${++sequence}`, `${formatUnits(units - previous, asset.decimals)} ${asset.symbol}`);
    }
    // A missing/failed asset must establish a new baseline when it recovers.
    entry.balances = next;
  }
  async function read(entry, started) {
    try {
      const snapshot = await entry.source.read();
      if (!current(entry, started)) return;
      if (entry.source.kind === 'history') observeHistory(entry, snapshot);
      else observeBalances(entry, snapshot);
    } catch {
      if (!current(entry, started)) return;
      if (entry.source.kind === 'balance') entry.balances.clear();
    }
    await deliver(entry, started);
  }
  function check() {
    if (!active || lockCoordinator.isLocked) return Promise.resolve();
    const started = generation, pending = [];
    for (const source of sources()) {
      let entry = states.get(source.chain);
      if (!entry || identity(entry.source) !== identity(source)) {
        entry = { source, since: now(), ready: false, seen: new Set(), balances: new Map(), queue: [] };
        states.set(source.chain, entry);
      }
      let job = jobs.get(source.chain);
      if (job?.entry !== entry) {
        job = { entry };
        job.promise = read(entry, started).finally(() => { if (jobs.get(source.chain) === job) jobs.delete(source.chain); });
        jobs.set(source.chain, job);
      }
      pending.push(job.promise);
    }
    return Promise.all(pending);
  }
  function stop() {
    active = false; generation++; states.clear(); jobs.clear();
    return schedule();
  }
  function start() {
    if (lockCoordinator.isLocked) return stop();
    active = true; generation++; states = new Map(); jobs = new Map();
    return Promise.all([schedule(), check()]);
  }
  function onAlarm(alarm) {
    if (alarm.name === INCOMING_NOTIFICATIONS_ALARM) return check().catch(() => {});
  }
  alarms.onAlarm.addListener(onAlarm);
  // A new worker has fresh locked key holders. Clear an alarm left by its
  // predecessor; successful unlock alone can establish a fresh baseline.
  await stop();
  return { start, stop, check,
    async destroy() { alarms.onAlarm.removeListener(onAlarm); await stop(); } };
}
