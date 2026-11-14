// The account histories the extension reads and used to throw away (Soqucoin, Splendor, XION, CKB) are kept encrypted in the
// network's own saved-history key (src/background/network-activity.js saveHistory -> HISTORY_KEY.<chain>.<network>), the key the
// Algorand and Ixios pages already use. Each holder (src/background/{soqucoin,splendor,xion,ckb}.js) is built over the REAL
// createNetworkActivity and an in-memory storage; the provider reader is a stub that answers with the reader's own row shape.
// What this proves, per chain: a read is written (the record opens with the wallet's history key and holds the rows, and its text
// does not show them); a wallet opened again over the same storage shows the kept page at once without asking the provider
// (Soqucoin, Splendor, XION: the existing 5-minute gap; CKB has no gap and reads every time); when the next read fails the kept
// rows still show with the failure named; a record of another address, or one whose rows do not check out, is not shown; another
// network's bucket is never read (Splendor testnet after a mainnet read).
// A typed-words wallet does not exist in the extension (every wallet is saved), so "nothing written for an unsaved wallet" is
// covered on the web side (test/history-kept.test.js header). The NODUS page is covered in nodus-background.test.js.
// Compile flags / environment: none. Leaves nothing behind (in-memory storage, no network: the readers are stubs).
// Falsely passes if: a holder served its in-memory copy instead of the storage (every "opened again" case builds a new lock
// coordinator, activity and holder over the same storage object), or the stub rows were produced by the code under test (they are
// hand-written / from the readers' own parsers).
import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '@scure/base';
import { createSoqucoin } from '../src/background/soqucoin.js';
import { createSplendor } from '../src/background/splendor.js';
import { createXion } from '../src/background/xion.js';
import { createCkb } from '../src/background/ckb.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { createNetworkActivity } from '../src/background/network-activity.js';
import { activityKeyFor, historyKeyFor, parseHistory, serializeHistory } from '../../src/activity-storage.js';
import { parseXionHistory } from '../../src/pq/xion-history.js';
import { parseSplendorHistory } from '../../src/pq/splendor-history.js';
import { HISTORY_KEY, VAULT_KEY } from '../../src/vault.js';

const phrase = 'abandon '.repeat(23) + 'art', id = Buffer.alloc(16, 9).toString('base64'), hex = (byte, n = 32) => byte.repeat(n);
const xionAccount = byte => bech32.encode('xion', bech32.toWords(Uint8Array.from({ length: 20 }, () => byte)));
const splendorAccount = byte => 'SQ:' + hex(byte);
const xionRows = parseXionHistory([{ txs: [{ body: { messages: [{ '@type': '/cosmos.bank.v1beta1.MsgSend', from_address: xionAccount(2), to_address: xionAccount(1), amount: [{ denom: 'uxion', amount: '1500000' }] }] } }],
  tx_responses: [{ txhash: hex('ab'), code: '0', timestamp: '2026-11-14T10:00:00Z' }] }, { txs: [], tx_responses: [] }], xionAccount(1));
const splendorRows = parseSplendorHistory({ address: splendorAccount('11'), transactions: [{ kind: 'transfer', from: splendorAccount('22'), to: splendorAccount('11'), hash: hex('cd'), amount: '1500000000000000000', status: '1', timestamp: '1790000000' }] }, splendorAccount('11'));
const soqRows = [{ chain: 'soqucoin', hash: hex('a1'), time: 1790000000000, dir: 'out', symbol: 'SOQ', amount: '0.5', peer: '', status: 'confirmed' }];
const ckbRows = [{ hash: '0x' + hex('ab'), dir: 'in', amount: '61', symbol: 'CKB', status: 'committed', time: 1790000000000 }];

const CASES = {
  soqucoin: { create: createSoqucoin, address: 'soq-address', rows: soqRows, read: rows => async () => ({ rows, totalListed: 1, examined: 1, omitted: 0, status: 'Partial native SOQ net flows.' }), gap: true },
  splendor: { create: createSplendor, address: splendorAccount('11'), rows: splendorRows, read: rows => async () => rows, gap: true },
  xion: { create: createXion, address: xionAccount(1), rows: xionRows, read: rows => async () => rows, gap: true },
  ckb: { create: createCkb, address: 'ckb-address', rows: ckbRows, read: rows => async () => ({ rows, status: 'Provider-reported net flow.', truncated: false }), gap: false },
};

function storageOf(values) {
  return { async get(keys) { return Object.fromEntries(keys.map(key => [key, structuredClone(values[key])])); }, async set(items) { Object.assign(values, structuredClone(items)); } };
}
// One wallet opening over `values`: a new lock coordinator, a new activity (it reads the saved history) and a new holder.
async function open(chain, values, { readHistory, network = 'mainnet', address = CASES[chain].address } = {}) {
  const storage = storageOf(values), net = { id: network, label: network, endpoint: 'https://provider.example' };
  const lockCoordinator = createLockCoordinator(); await lockCoordinator.unlock(async () => {});
  const session = { id, addresses: { [chain]: address }, vault: values[VAULT_KEY], key: await activityKeyFor(phrase, id), historyKey: await historyKeyFor(phrase, id) };
  const activity = createNetworkActivity({ chain, network: net, session, storage, current: () => lockCoordinator.assertUnlocked() });
  const holder = CASES[chain].create({ lockCoordinator, getWalletKeys: () => ({ getPqAddresses: () => ({ [chain]: { [network]: address } }), getRecoveryPhrase() { throw new Error('a history read must not touch the words'); } }),
    getActivity: () => activity, getNetwork: () => net, storage, watch: () => () => {}, readHistory });
  await activity.ready;
  return { holder, lockCoordinator, key: `${HISTORY_KEY}.${chain}.${network}` };
}
const counted = fn => { const read = async (...args) => { read.calls++; return fn(...args); }; read.calls = 0; return read; };
const failing = () => counted(async () => { throw new Error('provider unavailable'); });

for (const chain of Object.keys(CASES)) {
  const { rows, read, gap, address } = CASES[chain];

  test(`${chain}: a read is kept encrypted and shown at once by the wallet opened again`, async t => {
    const values = { [VAULT_KEY]: 'synthetic vault' };
    const first = await open(chain, values, { readHistory: counted(read(rows)) });
    const shown = await first.holder.getHistory();
    assert.deepEqual(shown.rows, rows);
    const key = await historyKeyFor(phrase, id);
    const saved = await parseHistory(values[first.key], id, key);
    assert.equal(saved[chain].address, address); assert.deepEqual(saved[chain].rows, rows);
    assert.ok(!JSON.stringify(values[first.key]).includes(rows[0].hash), 'the record is encrypted');
    assert.deepEqual(Object.keys(values).filter(name => name.startsWith(HISTORY_KEY)), [first.key]);
    await first.lockCoordinator.lock();

    // Opened again: the kept page, no provider request (the 5-minute gap; CKB has none and reads each time).
    const secondReader = counted(read(rows)), second = await open(chain, values, { readHistory: secondReader });
    const again = await second.holder.getHistory();
    assert.deepEqual(again.rows, rows);
    assert.equal(secondReader.calls, gap ? 0 : 1);
    await second.lockCoordinator.lock();

    // Later, with the provider failing: the kept rows stay, the failure is named.
    const now = Date.now(); t.mock.method(Date, 'now', () => now + 301000);
    const reader = failing(), third = await open(chain, values, { readHistory: reader });
    const failed = await third.holder.getHistory({ manual: true });
    assert.equal(reader.calls, 1);
    assert.deepEqual(failed.rows, rows);
    assert.match(failed.error, /provider unavailable/);
    await third.lockCoordinator.lock();
  });

  test(`${chain}: the gap is honoured from the kept page${gap ? '' : ' (CKB has none: it reads every time)'}`, async () => {
    const values = { [VAULT_KEY]: 'synthetic vault' };
    const first = await open(chain, values, { readHistory: counted(read(rows)) }); await first.holder.getHistory(); await first.lockCoordinator.lock();
    const reader = counted(read(rows)), second = await open(chain, values, { readHistory: reader });
    await second.holder.getHistory();
    assert.equal(reader.calls, gap ? 0 : 1);
    await second.lockCoordinator.lock();
  });

  test(`${chain}: a kept page of another address, or with rows that do not check out, is not shown`, async () => {
    const key = await historyKeyFor(phrase, id);
    const sealed = record => serializeHistory(id, { [chain]: record }, key);
    const bad = { ...rows[0], symbol: 'FAKE' };
    for (const [what, record] of [['another address', { address: 'someone-else', readAt: Date.now(), rows }], ['unchecked rows', { address, readAt: Date.now(), rows: [bad] }]]) {
      const values = { [VAULT_KEY]: 'synthetic vault' }, name = `${HISTORY_KEY}.${chain}.mainnet`;
      values[name] = await sealed(record);
      const reader = failing(), opened = await open(chain, values, { readHistory: reader });
      const shown = await opened.holder.getHistory();
      assert.equal(reader.calls, 1, `${what}: nothing kept counts as read, so the provider is asked`);
      assert.deepEqual(shown.rows, [], what);
      assert.match(shown.error, /provider unavailable/, what);
      await opened.lockCoordinator.lock();
    }
  });
}

test('splendor: another network\'s kept page is never read', async () => {
  const values = { [VAULT_KEY]: 'synthetic vault' };
  const main = await open('splendor', values, { readHistory: counted(CASES.splendor.read(splendorRows)) }); await main.holder.getHistory(); await main.lockCoordinator.lock();
  const reader = failing(), testnet = await open('splendor', values, { network: 'testnet', readHistory: reader });
  const shown = await testnet.holder.getHistory();
  assert.equal(reader.calls, 1); assert.deepEqual(shown.rows, []);
  assert.deepEqual(Object.keys(values).filter(name => name.startsWith(HISTORY_KEY)), [`${HISTORY_KEY}.splendor.mainnet`]);
  await testnet.lockCoordinator.lock();
});

test('soqucoin: the counts of this session\'s read show; a page that opened with the wallet says only when it was read', async () => {
  const values = { [VAULT_KEY]: 'synthetic vault' };
  const first = await open('soqucoin', values, { readHistory: counted(CASES.soqucoin.read(soqRows)) });
  assert.match((await first.holder.getHistory()).status, /Listed 1; examined 1; omitted 0/); await first.lockCoordinator.lock();
  const second = await open('soqucoin', values, { readHistory: counted(CASES.soqucoin.read(soqRows)) });
  const kept = await second.holder.getHistory();
  assert.match(kept.status, /kept from the read of/); assert.doesNotMatch(kept.status, /Listed/);
  await second.lockCoordinator.lock();
});
