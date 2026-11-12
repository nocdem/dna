// The last balances of a saved wallet (decision
// 2026-10-02-device-cache-only-when-saved): encrypted under their own key
// (HKDF info BALANCES_CONTEXT), bound to the vault id, refused when changed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { activityKeyFor, balancesKeyFor, serializeBalances, parseBalances, serializeActivity, parseActivity } from '../src/activity-storage.js';
import { ASSETS, portfolioSnapshot, BALANCE_MAX_AGE } from '../src/portfolio.js';

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const id = Buffer.alloc(16, 7).toString('base64'), otherId = Buffer.alloc(16, 8).toString('base64');
// Every kept balance carries the network it was read on ('main' for mainnet): without it the row is a legacy row.
const entries = { 'ethereum:ETH': { units: '1500000000000000000', observedAt: 1790000000000, address: '0xabc', network: 'main' } };

test('saved balances: round trip under the balances key', async () => {
  const key = await balancesKeyFor(phrase, id);
  const text = await serializeBalances(id, entries, key);
  assert.ok(!text.includes('1500000000000000000') && !text.includes('0xabc'));
  const back = await parseBalances(text, id, key, 1790000000000);
  assert.deepEqual(back, { 'ethereum:ETH': { units: 1500000000000000000n, observedAt: 1790000000000, address: '0xabc', network: 'main' } });
  assert.deepEqual(await parseBalances(null, id, key), {});
});

test('saved balances: another vault id, the activity key or a changed byte is refused', async () => {
  const key = await balancesKeyFor(phrase, id);
  const text = await serializeBalances(id, entries, key);
  await assert.rejects(parseBalances(text, otherId, key), /do not match/);
  await assert.rejects(parseBalances(text, id, await activityKeyFor(phrase, id)), /authentication failed/);
  const data = JSON.parse(text);
  const ct = Buffer.from(data.ciphertext, 'base64'); ct[0] ^= 1;
  await assert.rejects(parseBalances(JSON.stringify({ ...data, ciphertext: ct.toString('base64') }), id, key), /authentication failed/);
  // and the activity key cannot read balances / the balances key activity
  const activity = await serializeActivity(id, [], await activityKeyFor(phrase, id));
  await assert.rejects(parseActivity(activity, id, {}, key), /authentication failed/);
});

test('saved balances: malformed entries are refused', async () => {
  const key = await balancesKeyFor(phrase, id);
  const n = 'main';
  for (const bad of [{ 'ethereum:ETH': { units: '-1', observedAt: 1, address: 'a', network: n } }, { 'ethereum:ETH': { units: '1', observedAt: 1790000000000 + 3600000, address: 'a', network: n } }, { 'bad key!': { units: '1', observedAt: 1, address: 'a', network: n } }, { 'ethereum:ETH': { units: '1', observedAt: 1, address: '', network: n } },
    { 'ethereum:ETH': { units: '1', observedAt: 1, address: 'a', network: 'bad network!' } }, { 'ethereum:ETH': { units: '1', observedAt: 1, address: 'a', network: 5 } }]) {
    await assert.rejects(parseBalances(await serializeBalances(id, bad, key), id, key, 1790000000000), /Invalid saved balances/);
  }
});

test('portfolio: a kept balance shows with its read time, outside the total, counted missing', () => {
  const now = 1790000000000, eth = ASSETS.find(a => a.key === 'ethereum:ETH');
  const kept = { [eth.key]: { units: 2n * 10n ** 18n, observedAt: now - 3600000 } };
  let snap = portfolioSnapshot({}, {}, now, ASSETS, kept);
  let row = snap.rows.find(r => r.key === eth.key);
  assert.equal(row.balance, '2.0'); assert.equal(row.keptAt, now - 3600000); assert.equal(row.usd, null);
  assert.equal(snap.total, null); assert.equal(snap.missingBalances, ASSETS.length);
  // a fresh read wins over the kept value
  snap = portfolioSnapshot({ [eth.key]: { state: 'ready', units: 3n * 10n ** 18n, observedAt: now } }, {}, now, ASSETS, kept);
  row = snap.rows.find(r => r.key === eth.key);
  assert.equal(row.balance, '3.0'); assert.equal(row.keptAt, undefined);
  // an expired read falls back to the kept value
  snap = portfolioSnapshot({ [eth.key]: { state: 'ready', units: 3n * 10n ** 18n, observedAt: now } }, {}, now + BALANCE_MAX_AGE + 1, ASSETS, kept);
  row = snap.rows.find(r => r.key === eth.key);
  assert.equal(row.state, 'stale'); assert.equal(row.balance, '2.0'); assert.equal(row.keptAt, now - 3600000);
});

// Proves the kept price (units and read time) goes through the encrypted record and comes back as a bigint, an entry
// without a price is unchanged, and a malformed price is refused. Could falsely pass if the field were dropped on both
// sides; the plain text check and the exact round-trip value guard that.
test('saved balances: a kept price round-trips and a malformed price is refused', async () => {
  const key = await balancesKeyFor(phrase, id);
  const withPrice = { 'ethereum:ETH': { ...entries['ethereum:ETH'], price: { units: '200000000000', observedAt: 1789999990000 } } };
  const text = await serializeBalances(id, withPrice, key);
  assert.ok(!text.includes('200000000000'));
  assert.deepEqual(await parseBalances(text, id, key, 1790000000000), { 'ethereum:ETH': { units: 1500000000000000000n, observedAt: 1790000000000, address: '0xabc', price: { units: 200000000000n, observedAt: 1789999990000 } } });
  for (const price of [{ units: '-1', observedAt: 1 }, { units: '1', observedAt: 0 }, { units: '1', observedAt: 1790000000000 + 3600000 }, 'x']) {
    await assert.rejects(parseBalances(await serializeBalances(id, { 'ethereum:ETH': { ...entries['ethereum:ETH'], price } }, key), id, key, 1790000000000), /Invalid saved balances/);
  }
});

// Proves a saved row WITHOUT a network (written before rows were bound to the network they were read on) is dropped on load,
// not assumed to be mainnet, while the rows that carry one survive; and that a sealed Sepolia row keeps its own network id.
// Could falsely pass if serializeBalances itself dropped the row: the survivors' keys are asserted, and the legacy row is
// sealed with the same call as the others (a build that dropped it at save time would not be a legacy-record test).
test('saved balances: a legacy row without a network is dropped on load, a test-network row keeps its network', async () => {
  const key = await balancesKeyFor(phrase, id), sepolia = 'test:11155111:ethereum-sepolia-rpc.publicnode.com';
  const mixed = { 'ethereum:ETH': { units: '5', observedAt: 1790000000000, address: '0xabc' }, 'bsc:BNB': { units: '7', observedAt: 1790000000000, address: '0xabc', network: 'main' },
    'solana:SOL': { units: '9', observedAt: 1790000000000, address: 'sol', network: sepolia } };
  const text = await serializeBalances(id, mixed, key);
  const back = await parseBalances(text, id, key, 1790000000000);
  assert.deepEqual(Object.keys(back).sort(), ['bsc:BNB', 'solana:SOL']);
  assert.equal(back['solana:SOL'].network, sepolia); assert.equal(back['bsc:BNB'].network, 'main');
});
