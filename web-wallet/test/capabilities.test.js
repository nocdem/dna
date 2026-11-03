import test from 'node:test';
import assert from 'node:assert/strict';
import { capabilitiesFor, pageSupported } from '../src/capabilities.js';
import { zeroNetwork, groupNetworks } from '../src/portfolio.js';
const zero = { chain: 'ethereum', symbol: 'ETH', state: 'ready', balance: '0', units: 0n };
test('capabilities describe implemented features independently of runtime', () => {
  assert.equal(capabilitiesFor('cellframe').balance, true);
  assert.equal(capabilitiesFor('xion').receive, true);
  assert.equal(capabilitiesFor('bsc').history, false);
  assert.equal(pageSupported('algorand', 'send'), false);
  assert.equal(pageSupported('ethereum', 'vaults'), false);
  assert.equal(pageSupported('nodus', 'contracts'), true);
  assert.equal(pageSupported('ckb', 'settings'), true);
});
test('hide zero balances keeps only networks with a displayable nonzero holding', () => {
  const unknown = { ...zero, state: 'idle', balance: null, units: undefined };
  const error = { ...unknown, state: 'error' };
  const held = { ...zero, symbol: 'USDT', units: 1n, balance: '0.000001', priceMissing: true, usd: null };
  assert.equal(zeroNetwork([]), true);
  for (const rows of [[zero], [unknown], [error], [zero, unknown], [zero, error]]) assert.equal(zeroNetwork(rows), true);
  for (const row of [held, { ...held, state: 'stale', keptAt: 1 }, { ...held, state: 'error', keptAt: 1 }]) {
    assert.equal(zeroNetwork([zero, row]), false);
  }
  assert.equal(zeroNetwork([{ ...held, balance: null }]), true);
  const rows = [zero, held, { ...unknown, chain: 'solana' }, { ...error, chain: 'tron' }];
  assert.deepEqual(groupNetworks(rows).map(g => g.chain), ['ethereum', 'solana', 'tron']);
  assert.deepEqual(groupNetworks(rows, { hideZero: true }), [{ chain: 'ethereum', rows: [held] }]);
  const retained = { ...held, state: 'error', keptAt: 1 };
  assert.deepEqual(groupNetworks([zero, unknown, retained], { hideZero: true }), [{ chain: 'ethereum', rows: [retained] }]);
  assert.deepEqual(groupNetworks([zero, unknown, retained]), [{ chain: 'ethereum', rows: [zero, unknown, retained] }]);
});

test('every configured holding keeps its network when displayable and nonzero', async () => {
  const { ASSETS, CPUNK_ASSET } = await import('../src/portfolio.js');
  const { PQ_ENTRIES } = await import('../src/pq/networks.js');
  const { NODUS_ASSET } = await import('../src/nodus/network.js');
  const { IXIOS_ASSET } = await import('../src/pq/ixios/network.js');
  const assets = [...ASSETS, CPUNK_ASSET, NODUS_ASSET, IXIOS_ASSET, ...PQ_ENTRIES.map(e => e.asset)];
  for (const asset of assets) {
    const rows = assets.filter(a => a.chain === asset.chain).map(a => ({ ...a, state: 'ready', balance: '0', units: 0n }));
    assert.equal(zeroNetwork(rows), true, asset.key);
    const target = rows.find(row => row.key === asset.key);
    target.units = 1n; target.balance = asset.decimals ? `0.${'0'.repeat(asset.decimals - 1)}1` : '1';
    assert.equal(zeroNetwork(rows), false, `${asset.key}: one raw unit`);
    target.balance = null; target.state = 'error';
    assert.equal(zeroNetwork(rows), true, `${asset.key}: unavailable`);
  }
});
test('unknown and inherited network names expose no capabilities', () => {
  for (const chain of ['__proto__', 'constructor', 'missing', null, {}]) {
    assert.ok(Object.values(capabilitiesFor(chain)).every(value => value === false));
  }
});
