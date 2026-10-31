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
test('hide zero networks requires fresh confirmed zero for every holding', () => {
  assert.equal(zeroNetwork([]), false);
  assert.equal(zeroNetwork([zero]), true);
  for (const state of ['loading', 'error', 'idle', 'unsupported', 'stale']) assert.equal(zeroNetwork([{ ...zero, state }]), false);
  assert.equal(zeroNetwork([{ ...zero, keptAt: 1 }]), false);
  assert.equal(zeroNetwork([{ ...zero, balance: null }]), false);
  assert.equal(zeroNetwork([zero, { ...zero, symbol: 'USDT', units: 1n, balance: '0.000001' }]), false);
});
test('network grouping preserves tokens and all networks independent of selection', () => {
  const rows = [zero, { ...zero, symbol: 'USDT', units: 1n }, { ...zero, chain: 'solana' }];
  assert.deepEqual(groupNetworks(rows).map(g => [g.chain, g.rows.length]), [['ethereum', 2], ['solana', 1]]);
  assert.deepEqual(groupNetworks(rows, { hideZero: true }).map(g => g.chain), ['ethereum']);
});

test('every configured holding prevents network hiding when positive or unreadable', async () => {
  const { ASSETS, CPUNK_ASSET } = await import('../src/portfolio.js');
  const { PQ_ENTRIES } = await import('../src/pq/networks.js');
  const { NODUS_ASSET } = await import('../src/nodus/network.js');
  const { IXIOS_ASSET } = await import('../src/ixios/network.js');
  const assets = [...ASSETS, CPUNK_ASSET, NODUS_ASSET, IXIOS_ASSET, ...PQ_ENTRIES.map(e => e.asset)];
  for (const asset of assets) {
    const rows = assets.filter(a => a.chain === asset.chain).map(a => ({ ...a, state: 'ready', balance: '0', units: 0n }));
    assert.equal(zeroNetwork(rows), true, asset.key);
    const target = rows.find(row => row.key === asset.key);
    target.units = 1n; target.balance = asset.decimals ? `0.${'0'.repeat(asset.decimals - 1)}1` : '1';
    assert.equal(zeroNetwork(rows), false, `${asset.key}: one raw unit`);
    target.units = 0n; target.balance = '0'; target.state = 'error';
    assert.equal(zeroNetwork(rows), false, `${asset.key}: failed zero`);
  }
});
test('unknown and inherited network names expose no capabilities', () => {
  for (const chain of ['__proto__', 'constructor', 'missing', null, {}]) {
    assert.ok(Object.values(capabilitiesFor(chain)).every(value => value === false));
  }
});
