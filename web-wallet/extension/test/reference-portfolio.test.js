import test from 'node:test';
import assert from 'node:assert/strict';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { ASSETS, PRICE_MAX_AGE, usdText, displayAmount } from '../../src/portfolio.js';
import { DEFAULT_NETWORKS } from '../src/constants/networks.js';

// Node >=22.14. No flags/network/artifacts. Uses the test clock for each
// returned price. Proves the screen's snapshot keeps unpriced native rows,
// excludes failed-chain/testnet values, and expires prices without UI state
// churn. Does not prove background RPC validation or browser form retention.
test('reference portfolio keeps native rows and excludes failed chains and testnet money', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: 100_000 });
  const state = { isUnlocked: true, addresses: {}, evm: {}, nodus: { state: 'ready', tokens: [] },
    networks: { ...DEFAULT_NETWORKS, solana: 'devnet', tron: 'nile' } };
  state.addresses = { solana: 'public-solana', tron: 'public-tron' };
  const ui = createWalletUi({ async request(method, params) {
    if (method === 'getState') return structuredClone(state);
    if (method === 'getPrices') return Object.fromEntries(ASSETS.map(asset => [asset.key,
      { units: asset.key === 'ethereum:ETH' ? '200000000' : '100000000', observedAt: Date.now() }]));
    if (method === 'getNodusBalances') return [{ symbol: 'NODUS', balance: '12.34' }];
    if (method === 'getCpunkBalance') return { balance: '7' };
    if (method === 'getEvmBalances' && params[0] === 'bsc') throw new Error('Fixture balance failure');
    if (method === 'getEvmBalances') return ASSETS.filter(asset => asset.chain === 'ethereum').map(asset =>
      ({ symbol: asset.symbol, balance: asset.symbol === 'ETH' ? '1' : '0' }));
    if (method === 'getSolanaBalances') return [{ symbol: 'SOL', balance: '1000' }];
    if (method === 'getTronBalances') return [{ symbol: 'TRX', balance: '2000' }];
    throw new Error(`Unexpected fixture method ${method}`);
  } });
  await ui.refresh();
  await Promise.all([ui.loadEvmBalances(), ui.loadNodusBalances(), ui.loadSolanaTronBalances(), ui.loadPrices()]);
  const { snapshot } = ui.portfolioDetails();
  assert.equal(usdText(snapshot.total), '$2.00');
  assert.equal(snapshot.rows.find(row => row.key === 'nodus:NODUS').balance, '12.34');
  // src/portfolio.js:117,183-189: the exact snapshot and visible amount have different forms.
  const cpunk = snapshot.rows.find(row => row.key === 'cellframe:CPUNK');
  assert.equal(cpunk.balance, '7.0'); assert.equal(displayAmount(cpunk.balance), '7');
  assert.equal(snapshot.rows.find(row => row.key === 'solana:SOL').priceId, undefined);
  assert.equal(snapshot.rows.find(row => row.key === 'tron:TRX').priceId, undefined);
  assert.equal(snapshot.rows.filter(row => row.chain === 'bsc').every(row => row.state === 'error' && row.usd === null), true);
  assert.equal(snapshot.rows.some(row => ['solana', 'tron'].includes(row.chain) && row.symbol.startsWith('USD')), false);
  const before = JSON.stringify(ui.state);
  t.mock.timers.tick(PRICE_MAX_AGE + 1);
  assert.equal(ui.portfolioDetails().snapshot.total, null);
  assert.equal(JSON.stringify(ui.state), before);
});
