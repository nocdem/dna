import test from 'node:test';
import assert from 'node:assert/strict';
import { portfolioReaders } from '../src/ui/wallet-page.js';

// Package A: distinct replies pin every trusted method and its parameters.
// Node >=22, no flags/network/artifacts. Identical replies could falsely pass.
test('portfolio reads every chain through its own trusted background method', async () => {
  const calls = [], ui = { request: async (method, args = []) => { calls.push([method, args]); return method; } };
  const readers = portfolioReaders(ui);
  for (const chain of ['nodus', 'ethereum', 'bsc', 'solana', 'tron', 'cellframe', 'ixios']) {
    const value = await readers.readBalances(chain);
    assert.equal(value[0]?.symbol || value, chain === 'cellframe' ? 'CPUNK' : calls.at(-1)[0]);
  }
  assert.deepEqual(calls, [['getNodusBalances', []], ['getEvmBalances', ['ethereum']], ['getEvmBalances', ['bsc']],
    ['getSolanaBalances', []], ['getTronBalances', []], ['getCpunkBalance', []], ['getIxiosBalance', []]]);
  await assert.rejects(readers.readBalances('invented'), /Unsupported/);
});

// A failed BSC read must remove a previously priced BNB balance, while a
// distinct Ethereum balance stays counted. A fixture that never succeeds on
// BSC could miss stale values retained in the total. No live RPC/artifacts.
test('a chain whose read fails is left out of the total', { timeout: 60_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    assert.equal(await page.locator('#portfolio-total').textContent(), '$2.00');
    await page.evaluate(async () => { window.fixture.bscFails(false); await window.fixture.screen.loadBalances(true); });
    assert.equal(await page.locator('#portfolio-total').textContent(), '$8.00');
    await page.evaluate(async () => { window.fixture.bscFails(true); await window.fixture.screen.loadBalances(true); });
    assert.equal(await page.locator('#portfolio-total').textContent(), '$2.00');
    assert.equal(await page.locator('.network-health[data-chain="bsc"]').getAttribute('data-health'), 'failed');
    assert.equal(await page.locator('.network-health[data-chain="ethereum"]').getAttribute('data-health'), 'current');
  });
});
