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
    assert.equal(await page.locator('#portfolio-status').isVisible(), false);
    assert.equal(await page.locator('.network-health[data-chain="bsc"]').getAttribute('data-health'), 'failed');
    assert.equal(await page.locator('.network-health[data-chain="ethereum"]').getAttribute('data-health'), 'current');
  });
});

// Public replies on the real mounted controller, loopback Vite and Chromium.
// No flags/live RPC/artifacts. Checks links, shortcuts, holding actions and
// direct hashes; checking hidden properties alone could miss broken wiring.
test('portfolio and transfers open pages with Back to wallet and a home-only greeting', { timeout: 60_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    const heading = page.locator('#wallet-heading');
    assert.equal(await heading.isVisible(), true);
    const assertPage = async name => {
      assert.equal(await page.locator('#wallet-home').isVisible(), false);
      assert.equal(await heading.isVisible(), false);
      assert.equal(await page.locator(`#page-${name}`).isVisible(), true);
      assert.equal(await page.locator('.wallet-page:visible').count(), 1);
      assert.equal(await page.evaluate(() => location.hash), `#${name}`);
      assert.match(await page.locator(`#page-${name} > .page-back`).textContent(), /Back to wallet/u);
    };
    const back = async name => {
      await page.locator(`#page-${name} > .page-back`).click();
      assert.equal(await heading.isVisible(), true);
      assert.equal(await page.locator('#wallet-home').isVisible(), true);
      assert.equal(await page.locator('.wallet-page:visible').count(), 0);
    };
    for (const name of ['assets-panel', 'send-form']) {
      await page.locator(`.wallet-navigation a[href="#${name}"]`).click();
      await assertPage(name); await back(name);
    }
    for (const id of ['quick-send', 'quick-receive']) {
      await page.locator(`#${id}`).click(); await assertPage('send-form'); await back('send-form');
    }
    await page.locator('.wallet-navigation a[href="#assets-panel"]').click();
    await page.locator('.asset-group[data-symbol="ETH"] > summary').click();
    await page.getByRole('button', { name: 'Send ETH on Ethereum', exact: true }).click();
    await assertPage('send-form');
    await page.locator('#recipient').fill('public fixture draft'); await page.locator('#amount').fill('1.25');
    const recipient = await page.locator('#recipient').elementHandle();
    await back('send-form');
    await page.locator('#quick-receive').click();
    assert.equal(await page.locator('#recipient').inputValue(), 'public fixture draft');
    assert.equal(await page.locator('#amount').inputValue(), '1.25');
    assert.equal(await recipient.evaluate(node => node === document.getElementById('recipient')), true);
    await back('send-form');
    for (const name of ['assets-panel', 'send-form']) {
      await page.evaluate(value => { location.hash = value; }, name);
      await page.locator(`#page-${name}:visible`).waitFor(); await assertPage(name);
      await page.reload(); await page.waitForFunction(() => window.fixture?.ready);
      await assertPage(name); await back(name);
    }
    await page.evaluate(() => {
      Object.assign(window.fixture.state.nodus, { vaultable: true }); window.fixture.screen.update();
    });
    await page.locator('#nav-vaults').click(); await assertPage('vaults');
    const backButton = page.locator('#page-vaults > .page-back');
    const panel = page.locator('#vault-panel');
    assert.ok((await backButton.boundingBox()).y < (await panel.boundingBox()).y);
    await back('vaults');
  });
});
