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
    for (const name of ['send', 'receive']) {
      await page.locator(`.wallet-navigation a[href="#${name}"]`).click();
      await assertPage(name); await back(name);
    }
    for (const id of ['quick-send', 'quick-receive']) {
      await page.locator('#wallet-network > summary').click();
      const name = id === 'quick-send' ? 'send' : 'receive';
      await page.locator(`#${id}`).click(); await assertPage(name); await back(name);
    }
    const ethereum = page.locator('.asset-group[data-chain="ethereum"]');
    if (!await ethereum.evaluate(node => node.open)) await ethereum.locator('summary').click();
    await page.getByRole('button', { name: 'Select ETH on Ethereum', exact: true }).click();
    await page.locator('.wallet-navigation a[href="#send"]').click();
    await assertPage('send');
    await page.locator('#recipient').fill('public fixture draft'); await page.locator('#amount').fill('1.25');
    const recipient = await page.locator('#recipient').elementHandle();
    await back('send');
    await page.locator('.wallet-navigation a[href="#receive"]').click();
    assert.equal(await page.locator('#recipient').inputValue(), 'public fixture draft');
    assert.equal(await page.locator('#amount').inputValue(), '1.25');
    assert.equal(await recipient.evaluate(node => node === document.getElementById('recipient')), true);
    await back('receive');
    for (const name of ['send', 'receive']) {
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

// Wiring test through the real mounted wallet screen (portfolio-view, wallet-screen, the fixture's saved-record calls).
// Proves: (1) Ethereum read on Sepolia (5 ETH, kept under the test network), then the switch to Ethereum mainnet with the
// mainnet read HELD: no amount element of the Ethereum asset group reads 5 ETH (the group's own `.holding-value strong`
// elements, so a row that is absent also passes), the total is exactly the kept same-network values (the dash, see below),
// and no record saved after the switch holds the Sepolia units under a mainnet row; once released, the mainnet read (1 ETH)
// is what is saved under mainnet. (2) With a saved MAINNET row (3 ETH and its price) and the reads held, the page shows the
// kept total at once with its read label and counts it ($6.00).
// Negative controls measured by the orchestrator: with `visible()` in src/portfolio.js changed to ignore the row's network
// the Sepolia 5 ETH IS displayed on mainnet (and the old assertion on the concatenated #balances text did not see it, which
// is why the amount element is read now); before network binding (1a4b75b32) the first wait for a record saved under a
// `test:` network is never met, so the test times out. NOT a control: dceb7b6d3 already binds rows to the network, so this
// test passes there (49dfadffa only added the selected network id).
// How it can still falsely pass: the fixture is a fake background (no real storage or Sepolia RPC) and the Sepolia balance
// is the fixture's own 5; an unpriced Sepolia row leaves the total at the dash, so the total assertion alone would not catch
// a shown row (the amount-element assertion does); if the Ethereum group's markup changed (class or attribute names) the
// amount list would be empty and the assertion vacuous, which is why the list's length is also reported in the message.
// Not run by the builder.
test('a Sepolia balance is not shown or saved as the mainnet balance, and a mainnet kept value shows at once', { timeout: 90_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    const savedAfter = marker => page.evaluate(from => window.fixture.calls.slice(from).filter(call => call[0] === 'keepBalances').map(call => call[1][0]), marker);
    await page.evaluate(() => { window.fixture.state.networks.ethereum = 'sepolia'; window.fixture.screen.update(); });
    await page.waitForFunction(() => window.fixture.calls.some(call => call[0] === 'keepBalances' && call[1][0]['ethereum:ETH']?.network?.startsWith('test:') && call[1][0]['ethereum:ETH'].units === '5000000000000000000'));
    await page.evaluate(() => { window.fixture.holdEvm(true); window.fixture.state.networks.ethereum = 'mainnet'; window.fixture.screen.update(); });
    const marker = await page.evaluate(() => window.fixture.calls.length);
    await page.waitForFunction(from => window.fixture.calls.slice(from - 1).some(call => call[0] === 'getEvmBalances' && call[1][0] === 'ethereum'), marker);
    // The label may legitimately read "Last read ... updating": the first mainnet read kept Ethereum's token rows (USDT, USDC, ...
    // at 0 units, mainnet), which the Sepolia read (ETH only, no tokens) did not replace, and they are shown as kept mainnet
    // values while the held mainnet read refreshes. What matters: the ETH row has no Sepolia value, and the total is exactly
    // the kept same-network values. Those are zero-unit token rows valued at $0 with no fresh priced balance and the other
    // priced rows unknown (BNB read failed), so the total is 0 and incomplete, which the page shows as the dash; with the
    // Sepolia 5 ETH wrongly counted it would be $10.00 (5 ETH at the fixture's $2).
    // The Ethereum group's own amount elements (`${amount} ${symbol}`), not the concatenated list text: the row's "Last read"
    // small text follows the amount without a separator. A hidden or absent row gives no element, which also passes.
    const ethereumAmounts = await page.locator('.asset-group[data-chain="ethereum"] .holding-value strong').allTextContents();
    assert.ok(!ethereumAmounts.some(text => /^5(\.0+)? ETH$/.test(text.trim())), `a Sepolia balance is shown as the mainnet ETH balance (${ethereumAmounts.length} amounts: ${ethereumAmounts.join(' | ')})`);
    assert.equal(await page.locator('#portfolio-total').textContent(), '—');
    for (const saved of await savedAfter(marker)) assert.ok(!(saved['ethereum:ETH']?.network === 'main' && saved['ethereum:ETH'].units === '5000000000000000000'), 'a Sepolia value was saved under mainnet');
    await page.evaluate(() => window.fixture.releaseEvm());
    await page.waitForFunction(from => window.fixture.calls.slice(from).some(call => call[0] === 'keepBalances' && call[1][0]['ethereum:ETH']?.network === 'main' && call[1][0]['ethereum:ETH'].units === '1000000000000000000'), marker);
  });
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html?kept&holdevm`);
    await page.waitForFunction(() => /^Last read .+ · updating$/.test(document.getElementById('portfolio-label')?.textContent ?? ''));
    assert.equal(await page.locator('#portfolio-total').textContent(), '$6.00');
    await page.evaluate(() => window.fixture.releaseEvm());
  });
});
