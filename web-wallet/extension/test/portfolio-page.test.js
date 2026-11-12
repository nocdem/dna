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
    ['getSolanaBalances', []], ['getTronBalances', []], ['getCpunkBalance', []], ['getIxiosBalance', ['mainnet']]]);
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
    // priced rows unknown (BNB read failed), so the total is 0 and incomplete, which the page shows as the dash. The total
    // assertion catches only a leak that is VALUED (a price attached to the test row under mainnet would give $10.00); a Sepolia
    // row that is merely SHOWN keeps the dash, because a test-network row is kept without a price (measured with visible()
    // ignoring the network: the page showed 5 ETH and the total stayed the dash). The amount-element assertion below catches
    // the shown leak.
    // The Ethereum group's own amount elements (`${amount} ${symbol}`), not the concatenated list text: the row's "Last read"
    // small text follows the amount without a separator. A hidden or absent row gives no element, which also passes.
    const ethereumAmounts = await page.locator('.asset-group[data-chain="ethereum"] .holding-value strong').allTextContents();
    assert.ok(!ethereumAmounts.some(text => /^5(\.0+)? ETH$/.test(text.trim())), `a Sepolia balance is shown as the mainnet ETH balance (${ethereumAmounts.length} amounts: ${ethereumAmounts.join(' | ')})`);
    assert.equal(await page.locator('#portfolio-total').textContent(), '—');
    for (const saved of await savedAfter(marker)) assert.ok(!(saved['ethereum:ETH']?.network === 'main' && saved['ethereum:ETH'].units === '5000000000000000000'), 'a Sepolia value was saved under mainnet');
    await page.evaluate(() => window.fixture.releaseEvm());
    await page.waitForFunction(from => window.fixture.calls.slice(from).some(call => call[0] === 'keepBalances' && call[1][0]['ethereum:ETH']?.network === 'main' && call[1][0]['ethereum:ETH'].units === '1000000000000000000'), marker);
    // Every record saved since the switch (at least the 1 ETH one above): none holds the Sepolia units under mainnet.
    const savedAll = await savedAfter(marker);
    assert.ok(savedAll.length > 0, 'no record was saved after the switch');
    for (const saved of savedAll) assert.ok(!(saved['ethereum:ETH']?.network === 'main' && saved['ethereum:ETH'].units === '5000000000000000000'), 'a Sepolia value was saved under mainnet');
    // Positive control for the amount selector: the same locator finds the mainnet amount as the page formats it (displayAmount
    // of 1 ETH), so a markup change cannot make the assertions above vacuous.
    await page.waitForFunction(() => [...document.querySelectorAll('.asset-group[data-chain="ethereum"] .holding-value strong')].some(node => node.textContent.trim() === '1 ETH'));
    const releasedAmounts = await page.locator('.asset-group[data-chain="ethereum"] .holding-value strong').allTextContents();
    assert.ok(releasedAmounts.some(text => text.trim() === '1 ETH'), `the selector does not find the mainnet ETH amount (${releasedAmounts.join(' | ')})`);
  });
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html?kept&holdevm`);
    await page.waitForFunction(() => /^Last read .+ · updating$/.test(document.getElementById('portfolio-label')?.textContent ?? ''));
    assert.equal(await page.locator('#portfolio-total').textContent(), '$6.00');
    await page.evaluate(() => window.fixture.releaseEvm());
  });
});

// Wiring test for two test networks of ONE chain through the real mounted screen (wallet-screen.js passes the selected
// network's id with the definition, 49dfadffa). Solana Testnet answers 777 SOL, Devnet 1000. Proves: after a read on Testnet,
// switching to Devnet with its read HELD shows no 777 SOL (the kept Testnet row is not shown as Devnet's), and after the
// release the Devnet amount (1,000 SOL) is shown. Positive controls: the same selector finds 777 SOL while Testnet is
// selected and 1,000 SOL after the release, so it matches real markup. The screen saves no Solana record off mainnet
// (wallet-screen.js onKept filter), so no record is expected or waited for; the assertion that no record carries the Testnet
// units is therefore guaranteed by that filter, not by the network identity, and only the amount assertions test the identity.
// Negative control (by reasoning, not run): with equal identities for Testnet and Devnet (the code before 49dfadffa) the kept
// 777 SOL row stays visible after the switch and the assertion fails. How it can falsely pass: the fake background answers
// both networks without real RPC; if update() did not reach portfolio.setNetwork for the id change the first wait (777 SOL
// shown) would not be met and the test would time out. Not run by the builder.
test('a Solana Testnet balance is not shown as the Devnet balance while Devnet is read', { timeout: 90_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    const amounts = () => page.locator('.asset-group[data-chain="solana"] .holding-value strong').allTextContents();
    await page.evaluate(() => { window.fixture.state.networks.solana = 'testnet'; window.fixture.screen.update(); });
    await page.waitForFunction(() => [...document.querySelectorAll('.asset-group[data-chain="solana"] .holding-value strong')].some(node => node.textContent.trim() === '777 SOL'));
    assert.ok((await amounts()).some(text => text.trim() === '777 SOL'), 'positive control: the Testnet amount is found by the selector');
    await page.evaluate(() => { window.fixture.holdSolana(true); window.fixture.state.networks.solana = 'devnet'; window.fixture.screen.update(); });
    const marker = await page.evaluate(() => window.fixture.calls.length);
    await page.waitForFunction(from => window.fixture.calls.slice(from - 1).some(call => call[0] === 'getSolanaBalances'), marker);
    const held = await amounts();
    assert.ok(!held.some(text => text.trim() === '777 SOL'), `a Solana Testnet balance is shown as the Devnet balance (${held.join(' | ')})`);
    for (const call of await page.evaluate(from => window.fixture.calls.slice(from).filter(call => call[0] === 'keepBalances'), marker)) {
      assert.ok(call[1][0]['solana:SOL'] === undefined || call[1][0]['solana:SOL'].units !== '777000000000', 'the Testnet units were saved after the switch');
    }
    await page.evaluate(() => window.fixture.releaseSolana());
    await page.waitForFunction(() => [...document.querySelectorAll('.asset-group[data-chain="solana"] .holding-value strong')].some(node => node.textContent.trim() === '1,000 SOL'));
    assert.ok((await amounts()).some(text => text.trim() === '1,000 SOL'), 'positive control: the Devnet amount is found by the selector');
  });
});

// Ixios kept balances across its two networks, through the real mounted screen (plan D9; red-team note 2,
// docs/plans/2026-11-12-ixios-testnet-plan.redteam.md:61-67). The mainnet Ixios read answers 8 IXIOS (the fixture's), the test
// network 777, supplied here by wrapping the fixture's request function (the fixture file itself is not changed).
// Proves: (1) on the test network 777 IXIOS is shown, and no record saved from then on holds an Ixios entry at all (the
// mainnet-only save filter); (2) after the switch back to mainnet with the mainnet read HELD, no amount of the Ixios group reads
// 777 IXIOS, and no saved record holds the 777 units, under any network identity; (3) once released, the mainnet 8 IXIOS is
// shown and saved under the main identity. Every record saved in the whole test (what an unlock would load) holds an Ixios entry
// only as the mainnet value 8 IXIOS under 'main', so after a lock and an unlock no test-network value can be shown as the
// mainnet one (the fixture cannot lock and unlock the screen, so this is asserted on the saved records themselves).
// Positive controls: the same selector finds 777 IXIOS on the test network and 8 IXIOS after the release.
// Falsely passes if: the filter and the identity both failed but no record was ever saved (the wait for a record saved after
// the test-network read prevents that), or the group markup changed (the positive controls would fail). Not run by the builder.
test('a test-network Ixios balance is not shown or saved as the mainnet balance', { timeout: 90_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    const amounts = () => page.locator('.asset-group[data-chain="ixios"] .holding-value strong').allTextContents();
    const shown = text => page.waitForFunction(expected => [...document.querySelectorAll('.asset-group[data-chain="ixios"] .holding-value strong')].some(node => node.textContent.trim() === expected), text);
    const saved = from => page.evaluate(start => window.fixture.calls.slice(start).filter(call => call[0] === 'keepBalances').map(call => call[1][0]), from);
    await page.evaluate(() => {
      const ui = window.fixture.ui, original = ui.request.bind(ui), waiting = []; let held = false;
      window.fixture.holdIxios = value => { held = value; if (!value) for (const resolve of waiting.splice(0)) resolve(); };
      ui.request = async (method, args = []) => {
        if (method !== 'getIxiosBalance') return original(method, args);
        window.fixture.calls.push([method, args]);
        if (args[0] === 'testnet') return [{ symbol: 'IXIOS', balance: '777' }];
        if (held) await new Promise(resolve => waiting.push(resolve));
        return original(method, args);
      };
      window.fixture.state.networks.ixios = 'mainnet'; window.fixture.screen.update(); window.fixture.screen.loadBalances(true);
    });
    await shown('8 IXIOS');
    const first = await page.evaluate(() => window.fixture.calls.length);
    await page.evaluate(() => { window.fixture.state.networks.ixios = 'testnet'; window.fixture.screen.update(); });
    await shown('777 IXIOS');
    assert.ok((await amounts()).some(text => text.trim() === '777 IXIOS'), 'positive control: the test-network amount is found by the selector');
    assert.ok((await page.evaluate(() => window.fixture.calls.filter(call => call[0] === 'getIxiosBalance').map(call => call[1][0]))).includes('testnet'), 'the portfolio asked for the test network');
    await page.waitForFunction(from => window.fixture.calls.slice(from).some(call => call[0] === 'keepBalances'), first);
    for (const record of await saved(first)) assert.equal(record['ixios:IXIOS'], undefined, 'a record saved on the test network holds an Ixios entry');
    await page.evaluate(() => { window.fixture.holdIxios(true); window.fixture.state.networks.ixios = 'mainnet'; window.fixture.screen.update(); });
    const second = await page.evaluate(() => window.fixture.calls.length);
    await page.waitForFunction(from => window.fixture.calls.slice(from - 1).some(call => call[0] === 'getIxiosBalance' && call[1][0] === 'mainnet'), second);
    const held = await amounts();
    assert.ok(!held.some(text => text.trim() === '777 IXIOS'), `a test-network Ixios balance is shown as the mainnet balance (${held.join(' | ')})`);
    for (const record of await saved(second)) assert.ok(record['ixios:IXIOS'] === undefined || record['ixios:IXIOS'].units !== '777000000000000000000', 'the test units were saved after the switch');
    await page.evaluate(() => window.fixture.holdIxios(false));
    await shown('8 IXIOS');
    assert.ok((await amounts()).some(text => text.trim() === '8 IXIOS'), 'positive control: the mainnet amount is found by the selector');
    await page.waitForFunction(from => window.fixture.calls.slice(from).some(call => call[0] === 'keepBalances' && call[1][0]['ixios:IXIOS']?.network === 'main' && call[1][0]['ixios:IXIOS'].units === '8000000000000000000'), second);
    for (const record of await saved(0)) assert.ok(record['ixios:IXIOS'] === undefined || (record['ixios:IXIOS'].network === 'main' && record['ixios:IXIOS'].units === '8000000000000000000'), 'every saved Ixios value is the mainnet one');
  });
});
