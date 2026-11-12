import test from 'node:test';
import assert from 'node:assert/strict';
import { keccak256 } from 'ethers';
import { setup, password, unlockOptions } from './solana-tron-fixture.js';
import { ixiosFixture } from './ixios-fixture.js';
import { ACTIVITY_KEY } from '../../src/vault.js';

// Ixios test network, Step B follow-up cases (Sol verifier report 2026-11-12). Node >=22.14; the browser cases use the
// loopback Vite and Chromium of the other portfolio-page tests, no live RPC, nothing left on disk. Not run by the builder.

// Item 1. Proves: the local-history route, asked FIRST after an unlock (no other Ixios call before it), returns the rows saved
// in the selected network's bucket. A network bucket restores its saved rows asynchronously; a route that read the rows at once
// returned an empty list. Falsely passes if something else had loaded the bucket before the route: the send, lock and unlock
// come first and the route is the first Ixios call after the unlock (the unlock itself creates no bucket); the sent hash is
// compared, so an empty list cannot satisfy it.
test('the local-history route returns saved rows when it is the first call after an unlock', async t => {
  const { background, client, values } = await setup(t), f = await ixiosFixture(t);
  f.setCallback(async bytes => keccak256(bytes));
  await client.request('setChainNetwork', ['ixios', 'testnet']);
  const review = await client.request('prepareIxiosSend', [{ symbol: 'IXIOS', to: f.to, amount: '1', maxGasPrice: '100000000000000000' }]);
  const hash = await client.request('confirmIxiosSend', [review.id]);
  assert.ok(values[`${ACTIVITY_KEY}.ixios.testnet`], 'the row is saved');
  await background.lock(); await background.unlock(password, unlockOptions);
  await client.request('setChainNetwork', ['ixios', 'testnet']);
  assert.deepEqual((await client.request('getChainLocalHistory', ['ixios'])).map(row => row.hash), [hash]);
  await client.request('setChainNetwork', ['ixios', 'mainnet']);
  assert.deepEqual(await client.request('getChainLocalHistory', ['ixios']), [], 'mainnet shows no test-network row');
});

// Items 2 and 3 run on the real mounted wallet screen (fixtures/functions.html). The fixture answers 8 IXIOS for the Ixios main
// network and 777 for the test network (the request's argument), can hold Ixios reads (`?holdixios`, holdIxios/releaseIxios) and
// can seed the saved record with one Ixios entry (`?keptixios=<JSON>`). The screen has no lock path of its own (the app shell
// locks): an "unlock" is a fresh mount of the screen with the saved record, which is what an unlock does to the portfolio.
const amounts = page => page.locator('.asset-group[data-chain="ixios"] .holding-value strong').allTextContents();
const shown = (page, text) => page.waitForFunction(expected => [...document.querySelectorAll('.asset-group[data-chain="ixios"] .holding-value strong')].some(node => node.textContent.trim() === expected), text);
const saved = (page, from) => page.evaluate(start => window.fixture.calls.slice(start).filter(call => call[0] === 'keepBalances').map(call => call[1][0]), from);
// While the Ixios read is held and no kept Ixios value is admitted, the Ixios group is NOT rendered: with zero balances hidden
// (the default) a network group is listed only if one of its rows is a displayed holding (a known, non-zero amount), and a row
// that is still being read has no amount (src/portfolio.js:280 displayedHolding, :284-291 groupNetworks). That is the designed
// behaviour, not a defect. So these helpers read what is rendered without waiting for the group: the text of every Ixios group
// element that exists (empty if none) and the text of the whole page. The positive control that the page is not simply empty is
// the wait for '8 IXIOS' after releaseIxios().
const ixiosGroupText = page => page.evaluate(() => [...document.querySelectorAll('.asset-group[data-chain="ixios"]')].map(node => node.textContent).join(' | '));
const pageText = page => page.evaluate(() => document.body.textContent);
const asked = page => page.waitForFunction(() => window.fixture?.calls?.some(call => call[0] === 'getIxiosBalance'));
const TEST_UNITS = '777000000000000000000';

// Item 2 (red-team note 2, docs/plans/2026-11-12-ixios-testnet-plan.redteam.md:61-67). The window: the state already says
// mainnet, update() has not run, and a test-network Ixios read completes and reaches onKept. Proves: (a) no record saved in the
// window holds the test units under the identity 'main' (a record under the test identity is allowed: it is only shown on the
// test network); (b) after update() the mainnet 8 IXIOS is shown and no amount reads 777; (c) a fresh mount of the screen on that
// saved record (the unlock) with the mainnet read held does not show 777 IXIOS or a "Last read" for Ixios.
// The window is entered in ONE synchronous page step (state to mainnet, then the release), and the test read was requested
// before it (the wait on the request). Falsely passes if the held read never completed inside the window: the test waits for a
// record saved after the release; if the screen saved no Ixios record at all there, the identity check has nothing to look at
// and (c) runs only when a record with the test units exists. Positive control: the selector finds 8 IXIOS after update().
test('a test-network Ixios read finishing between the state change and update() is not saved or shown as the mainnet balance', { timeout: 90_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  let gap;
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    await shown(page, '8 IXIOS');
    await page.evaluate(() => { window.fixture.holdIxios(true); window.fixture.state.networks.ixios = 'testnet'; window.fixture.screen.update(); });
    await page.waitForFunction(() => window.fixture.calls.some(call => call[0] === 'getIxiosBalance' && call[1][0] === 'testnet'));
    const marker = await page.evaluate(() => window.fixture.calls.length);
    await page.evaluate(() => { window.fixture.state.networks.ixios = 'mainnet'; window.fixture.releaseIxios(); });
    await page.waitForFunction(from => window.fixture.calls.slice(from).some(call => call[0] === 'keepBalances'), marker);
    const inWindow = await saved(page, marker);
    for (const record of inWindow) {
      const entry = record['ixios:IXIOS'];
      assert.ok(!(entry && entry.network === 'main' && entry.units === TEST_UNITS), 'the test units were saved under the mainnet identity');
    }
    gap = inWindow.map(record => record['ixios:IXIOS']).find(entry => entry?.units === TEST_UNITS);
    if (gap) assert.notEqual(gap.network, 'main');
    await page.evaluate(() => window.fixture.screen.update());
    await shown(page, '8 IXIOS');
    assert.ok((await amounts(page)).some(text => text.trim() === '8 IXIOS'), 'positive control: the mainnet amount is found by the selector');
    assert.ok(!(await amounts(page)).some(text => text.trim() === '777 IXIOS'), 'the test balance is shown as the mainnet balance');
    for (const record of await saved(page, marker)) {
      const entry = record['ixios:IXIOS'];
      assert.ok(!(entry && entry.network === 'main' && entry.units === TEST_UNITS), 'the test units were saved under the mainnet identity');
    }
  });
  if (!gap) return;
  await withPortfolioPage(async (page, origin) => {
    const entry = encodeURIComponent(JSON.stringify({ units: gap.units, network: gap.network }));
    await page.goto(`${origin}/test/fixtures/functions.html?holdixios&keptixios=${entry}`);
    await asked(page);
    const held = (await amounts(page)).map(text => text.trim());
    assert.ok(!held.includes('777 IXIOS'), `the saved test value is shown as the mainnet balance (${held.join(' | ')})`);
    assert.doesNotMatch(await ixiosGroupText(page), /Last read/);
    assert.doesNotMatch(await pageText(page), /777(\.0+)? IXIOS/, 'a 777 IXIOS amount is rendered somewhere');
    await page.evaluate(() => window.fixture.releaseIxios());
    await shown(page, '8 IXIOS');
  });
});

// Item 3 (plan 9.3 "Kept balances do not cross"). With the Ixios read HELD at open, the saved record decides what is shown.
// Proves: a saved MAINNET Ixios entry (9 IXIOS) is shown at once as "Last read" at the first definition after the unlock (it is
// not forgotten), then replaced by the read (8 IXIOS); a saved entry carrying the TEST-network identity (777 IXIOS, identity
// computed by src/portfolio.js networkIdOf for the extension's test definition) is not shown at all while mainnet is selected,
// and the read's 8 IXIOS replaces nothing visible. Falsely passes if the held read were answered before the first assertion:
// the page waits for the request and the read stays held until the explicit release. Positive control: the first case finds
// the kept amount with the same selector as the second.
test('a saved mainnet Ixios value is shown at the first definition after unlock; a saved test-network value is not', { timeout: 90_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js'), { networkIdOf } = await import('../../src/portfolio.js');
  const testIdentity = networkIdOf({ testnet: true, networkId: 'testnet', endpoint: 'https://nx-rpc.ixoflow.io' });
  assert.notEqual(testIdentity, 'main');
  await withPortfolioPage(async (page, origin) => {
    const entry = encodeURIComponent(JSON.stringify({ units: '9000000000000000000', network: 'main' }));
    await page.goto(`${origin}/test/fixtures/functions.html?holdixios&keptixios=${entry}`);
    await asked(page);
    await shown(page, '9 IXIOS');
    assert.match(await page.locator('.asset-group[data-chain="ixios"] .holding-value small').first().textContent(), /Last read/);
    await page.evaluate(() => window.fixture.releaseIxios());
    await shown(page, '8 IXIOS');
  });
  await withPortfolioPage(async (page, origin) => {
    const entry = encodeURIComponent(JSON.stringify({ units: TEST_UNITS, network: testIdentity }));
    await page.goto(`${origin}/test/fixtures/functions.html?holdixios&keptixios=${entry}`);
    await asked(page);
    const held = (await amounts(page)).map(text => text.trim());
    assert.ok(!held.includes('777 IXIOS'), `a saved test-network value is shown on mainnet (${held.join(' | ')})`);
    assert.doesNotMatch(await ixiosGroupText(page), /Last read/);
    assert.doesNotMatch(await pageText(page), /777(\.0+)? IXIOS/, 'a 777 IXIOS amount is rendered somewhere');
    await page.evaluate(() => window.fixture.releaseIxios());
    await shown(page, '8 IXIOS');
  });
});
