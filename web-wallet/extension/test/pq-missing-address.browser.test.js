import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const addresses = JSON.parse(readFileSync(new URL('../../test/fixtures/pq-receive.json', import.meta.url))).vectors[0].addresses.qtc;
import { withPortfolioPage } from './fixtures/portfolio-page-checks.js';

test('settled missing PQ addresses stop loading and recover only for the selected environment', async () => {
  await withPortfolioPage(async (page, origin) => {
    const requests = [];
    await page.route('**/*', route => {
      if (new URL(route.request().url()).origin === origin) return route.continue();
      requests.push(route.request().url()); return route.abort('blockedbyclient');
    });
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    const settled = async () => {
      await page.waitForFunction(() => document.querySelector('#portfolio-label').textContent !== 'Updating portfolio');
      assert.equal(await page.locator('.network-health[data-reading="true"]').count(), 0);
      assert.equal(await page.locator('#portfolio-refresh').isDisabled(), false);
    };
    await settled();
    assert.equal(await page.locator('#portfolio-total').textContent(), '$2.00');
    // No native balance request may be issued with an absent address.
    assert.equal(requests.length, 0);
    await page.evaluate(async addresses => {
      const f = window.fixture;
      f.state.networks.qtc = 'mainnet';
      f.state.pqAddresses = { qtc: { testnet: addresses.testnet } };
      f.screen.update(); await f.screen.loadBalances(true);
    }, addresses);
    await settled();
    assert.equal(requests.length, 0);
    await page.evaluate(async addresses => {
      const f = window.fixture;
      f.state.pqAddresses.qtc.mainnet = addresses.mainnet;
      f.screen.update(); await f.screen.loadBalances(true);
    }, addresses);
    await settled();
    assert.ok(requests.length > 0, 'Restored selected address resumes its public reader');
    const before = requests.length;
    await page.evaluate(async () => {
      const f = window.fixture; delete f.state.pqAddresses.qtc.mainnet;
      f.screen.update(); await f.screen.loadBalances(true);
      f.calls.length = 0; await f.screen.loadBalances(true);
    });
    await settled();
    assert.equal(requests.length, before, 'Missing address stops subsequent reads');
  });
});
