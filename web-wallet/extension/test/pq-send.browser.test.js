import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { withPortfolioPage, selectFixtureNetwork } from './fixtures/portfolio-page-checks.js';

const addresses = JSON.parse(readFileSync(new URL('../../test/fixtures/pq-receive.json', import.meta.url))).vectors[0].addresses;
const enabled = ['algorand', 'soqucoin', 'ckb', 'qtc', 'xion', 'splendor', 'asentum', 'ixios'];

test('real Chromium routes all eight trusted send forms through review and cancellation, with TDC disabled', { timeout: 120_000 }, async () => {
  await withPortfolioPage(async (page, origin) => {
    // Only loopback assets may leave this browser. Provider availability is
    // deliberately negative here; signing/transport have separate real-WASM tests.
    await page.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort('blockedbyclient'));
    await page.goto(`${origin}/test/fixtures/functions.html`);
    await page.waitForFunction(() => window.fixture?.ready);
    await page.evaluate(addresses => {
      const f = window.fixture;
      f.state.pqAddresses = addresses;
      for (const chain of Object.keys(addresses)) f.state.networks[chain] = chain === 'asentum' ? 'testnet' : 'mainnet';
      f.prepared = []; f.cancelled = []; f.confirmed = [];
      f.ui.prepareSolanaTronSend = async fields => {
        f.prepared.push(fields);
        return { id: fields.chain + '-review', to: fields.to, expiresAt: Date.now() + 60000,
          review: [['Network', fields.chain], ['Recipient', fields.to], ['Amount', fields.amount]] };
      };
      f.ui.cancelSolanaTronSend = async (chain, id) => { f.cancelled.push([chain, id]); };
      f.ui.confirmSolanaTronSend = async (...args) => { f.confirmed.push(args); throw Error('No broadcast permitted in UI fixture'); };
      f.screen.update();
    }, addresses);
    for (const chain of enabled) {
      await selectFixtureNetwork(page, chain);
      await page.locator('.wallet-navigation a[href="#send"]').click();
      assert.equal(await page.locator('#page-send').isVisible(), true, chain);
      const recipient = chain === 'ixios' ? '0x' + '22'.repeat(48) : addresses[chain][chain === 'asentum' ? 'testnet' : 'mainnet'];
      await page.locator('#recipient').fill(recipient);
      await page.locator('#amount').fill('1');
      if (chain === 'xion') {
        await page.locator('#xion-fee-atoms').fill('1000');
        await page.locator('#xion-gas-limit').fill('200000');
      }
      if (chain === 'asentum') await page.locator('#asentum-max-fee').fill('10');
      if (chain === 'ixios') await page.locator('#ixios-max-gas-price').fill('100');
      await page.locator('#review-button').click();
      await page.locator('#review-dialog[open]').waitFor();
      assert.match(await page.locator('#review-notice').textContent(), chain === 'asentum' ? /Testnet/ : /Mainnet/);
      assert.equal(await page.locator('#confirm-send').isDisabled(), true, 'review delay remains enforced');
      assert.ok((await page.locator('#review-details').textContent()).includes(recipient), chain);
      await page.locator('#cancel-send').click();
      assert.equal(await page.locator('#review-dialog').isVisible(), false, chain);
    }
    const result = await page.evaluate(() => ({ prepared: window.fixture.prepared, cancelled: window.fixture.cancelled, confirmed: window.fixture.confirmed }));
    assert.deepEqual(result.prepared.map(p => p.chain), enabled);
    assert.deepEqual(result.cancelled.map(p => p[0]), enabled);
    assert.deepEqual(result.confirmed, []);
    assert.equal(result.prepared.find(p => p.chain === 'xion').feeAtoms, '1000');
    assert.equal(result.prepared.find(p => p.chain === 'xion').gasLimit, '200000');
    assert.equal(result.prepared.find(p => p.chain === 'asentum').maxFeePerGas, '10');
    assert.equal(result.prepared.find(p => p.chain === 'ixios').maxGasPrice, '100');
    await selectFixtureNetwork(page, 'tidecoin');
    assert.equal(await page.locator('#review-button').isDisabled(), true);
    assert.equal(await page.locator('.wallet-navigation a[href="#send"]').isVisible(), false);
  });
});
