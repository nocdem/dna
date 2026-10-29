import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createWalletKeys } from '../src/background/wallet-keys.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { deriveIxiosAddress } from '../../src/ixios/derive.js';
import { ixiosChecksumAddress } from '../../src/ixios/address.js';
import { IXIOS_NETWORK, IXIOS_ASSET } from '../../src/ixios/network.js';
import { holdingActions, portfolioSnapshot } from '../../src/portfolio.js';

// Package J: calls both real derivations on a known public phrase; no flags,
// network/artifacts. A fixed derivation mock would prove only wiring.
test('Ixios address equals the web wallet derivation and failure keeps the wallet open', async () => {
  const phrase = 'abandon '.repeat(23) + 'art';
  const nodusWasmBytes = readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url));
  const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
  const expected = ixiosChecksumAddress(await deriveIxiosAddress(phrase, { wasmBytes: nodusWasmBytes }));
  const lockCoordinator = createLockCoordinator(), keys = createWalletKeys({ lockCoordinator, consumeNodusSeed: async () => {} });
  await lockCoordinator.unlock(() => keys.unlock(phrase, { nodusWasmBytes, cpunkWasmBytes }));
  assert.equal(keys.getAddresses().ixios, expected); await lockCoordinator.lock();
  await lockCoordinator.unlock(() => keys.unlock(phrase, { nodusWasmBytes, cpunkWasmBytes, ixiosWasmBytes: Uint8Array.of(0) }));
  assert.equal(lockCoordinator.isLocked, false); assert.equal(keys.getAddresses().ixios, undefined); await lockCoordinator.lock();
  assert.deepEqual(holdingActions(IXIOS_NETWORK, { symbol: 'IXIOS' }), ['Receive']);
  const snap = portfolioSnapshot({ [IXIOS_ASSET.key]: { state: 'ready', units: 100n, observedAt: Date.now() } }, {}, Date.now(), [IXIOS_ASSET]);
  assert.equal(snap.total, 0n); assert.equal(snap.rows[0].usd, null); assert.equal(snap.rows[0].priceId, undefined);
});

// The failed derivation above leaves no address. Exercise that public state
// on the real mounted screen; a key-holder-only test could miss its message.
test('failed Ixios derivation shows the web wallet unavailable text', { timeout: 60_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html?ixios-unavailable`);
    await page.waitForFunction(() => window.fixture?.ready);
    await page.locator('#chain').selectOption('ixios');
    assert.equal(await page.locator('#ixios-address-status').isVisible(), true);
    assert.equal(await page.locator('#ixios-address-status').textContent(), 'Ixios address unavailable. Lock and reopen your wallet to retry.');
    assert.equal(await page.evaluate(() => window.fixture.state.isUnlocked), true);
  });
});
