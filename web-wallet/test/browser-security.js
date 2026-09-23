import { portfolioRead, cellframeRead } from './portfolio-routes.js';
import { pastePhrase, readPhrase } from './browser-phrase.js';
// Production bundle; all external traffic is intercepted. Public test phrase only.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { Transaction, formatEther } from 'ethers';
import { activityKeyFor, parseActivity } from '../src/activity-storage.js';
import { deriveWallet } from '../src/keys.js';
const app = fileURLToPath(new URL('..', import.meta.url)), url = 'http://127.0.0.1:4189';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-security-test-password-2026', addresses = deriveWallet(phrase).addresses;
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '4189', '--strictPort'], { cwd: app, stdio: 'pipe' });
for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await delay(50); }
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, headless: true });
let page, broadcasts = 0, durable = 0, staleWriteCompleted = false;
const errors = [];
const context = await browser.newContext();
await context.route('**/*', async route => {
  const req = route.request(); if (req.url().startsWith(url + '/')) return route.continue();
  if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' } });
  if (await cellframeRead(route)) return;
  if (await portfolioRead(route, { ethereum: false })) return;
  const body = req.postDataJSON(); assert.ok(!JSON.stringify(body).includes(phrase));
  const process = async call => {
    if (call.method === 'eth_sendRawTransaction') {
      const tx = Transaction.from(call.params[0]); broadcasts++;
      const stored = await page.evaluate(() => ({ vault: JSON.parse(localStorage.getItem('nodus.wallet.v1')), activity: localStorage.getItem('nodus.activity.v1') }));
      const key = await activityKeyFor(phrase, stored.vault.id);
      const rows = await parseActivity(stored.activity, stored.vault.id, addresses, key);
      assert.ok(rows.some(row => row.hash === tx.hash && row.amount === formatEther(tx.value))); durable++;
      return { jsonrpc: '2.0', id: call.id, result: tx.hash };
    }
    const results = { eth_chainId: '0x1', eth_getBalance: '0x8ac7230489e80000', eth_call: '0x' + '0'.repeat(64), eth_estimateGas: '0x5208', eth_gasPrice: '0x3b9aca00', eth_maxPriorityFeePerGas: '0x3b9aca00', eth_getTransactionCount: '0x0', eth_getTransactionReceipt: null, eth_getBlockByNumber: { hash: '0x' + 'a'.repeat(64), parentHash: '0x' + 'b'.repeat(64), number: '0x1', timestamp: '0x65000000', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x5208', miner: '0x0000000000000000000000000000000000000001', extraData: '0x', transactions: [] } };
    assert.ok(Object.hasOwn(results, call.method), call.method); return { jsonrpc: '2.0', id: call.id, result: results[call.method] };
  };
  await route.fulfill({ json: Array.isArray(body) ? await Promise.all(body.map(process)) : await process(body) });
});
async function fresh() { const p = await context.newPage(); p.setDefaultTimeout(10000); p.on('pageerror', error => errors.push(error.message)); await p.goto(url); await p.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function'); return p; }
async function restore(p) { await p.locator('#restore').click(); await pastePhrase(p, phrase); await p.locator('#backup-confirm').check(); await p.locator('#phrase-submit').click(); await p.locator('#wallet-open').waitFor({ state: 'visible' }); }
async function unlock(p) { await p.locator('#unlock-password').fill(password); await p.locator('#unlock-wallet').click(); await p.locator('#wallet-open').waitFor({ state: 'visible' }); }
async function review(p) { await p.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await p.locator('#amount').fill('0.01'); await p.locator('#review-button').click(); await p.locator('#review-dialog').waitFor({ state: 'visible' }); }
try {
  page = await fresh(); await page.clock.install();
  for (const stage of ['create', 'verify', 'restore']) {
    await page.locator(stage === 'restore' ? '#restore' : '#create').click();
    if (stage === 'verify') { await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click(); await pastePhrase(page, phrase); }
    if (stage === 'restore') await pastePhrase(page, phrase);
    await page.clock.fastForward(11 * 60 * 1000);
    assert.equal(await readPhrase(page), ''); assert.equal(await page.locator('#phrase-form').isVisible(), false);
  }
  await page.locator('#restore').click(); await pastePhrase(page, phrase);
  // Simulate a suspended timer: visibility/focus must check the absolute deadline.
  await page.clock.setSystemTime(Date.now() + 24 * 60 * 60 * 1000); await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  assert.equal(await readPhrase(page), ''); await page.close();
  console.log('RT-01: create, verify, restore and suspended-tab expiry clear secrets.');

  page = await fresh(); await restore(page); await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  assert.equal(await page.locator('#vault-risk-confirm').isChecked(), false);
  await page.locator('#vault-password').fill(password); await page.locator('#vault-save').click();
  assert.match(await page.locator('#vault-status').innerText(), /read and accept the risks/);
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  // Withdrawing consent while encryption is pending must prevent persistence.
  await page.evaluate(() => {
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    globalThis.restoreEncryption = () => { crypto.subtle.encrypt = original; };
    crypto.subtle.encrypt = async (...args) => {
      const result = await original(...args); globalThis.consentEncryptionHeld = true;
      await new Promise(resolve => { globalThis.releaseConsentEncryption = resolve; });
      return result;
    };
  });
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => globalThis.consentEncryptionHeld);
  await page.locator('#vault-risk-confirm').uncheck();
  await page.evaluate(() => { globalThis.restoreEncryption(); globalThis.releaseConsentEncryption(); });
  await page.waitForFunction(() => !document.querySelector('#vault-save').disabled);
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  assert.match(await page.locator('#vault-status').innerText(), /Save canceled/);
  await page.locator('#vault-password').fill('Example-pass-15');
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  assert.match(await page.locator('#vault-status').innerText(), /16/);
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.locator('#vault-password').fill('aaaaaaaaaaaaaaaa'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('easy to guess'));
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.locator('#vault-password').fill(password); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  assert.equal(await page.locator('#vault-risk-confirm').isChecked(), false);
  assert.match(await page.locator('#wallet-storage-state').innerText(), /Encrypted copy saved/);
  console.log('Storage is opt-in: unchecked or withdrawn risk consent writes nothing; short and weak passwords are rejected; saving resets consent.');
  // Single-tab rule (decision 2026-09-23-web-wallet-single-tab.md): the saved
  // wallet is open in `page` (tab A). A second tab of the same browser context
  // (B, `peer`) is refused and derives nothing; B's takeover opens it in B and
  // locks A; A cannot send or reopen while B holds it; closing B lets A reopen.
  // This replaces the former two-tabs-sending-at-once scenario, which the rule
  // makes unreachable (SECURITY-FOLLOWUP "cross-tab record loss").
  const sessionHeld = p => p.evaluate(async () => (await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
  assert.equal(await sessionHeld(page), true);
  await review(page); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts, 1); assert.equal(durable, 1);
  const original = await page.evaluate(() => localStorage.getItem('nodus.activity.v1'));
  assert.ok(!original.includes(addresses.ethereum)); assert.ok(!original.includes('rows'));
  async function refused(p) {
    assert.equal(await p.locator('#session-conflict').isVisible(), true);
    assert.match(await p.locator('#session-conflict').innerText(), /Wallet is open in another tab\./);
    assert.equal(await p.locator('#session-takeover').innerText(), 'Use it here instead');
    assert.equal(await p.locator('#wallet-open').isVisible(), false); assert.equal(await p.locator('#phrase-form').isVisible(), false);
    assert.equal(await readPhrase(p), ''); assert.equal(await p.locator('#unlock-password').inputValue(), '');
    assert.equal(await p.locator('#nodus-address').textContent(), ''); assert.equal(await p.locator('#receive-address').textContent(), '');
    assert.equal(await p.locator('#cellframe-address-status').textContent(), '');
  }
  // Waits for an unlock attempt to finish: the handler disables the button and
  // hides the conflict notice synchronously, before its first await.
  const unlockSettled = p => p.waitForFunction(() => !document.querySelector('#unlock-wallet').disabled && !document.querySelector('#session-conflict').hidden);
  const peer = await fresh();
  await peer.locator('#unlock-password').fill(password); await peer.locator('#restore').click();
  assert.equal(await peer.locator('#unlock-password').inputValue(), '');
  await pastePhrase(peer, phrase); await peer.locator('#backup-confirm').check(); await peer.locator('#phrase-submit').click();
  await peer.locator('#session-conflict').waitFor({ state: 'visible' });
  await refused(peer);
  await peer.locator('#unlock-password').fill(password); await peer.locator('#unlock-wallet').click(); await unlockSettled(peer);
  await refused(peer);
  assert.equal(await page.locator('#wallet-open').isVisible(), true);
  assert.equal(broadcasts, 1);
  await peer.locator('#session-takeover').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Wallet was opened in another tab. This tab was locked.'));
  assert.equal(await page.locator('#wallet-open').isVisible(), false); assert.equal(await page.locator('#welcome').isVisible(), true);
  assert.equal(await page.locator('#send-form').isVisible(), false); assert.equal(await page.locator('#review-button').isVisible(), false);
  assert.equal(await page.locator('#nodus-address').textContent(), '');
  assert.equal(await page.locator('#review-details').textContent(), '');
  assert.equal(await page.locator('#review-error').textContent(), '');
  assert.equal(await page.locator('#account-explorer').getAttribute('href'), null);
  await peer.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Enter your local password again'));
  await unlock(peer);
  await peer.waitForFunction(() => document.querySelector('#activity').textContent.includes('0.01'));
  assert.equal(await peer.locator('#session-conflict').isVisible(), false);
  await page.locator('#unlock-password').fill(password); await page.locator('#unlock-wallet').click(); await unlockSettled(page);
  await refused(page);
  assert.equal(await peer.locator('#wallet-open').isVisible(), true);
  assert.equal(broadcasts, 1);
  await peer.close();
  // Tab close and lock release are not ordered as seen from Playwright; wait
  // for the release itself rather than for time.
  await page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
  await unlock(page);
  assert.equal(await page.locator('#session-conflict').isVisible(), false);
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('0.01'));
  await page.locator('#lock').click();
  // A release reaches the browser's lock manager asynchronously: wait for it.
  await page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
  // Both tabs are now locked or closed; locked tabs never write, so storage is stable.
  const preserved = await page.evaluate(() => ({ vault: localStorage.getItem('nodus.wallet.v1'), activity: localStorage.getItem('nodus.activity.v1') }));
  const vaultId = JSON.parse(preserved.vault).id, activityKey = await activityKeyFor(phrase, vaultId);
  const savedRows = await parseActivity(preserved.activity, vaultId, addresses, activityKey);
  assert.deepEqual(savedRows.map(row => row.amount), ['0.01']);
  await restore(page);
  await page.locator('#vault-password').fill('different-public-test-password'); await page.locator('#vault-old-password').fill(password); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-change').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('unlock the saved wallet'));
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), preserved.vault);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.activity.v1')), preserved.activity);
  await page.locator('#lock').click();
  console.log('Single-tab rule: a second tab is refused and derives nothing; its takeover opens it there and locks the first tab, which cannot send or reopen until the second tab closes. Signed record durable before broadcast and saved encrypted. Phrase-only password change blocked; hidden password and locked review metadata cleared.');
  await page.evaluate(() => { const data = JSON.parse(localStorage.getItem('nodus.activity.v1')); data.ciphertext = (data.ciphertext[0] === 'A' ? 'B' : 'A') + data.ciphertext.slice(1); localStorage.setItem('nodus.activity.v1', JSON.stringify(data)); });
  const tampered = await page.evaluate(() => localStorage.getItem('nodus.activity.v1'));
  await unlock(page); assert.equal(await page.locator('#discard-activity').isVisible(), true); assert.equal(await page.locator('#activity').innerText(), '');
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.activity.v1')), tampered);
  await page.locator('#discard-activity').click(); await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('history discarded'));
  await page.locator('#lock').click();
  await page.evaluate(({ address }) => { const id = JSON.parse(localStorage.getItem('nodus.wallet.v1')).id; localStorage.setItem('nodus.activity.v1', JSON.stringify({ version: 1, id, rows: [{ chain: 'ethereum', address, to: address, amount: '999', symbol: 'ETH', hash: '0x' + '1'.repeat(64), status: 'confirmed', createdAt: new Date().toISOString() }] })); }, { address: addresses.ethereum });
  await unlock(page); assert.equal(await page.locator('#activity').innerText(), ''); assert.equal(await page.locator('#discard-activity').isVisible(), true);
  await page.locator('#discard-activity').click(); await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('history discarded'));
  console.log('RT-03/04: weak password rejected, encrypted hash durable before broadcast, tampered/forged legacy history blocked and preserved until explicit discard.');

  await review(page);
  await page.evaluate(() => {
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    crypto.subtle.encrypt = async (...args) => {
      const result = await original(...args);
      if (new TextDecoder().decode(args[0].additionalData).startsWith('nodus.wallet.activity.v2')) {
        globalThis.historyWait = true; await new Promise(resolve => { globalThis.releaseHistory = resolve; });
      }
      return result;
    };
  });
  await page.locator('#confirm-send').click(); await page.waitForFunction(() => globalThis.historyWait);
  assert.equal(broadcasts, 1);
  await page.evaluate(() => { window.dispatchEvent(new PageTransitionEvent('pagehide')); localStorage.clear(); globalThis.releaseHistory(); });
  await page.waitForFunction(() => !document.querySelector('#cancel-send').disabled);
  assert.equal(broadcasts, 1); assert.equal(await page.evaluate(() => localStorage.length), 0); staleWriteCompleted = true;
  console.log('Lock while activity encryption is pending: no broadcast and no stale write after delete.');
  const clearingPeer = await fresh();
  await restore(page);
  await clearingPeer.evaluate(() => { localStorage.setItem('public-test-marker', '1'); localStorage.clear(); });
  await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await clearingPeer.close();
  console.log('Clearing local storage in another tab locks the open wallet.');
  // Cellframe derivation now starts automatically as soon as the wallet opens
  // (like the Nodus address), so the fetch patch must be installed before
  // restore(), not triggered by a manual button afterwards.
  await page.evaluate(() => {
    const original = globalThis.fetch;
    globalThis.fetch = (input, options) => {
      if (!String(input).includes('legacy-dilithium')) return original(input, options);
      globalThis.cpunkFetchSignal = options.signal;
      return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true }));
    };
  });
  await restore(page);
  await page.waitForFunction(() => !!globalThis.cpunkFetchSignal);
  await page.locator('#lock').click();
  await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.evaluate(() => globalThis.cpunkFetchSignal.aborted), true);
  console.log('Lock aborts an in-flight Cellframe address fetch.');

  // E-2/B-1/E-3: a fresh saved wallet exercises the review dialog's focus/timing
  // guard, the same-network double-send lock and its abandon escape hatch, and
  // the lower-case-address review warning, in one continuous session.
  page = await fresh(); await restore(page); await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill(password); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));

  let sent = broadcasts;
  await review(page);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'cancel-send');
  assert.equal(await page.locator('#confirm-send').isDisabled(), true);
  await page.keyboard.down('Enter');
  await delay(700);
  assert.equal(broadcasts, sent); assert.equal(await page.locator('#review-dialog').isVisible(), true);
  await page.keyboard.up('Enter');
  assert.equal(await page.locator('#confirm-send').isDisabled(), false);
  await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts, sent + 1);
  assert.equal(await page.locator('#recipient').inputValue(), ''); assert.equal(await page.locator('#amount').inputValue(), '');
  console.log('E-2: review opens with Cancel focused and Confirm disabled for 600ms, a held Enter reaches no signing action, and the form clears after broadcast.');

  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01'); await page.locator('#review-button').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('no final result yet'));
  assert.equal(await page.locator('#review-dialog').isVisible(), false);
  await page.locator('#activity').getByRole('button', { name: 'Mark as abandoned' }).click();
  await page.locator('#activity').getByRole('button', { name: 'Confirm abandon' }).click();
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('abandoned'));
  console.log('B-1: a second review on the same network is blocked while the first send has no final result.');

  await page.locator('#recipient').fill(addresses.ethereum.toLowerCase()); await page.locator('#amount').fill('0.01'); await page.locator('#review-button').click();
  await page.locator('#review-dialog').waitFor({ state: 'visible' });
  assert.match(await page.locator('#review-details').innerText(), /Address check/);
  await page.locator('#cancel-send').click();
  await page.locator('#recipient').fill(addresses.ethereum); await page.locator('#amount').fill('0.01'); await page.locator('#review-button').click();
  await page.locator('#review-dialog').waitFor({ state: 'visible' });
  assert.doesNotMatch(await page.locator('#review-details').innerText(), /Address check/);
  await page.locator('#cancel-send').click();
  console.log('E-3: a lower-case EVM recipient triggers a review warning and a checksummed one does not; both prove a review can open again once the earlier send is marked abandoned.');

  assert.deepEqual(errors, []); assert.ok(staleWriteCompleted);
  console.log('Browser security regressions passed. All blockchain traffic was intercepted.');
} finally { await browser.close(); server.kill(); }
