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
  await page.locator('#vault-password').fill('aaaaaaaaaaaaaaaa'); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('easy to guess'));
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.locator('#vault-password').fill(password); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  const peer = await fresh();
  await peer.locator('#unlock-password').fill(password); await peer.locator('#restore').click();
  assert.equal(await peer.locator('#unlock-password').inputValue(), '');
  await peer.locator('#phrase-cancel').click(); await unlock(peer);
  await page.evaluate(() => {
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle); let held = false;
    crypto.subtle.encrypt = async (...args) => {
      const result = await encrypt(...args);
      if (!held && new TextDecoder().decode(args[0].additionalData).startsWith('nodus.wallet.activity.v2') && JSON.parse(new TextDecoder().decode(args[2])).length) {
        held = true; globalThis.concurrentWriteHeld = true;
        await new Promise(resolve => { globalThis.releaseConcurrentWrite = resolve; });
      }
      return result;
    };
  });
  await review(page); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => globalThis.concurrentWriteHeld);
  await peer.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await peer.locator('#amount').fill('0.02');
  await peer.locator('#review-button').click(); await peer.locator('#review-dialog').waitFor({ state: 'visible' }); await peer.locator('#confirm-send').click();
  await peer.waitForFunction(async () => (await navigator.locks.query()).pending.some(lock => lock.name === 'nodus.wallet.storage'));
  assert.equal(broadcasts, 0);
  await page.evaluate(() => globalThis.releaseConcurrentWrite());
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  await peer.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts, 2); assert.equal(durable, 2);
  const original = await page.evaluate(() => localStorage.getItem('nodus.activity.v1'));
  assert.ok(!original.includes(addresses.ethereum)); assert.ok(!original.includes('rows'));
  await page.locator('#lock').click();
  assert.equal(await page.locator('#review-details').textContent(), '');
  assert.equal(await page.locator('#review-error').textContent(), '');
  assert.equal(await page.locator('#account-explorer').getAttribute('href'), null);
  await peer.selectOption('#chain', 'bsc');
  await peer.waitForFunction(previous => localStorage.getItem('nodus.activity.v1') !== previous, original);
  const preserved = await page.evaluate(() => ({ vault: localStorage.getItem('nodus.wallet.v1'), activity: localStorage.getItem('nodus.activity.v1') }));
  const vaultId = JSON.parse(preserved.vault).id, activityKey = await activityKeyFor(phrase, vaultId);
  const combinedRows = await parseActivity(preserved.activity, vaultId, addresses, activityKey);
  assert.equal(combinedRows.length, 2); assert.deepEqual(combinedRows.map(row => row.amount).sort(), ['0.01', '0.02']);
  await peer.close();
  await restore(page);
  await page.locator('#vault-password').fill('different-public-test-password'); await page.locator('#vault-old-password').fill(password); await page.locator('#vault-change').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('unlock the saved wallet'));
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), preserved.vault);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.activity.v1')), preserved.activity);
  await page.locator('#lock').click();
  console.log('Concurrent signed records serialized across tabs and both durable before broadcast; stale-tab writes preserve both. Phrase-only password change blocked; hidden password and locked review metadata cleared.');
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
  assert.equal(broadcasts, 2);
  await page.evaluate(() => { window.dispatchEvent(new PageTransitionEvent('pagehide')); localStorage.clear(); globalThis.releaseHistory(); });
  await page.waitForFunction(() => !document.querySelector('#cancel-send').disabled);
  assert.equal(broadcasts, 2); assert.equal(await page.evaluate(() => localStorage.length), 0); staleWriteCompleted = true;
  console.log('Lock while activity encryption is pending: no broadcast and no stale write after delete.');
  const clearingPeer = await fresh();
  await restore(page);
  await clearingPeer.evaluate(() => { localStorage.setItem('public-test-marker', '1'); localStorage.clear(); });
  await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await clearingPeer.close();
  console.log('Clearing local storage in another tab locks the open wallet.');
  await restore(page);
  await page.evaluate(() => {
    const original = globalThis.fetch;
    globalThis.fetch = (input, options) => {
      if (!String(input).includes('legacy-dilithium')) return original(input, options);
      globalThis.cpunkFetchSignal = options.signal;
      return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true }));
    };
  });
  await page.locator('#cpunk-assets > summary').click(); await page.locator('#cpunk-derive').click();
  await page.waitForFunction(() => !!globalThis.cpunkFetchSignal);
  await page.locator('#lock').click();
  await page.waitForFunction(() => !document.querySelector('#cpunk-derive').disabled);
  assert.equal(await page.evaluate(() => globalThis.cpunkFetchSignal.aborted), true);
  assert.equal(await page.locator('#cpunk-address').inputValue(), '');
  console.log('Lock aborts an in-flight CPUNK module fetch and leaves no derived address.');
  assert.deepEqual(errors, []); assert.ok(staleWriteCompleted);
  console.log('Browser security regressions passed. All blockchain traffic was intercepted.');
} finally { await browser.close(); server.kill(); }
