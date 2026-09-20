// Production bundle; all external traffic is intercepted. Public test phrase only.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { Transaction } from 'ethers';
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
      assert.ok(rows.some(row => row.hash === tx.hash && row.amount === '0.01')); durable++;
      return { jsonrpc: '2.0', id: call.id, result: tx.hash };
    }
    const results = { eth_chainId: '0x1', eth_getBalance: '0x8ac7230489e80000', eth_call: '0x' + '0'.repeat(64), eth_estimateGas: '0x5208', eth_gasPrice: '0x3b9aca00', eth_maxPriorityFeePerGas: '0x3b9aca00', eth_getTransactionCount: '0x0', eth_getTransactionReceipt: null, eth_getBlockByNumber: { hash: '0x' + 'a'.repeat(64), parentHash: '0x' + 'b'.repeat(64), number: '0x1', timestamp: '0x65000000', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x5208', miner: '0x0000000000000000000000000000000000000001', extraData: '0x', transactions: [] } };
    assert.ok(Object.hasOwn(results, call.method), call.method); return { jsonrpc: '2.0', id: call.id, result: results[call.method] };
  };
  await route.fulfill({ json: Array.isArray(body) ? await Promise.all(body.map(process)) : await process(body) });
});
async function fresh() { const p = await context.newPage(); p.setDefaultTimeout(10000); p.on('pageerror', error => errors.push(error.message)); await p.goto(url); await p.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function'); return p; }
async function restore(p) { await p.locator('#restore').click(); await p.locator('#phrase').fill(phrase); await p.locator('#backup-confirm').check(); await p.locator('#phrase-submit').click(); await p.locator('#wallet-open').waitFor({ state: 'visible' }); }
async function unlock(p) { await p.locator('#unlock-password').fill(password); await p.locator('#unlock-wallet').click(); await p.locator('#wallet-open').waitFor({ state: 'visible' }); }
async function review(p) { await p.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await p.locator('#amount').fill('0.01'); await p.locator('#review-button').click(); await p.locator('#review-dialog').waitFor({ state: 'visible' }); }
try {
  page = await fresh(); await page.clock.install();
  for (const stage of ['create', 'verify', 'restore']) {
    await page.locator(stage === 'restore' ? '#restore' : '#create').click();
    if (stage === 'verify') { await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click(); await page.locator('#phrase').fill(phrase); }
    if (stage === 'restore') await page.locator('#phrase').fill(phrase);
    await page.clock.fastForward(11 * 60 * 1000);
    assert.equal(await page.locator('#phrase').inputValue(), ''); assert.equal(await page.locator('#phrase-form').isVisible(), false);
  }
  await page.locator('#restore').click(); await page.locator('#phrase').fill(phrase);
  // Simulate a suspended timer: visibility/focus must check the absolute deadline.
  await page.clock.setSystemTime(Date.now() + 24 * 60 * 60 * 1000); await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  assert.equal(await page.locator('#phrase').inputValue(), ''); await page.close();
  console.log('RT-01: create, verify, restore and suspended-tab expiry clear secrets.');

  page = await fresh(); await restore(page); await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill('aaaaaaaaaaaaaaaa'); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('easy to guess'));
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.locator('#vault-password').fill(password); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  await review(page); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts, 1); assert.equal(durable, 1);
  const original = await page.evaluate(() => localStorage.getItem('nodus.activity.v1'));
  assert.ok(!original.includes(addresses.ethereum)); assert.ok(!original.includes('rows'));
  await page.locator('#lock').click();
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
  assert.deepEqual(errors, []); assert.ok(staleWriteCompleted);
  console.log('Browser security regressions passed. All blockchain traffic was intercepted.');
} finally { await browser.close(); server.kill(); }
