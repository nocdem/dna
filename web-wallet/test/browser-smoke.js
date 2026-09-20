import { portfolioRead } from './portfolio-routes.js';
import { pastePhrase, readPhrase } from './browser-phrase.js';
// Run after npm run build + npm run preview. Every external request is intercepted.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const nodusAddress = JSON.parse(readFileSync(new URL('./fixtures/nodus-addresses.json', import.meta.url))).vectors[0].address;
import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
const url = process.env.WALLET_URL || 'http://127.0.0.1:4173';
const server = process.env.WALLET_URL ? null : spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '4173', '--strictPort'], { stdio: 'pipe' });
for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await setTimeout(50); }
import { chromium } from 'playwright';
import { Transaction, Interface } from 'ethers';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 960 } });
page.setDefaultTimeout(10000);
const errors = [], broadcasts = [], calls = [];
page.on('pageerror', error => errors.push(error.message));
let cpunkMode = 'success', networkId = '0x1', finalized = false;
await page.route('**/*', async route => {
  const req = route.request();
  if (req.url().startsWith(url + '/')) return route.continue();
  if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' } });
  if (await portfolioRead(route, { ethereum: false })) return;
  const body = req.postDataJSON(); calls.push(body);
  assert.ok(!JSON.stringify(body).includes(phrase));
  if (req.url() === 'https://rpc.cellframe.net/connect') {
    assert.deepEqual(body, { method: 'wallet', subcommand: 'info', arguments: { net: 'Backbone', addr: 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps', token: 'CPUNK' }, id: 1 });
    if (cpunkMode === 'network') return route.abort();
    return route.fulfill({ json: cpunkMode === 'success' ? { result: [[{ balance: '123.000000000000000001' }]] } : { result: [] } });
  }
  const process = call => {
    if (call.method === 'eth_getTransactionReceipt') return { jsonrpc: '2.0', id: call.id, result: finalized ? { transactionHash: call.params[0], blockHash: '0x' + 'a'.repeat(64), blockNumber: '0x1', status: '0x1' } : null };
    const result = { eth_getTransactionReceipt: null, eth_chainId: networkId, eth_getBalance: '0x8ac7230489e80000', eth_call: '0x' + '0'.repeat(64), eth_estimateGas: '0x5208', eth_gasPrice: '0x3b9aca00', eth_maxPriorityFeePerGas: '0x3b9aca00', eth_getTransactionCount: '0x0', eth_getBlockByNumber: { hash: '0x' + 'a'.repeat(64), parentHash: '0x' + 'b'.repeat(64), number: '0x1', timestamp: '0x65000000', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x5208', miner: '0x0000000000000000000000000000000000000001', extraData: '0x', transactions: [] } }[call.method];
    if (call.method === 'eth_sendRawTransaction') { broadcasts.push(Transaction.from(call.params[0])); return { jsonrpc: '2.0', id: call.id, result: Transaction.from(call.params[0]).hash }; }
    assert.notEqual(result, undefined, `Unexpected RPC method ${call.method}`);
    return { jsonrpc: '2.0', id: call.id, result };
  };
  return route.fulfill({ json: Array.isArray(body) ? body.map(process) : process(body) });
});
try {
  await page.goto(url);
  await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function' && typeof document.querySelector('#cpunk-form').onsubmit === 'function');
  assert.equal(await page.locator('#cpunk-assets').isVisible(), false);
  assert.doesNotMatch(await page.locator('body').innerText(), /Check CPUNK|CF-20|Cellframe|CPUNK/);
  await page.locator('#restore').click(); await pastePhrase(page, phrase); await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#nodus-address').textContent));
  assert.equal(await page.locator('#receive-address').innerText(), '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
  assert.equal(await page.locator('#nodus-address').innerText(), nodusAddress);
  assert.match(await page.locator('#wallet-storage-state').innerText(), /Temporary session/);
  await page.locator('#quick-send').click();
  assert.equal(await page.locator('#send-title').evaluate(el => el === document.activeElement), true);
  await page.locator('#quick-receive').click();
  assert.equal(await page.locator('#receive-title').evaluate(el => el === document.activeElement), true);
  for (const width of [320, 390, 820, 1280]) {
    await page.setViewportSize({ width, height: 960 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Dashboard overflow at ${width}px`);
  }
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.locator('#copy-nodus-address').click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), nodusAddress);
  assert.equal(await readPhrase(page), '');
  await page.locator('#cpunk-assets > summary').click();
  await page.locator('#cpunk-derive').click();
  await page.waitForFunction(() => document.querySelector('#cpunk-result').textContent.includes('Address derived locally'));
  assert.ok((await page.locator('#cpunk-address').inputValue()).startsWith('R'));
  assert.equal(broadcasts.length, 0);
  for (const [chain, expected] of [['bsc','0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'],['solana','3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx'],['tron','TEfhiqsW1SdN44DeHrAWVmbyr8ZbvChrtS'],['ethereum','0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb']]) {
    await page.selectOption('#chain', chain); assert.equal(await page.locator('#receive-address').innerText(), expected);
    const selectedName = await page.locator('#chain option:checked').innerText();
    assert.ok((await page.locator('.selected-network-name').allTextContents()).every(name => name === selectedName));
  }
  await page.locator('#refresh').click(); await page.waitForFunction(() => document.querySelector('#balances').textContent.includes('10.0'));
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01');
  await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); assert.equal(broadcasts.length, 0);
  assert.match(await page.locator('#review-details').innerText(), /0.01/); await page.locator('#cancel-send').click(); assert.equal(broadcasts.length, 0);
  await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts.length, 1); assert.equal(broadcasts[0].from, '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'); assert.equal(broadcasts[0].value, 10000000000000000n); assert.equal(broadcasts[0].chainId, 1n);
  await page.selectOption('#asset','USDC'); await page.locator('#amount').fill('1.000001'); await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts.length, 2); assert.equal(broadcasts[1].to, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'); assert.equal(broadcasts[1].value, 0n);
  const erc = new Interface(['function transfer(address,uint256)']); assert.equal(erc.decodeFunctionData('transfer', broadcasts[1].data)[1], 1000001n);
  assert.match(await page.locator('#activity').innerText(), /pending/);
  finalized = true; await page.selectOption('#chain', 'bsc'); assert.equal(await page.locator('#activity').innerText(), ''); await page.selectOption('#chain', 'ethereum');
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('confirmed'));
  assert.equal(await page.locator('#nodus-address').innerText(), nodusAddress);
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01');
  networkId = '0x38'; await page.locator('#review-button').click(); await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('wrong network')); assert.equal(broadcasts.length, 2);
  await page.locator('#cpunk-address').fill('Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps'); assert.equal(await page.locator('#cpunk-endpoint').inputValue(), ''); await page.locator('#cpunk-read').click();
  await page.waitForFunction(() => document.querySelector('#cpunk-result').textContent.includes('123.000000000000000001'));
  assert.match(await page.locator('#cpunk-connection').innerText(), /Connected/);
  cpunkMode = 'malformed'; await page.locator('#cpunk-read').click(); await page.waitForFunction(() => document.querySelector('#cpunk-result').textContent.includes('unrecognized')); assert.ok(!(await page.locator('#cpunk-result').innerText()).includes('123.'));
  cpunkMode = 'network'; await page.locator('#cpunk-read').click(); await page.waitForFunction(() => document.querySelector('#cpunk-result').textContent.includes('unavailable'));
  assert.match(await page.locator('#cpunk-connection').innerText(), /Read failed/);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  networkId = '0x1';
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill('public-test-password-123'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage })); assert.ok(!stored.includes(phrase)); assert.ok(!stored.includes('public-test-password-123'));
  await page.locator('#lock').click(); assert.equal(await page.locator('#nodus-address').innerText(), ''); assert.equal(await page.locator('#cpunk-address').inputValue(), ''); assert.equal(await page.locator('#cpunk-assets').isVisible(), false); await page.locator('#unlock-password').fill('incorrect-password-123'); await page.locator('#unlock-wallet').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Incorrect password'));
  await page.locator('#unlock-password').fill('public-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#nodus-address').textContent));
  await page.locator('#vault-password').fill('changed-test-password-123'); await page.locator('#vault-old-password').fill('public-test-password-123');
  assert.equal(await page.locator('#vault-risk-confirm').isChecked(), false);
  await page.locator('#vault-change').click();
  assert.match(await page.locator('#vault-status').innerText(), /read and accept the risks/);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), JSON.parse(stored)['nodus.wallet.v1']);
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-change').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Local password changed'));
  await page.reload(); await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  await page.locator('#unlock-password').fill('changed-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#nodus-address').textContent));
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('confirmed'));
  assert.equal(await page.locator('#nodus-address').innerText(), nodusAddress);
  await page.getByText('Delete saved wallet from this device', { exact: true }).click(); await page.locator('#vault-delete-confirm').check(); await page.locator('#vault-delete').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('saved activity deleted'));
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill('public-test-password-123'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click(); await page.locator('#lock').click(); assert.equal(await page.locator('#nodus-address').innerText(), '');
  await page.waitForFunction(() => !document.querySelector('#vault-save').disabled); assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.locator('#welcome').waitFor({ state: 'visible' }); assert.equal(await page.locator('#receive-address').innerText(), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await page.locator('#create').click(); const created = await readPhrase(page); assert.equal(created.split(' ').length, 24); await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await pastePhrase(page, phrase); await page.locator('#phrase-submit').click(); await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('does not match'));
  await pastePhrase(page, created); await page.locator('#phrase-submit').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#nodus-address').textContent));
  await page.locator('#lock').click(); assert.equal(await page.locator('#nodus-address').innerText(), '');
  await page.setViewportSize({ width: 390, height: 844 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(errors, []);
  console.log('Browser smoke passed: create/backup/restore, Nodus native address/copy/lock/reopen, 4 external chain addresses, ETH/ERC20 signed mocked broadcasts, wrong-network guard, CPUNK derivation/success/error, finalized scoped activity, encrypted save/unlock/change/reload/delete, KDF cancellation, temporary storage behavior, mobile layout. No external request reached a blockchain.');
} catch (error) { console.error('UI status:', await page.locator('#wallet-status').textContent(), 'CPUNK:', await page.locator('#cpunk-result').textContent(), 'Page errors:', errors, 'Methods:', calls.map(c => c?.method)); throw error; } finally { await browser.close(); server?.kill(); }
