import { portfolioRead, cellframeRead } from './portfolio-routes.js';
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
let cellframeBalance = '5', cellframeFail = false, networkId = '0x1', finalized = false;
await page.route('**/*', async route => {
  const req = route.request();
  if (req.url().startsWith(url + '/')) return route.continue();
  if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' } });
  if (await cellframeRead(route, { balance: cellframeBalance, fail: cellframeFail })) return;
  if (await portfolioRead(route, { ethereum: false })) return;
  const body = req.postDataJSON(); calls.push(body);
  assert.ok(!JSON.stringify(body).includes(phrase));
  const process = call => {
    if (call.method === 'eth_getTransactionReceipt') return { jsonrpc: '2.0', id: call.id, result: finalized ? { transactionHash: call.params[0], blockHash: '0x' + 'a'.repeat(64), blockNumber: '0x1', status: '0x1' } : null };
    const result = { eth_getTransactionReceipt: null, eth_chainId: networkId, eth_getBalance: '0x8ac7230489e80000', eth_call: '0x' + '0'.repeat(64), eth_estimateGas: '0x5208', eth_gasPrice: '0x3b9aca00', eth_maxPriorityFeePerGas: '0x3b9aca00', eth_getTransactionCount: '0x0', eth_getBlockByNumber: { hash: '0x' + 'a'.repeat(64), parentHash: '0x' + 'b'.repeat(64), number: '0x1', timestamp: '0x65000000', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x5208', miner: '0x0000000000000000000000000000000000000001', extraData: '0x', transactions: [] } }[call.method];
    if (call.method === 'eth_sendRawTransaction') { broadcasts.push(Transaction.from(call.params[0])); return { jsonrpc: '2.0', id: call.id, result: Transaction.from(call.params[0]).hash }; }
    assert.notEqual(result, undefined, `Unexpected RPC method ${call.method}`);
    return { jsonrpc: '2.0', id: call.id, result };
  };
  return route.fulfill({ json: Array.isArray(body) ? body.map(process) : process(body) });
});
// A grant is observed by the page before it opens the wallet, so "held" can be
// read once; a release reaches the browser's lock manager asynchronously, so
// "released" is waited for (the 10 s page timeout fails it if it never happens).
const sessionHeld = () => page.evaluate(async () => (await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
const sessionReleased = () => page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
try {
  await page.goto(url);
  await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  assert.doesNotMatch(await page.locator('body').innerText(), /Check CPUNK|CF-20|Cellframe|CPUNK/);
  await page.locator('#restore').click(); await pastePhrase(page, phrase); await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  // Single-tab rule: an open wallet holds the session lock; one tab alone is never refused.
  assert.equal(await sessionHeld(), true); assert.equal(await page.locator('#session-conflict').isVisible(), false);
  // NODUS leads every list and is the network selected when the page loads: its
  // locally derived address is the receive address, sending is off, no explorer.
  assert.equal(await page.locator('#chain option').first().getAttribute('value'), 'nodus');
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  assert.equal(await page.locator('#nodus-address-status').isVisible(), true);
  assert.match(await page.locator('#nodus-address-status').innerText(), /Derived locally/);
  assert.equal(await page.locator('#cellframe-address-status').isVisible(), false);
  assert.equal(await page.locator('#send-fields').isVisible(), false);
  assert.equal(await page.locator('#send-disabled-note').innerText(), 'Sending NODUS is not available in this release.');
  assert.equal(await page.locator('#account-explorer').isVisible(), false);
  assert.equal(await page.locator('#rpc-settings').isVisible(), false);
  assert.equal(await page.locator('#activity').innerText(), '');
  // Portfolio: NODUS is the first asset group, badge and network filter; its row
  // has only Receive and shows no balance (no amount, no zero, no read state).
  assert.equal(await page.locator('#balances .asset-group').first().getAttribute('data-symbol'), 'NODUS');
  assert.equal(await page.locator('#portfolio-networks .network-health').first().innerText(), 'Nodus · Balance not shown yet');
  assert.deepEqual((await page.locator('#portfolio-filters button').allTextContents()).slice(0, 2), ['All networks', 'Nodus']);
  const nodusGroup = page.locator('.asset-group[data-symbol="NODUS"]');
  assert.ok((await nodusGroup.locator('summary img.coin-icon').getAttribute('src')).endsWith('/assets/coins/nodus.svg'));
  assert.equal(await nodusGroup.locator('.asset-value strong').innerText(), '—');
  await nodusGroup.locator('summary').click();
  assert.equal(await nodusGroup.locator('.chain-holding').count(), 1);
  assert.match(await nodusGroup.locator('.chain-holding').innerText(), /Balance not shown yet/);
  assert.doesNotMatch(await nodusGroup.innerText(), /Reading|Not read|Balance unavailable|\b0\.0\b/);
  assert.deepEqual(await nodusGroup.locator('.holding-actions button').allTextContents(), ['Receive']);
  await nodusGroup.locator('summary').click();
  assert.match(await page.locator('#portfolio-scope').innerText(), /NODUS is shown, but its balance is not shown yet/);
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
  // Nodus is still the selected network: the shared Copy button copies its address.
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.locator('#copy-address').click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), nodusAddress);
  assert.equal(await readPhrase(page), '');
  await page.selectOption('#chain', 'ethereum');
  assert.equal(await page.locator('#receive-address').innerText(), '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
  assert.equal(await page.locator('#nodus-address-status').isVisible(), false);
  assert.equal(await page.locator('#rpc-settings').isVisible(), true);
  // Cellframe/CPUNK now lives inside the wallet like any other asset: its
  // address is derived automatically (started right after the wallet opened,
  // same as Nodus), and there is no separate panel or manual derive button.
  await page.selectOption('#chain', 'cellframe');
  await page.waitForFunction(() => /^[1-9A-HJ-NP-Za-km-z]{100,110}$/.test(document.querySelector('#receive-address').textContent));
  assert.match(await page.locator('#cellframe-address-status').innerText(), /Derived locally/);
  assert.equal(await page.locator('#send-fields').isVisible(), false);
  assert.match(await page.locator('#send-disabled-note').innerText(), /Sending CPUNK is not available/);
  assert.equal(await page.locator('#account-explorer').isVisible(), false);
  assert.equal(broadcasts.length, 0);
  for (const [chain, expected] of [['bsc','0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'],['solana','3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx'],['tron','TEfhiqsW1SdN44DeHrAWVmbyr8ZbvChrtS'],['ethereum','0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb']]) {
    await page.selectOption('#chain', chain); assert.equal(await page.locator('#receive-address').innerText(), expected);
    const selectedName = await page.locator('#chain option:checked').innerText();
    assert.ok((await page.locator('.selected-network-name').allTextContents()).every(name => name === selectedName));
  }
  // Paket C: RPC provider select — populated per network, TRON has no custom
  // option, and picking "Custom HTTPS endpoint..." reveals the free-text box.
  // Open the settings disclosure first, as a user must: inside a closed
  // <details> Chromium reports option innerText as '' and every control as
  // not visible, so the visibility checks below would pass vacuously.
  await page.locator('.rpc-settings summary').click();
  assert.equal(await page.locator('#rpc-choice').isVisible(), true);
  await page.selectOption('#chain', 'tron');
  assert.deepEqual(await page.locator('#rpc-choice option').allTextContents(), ['TronGrid']);
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), false);
  await page.selectOption('#chain', 'bsc');
  assert.equal(await page.locator('#rpc-choice option').count(), 9);
  assert.equal(await page.locator('#rpc-choice option').last().innerText(), 'Custom HTTPS endpoint…');
  await page.selectOption('#chain', 'solana');
  assert.equal(await page.locator('#rpc-choice option').count(), 2);
  await page.selectOption('#chain', 'ethereum');
  assert.equal(await page.locator('#rpc-choice option').count(), 5);
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), false);
  await page.selectOption('#rpc-choice', 'custom');
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), true);
  assert.equal(await page.locator('#rpc-endpoint').inputValue(), '');
  await page.selectOption('#rpc-choice', '0');
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), false);
  await page.locator('#refresh').click(); await page.waitForFunction(() => document.querySelector('#balances').textContent.includes('10.0'));
  await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-symbol="CPUNK"] .holding-value strong'); return strong && strong.textContent.includes('CPUNK'); });
  assert.equal(await page.locator('.asset-group[data-symbol="CPUNK"] .asset-value small').innerText(), '—');
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01');
  await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); assert.equal(broadcasts.length, 0);
  assert.match(await page.locator('#review-details').innerText(), /0.01/); await page.locator('#cancel-send').click(); assert.equal(broadcasts.length, 0);
  await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts.length, 1); assert.equal(broadcasts[0].from, '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'); assert.equal(broadcasts[0].value, 10000000000000000n); assert.equal(broadcasts[0].chainId, 1n);
  // B-1: the first send has no final result yet, so it must be marked abandoned
  // before a second same-network review can open; E-2 also clears the recipient
  // after a successful broadcast, so it is re-filled here too.
  await page.locator('#activity').getByRole('button', { name: 'Mark as abandoned' }).click(); await page.locator('#activity').getByRole('button', { name: 'Confirm abandon' }).click(); await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('abandoned'));
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001');
  await page.selectOption('#asset','USDC'); await page.locator('#amount').fill('1.000001'); await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts.length, 2); assert.equal(broadcasts[1].to, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'); assert.equal(broadcasts[1].value, 0n);
  const erc = new Interface(['function transfer(address,uint256)']); assert.equal(erc.decodeFunctionData('transfer', broadcasts[1].data)[1], 1000001n);
  assert.match(await page.locator('#activity').innerText(), /pending/);
  finalized = true; await page.selectOption('#chain', 'bsc'); assert.equal(await page.locator('#activity').innerText(), ''); await page.selectOption('#chain', 'ethereum');
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('confirmed'));
  // The Nodus address is unchanged after sends on other networks, and Nodus has no activity.
  await page.selectOption('#chain', 'nodus');
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress); assert.equal(await page.locator('#activity').innerText(), '');
  await page.selectOption('#chain', 'ethereum');
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('confirmed'));
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01');
  networkId = '0x38'; await page.locator('#review-button').click(); await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('wrong network')); assert.equal(broadcasts.length, 2);
  // A CPUNK read failure shows "Balance unavailable" on its own row, never an
  // inferred zero, and never blocks the rest of the (unrelated) portfolio.
  cellframeFail = true; await page.locator('#refresh').click();
  await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-symbol="CPUNK"] .holding-value strong'); return strong && strong.textContent === 'Balance unavailable'; });
  cellframeFail = false;
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  networkId = '0x1';
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill('public-test-password-123'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage })); assert.ok(!stored.includes(phrase)); assert.ok(!stored.includes('public-test-password-123'));
  // Lock with Nodus selected: its address and status are cleared.
  await page.selectOption('#chain', 'nodus'); assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  await page.locator('#lock').click(); assert.equal(await page.locator('#receive-address').textContent(), ''); assert.equal(await page.locator('#nodus-address-status').textContent(), ''); assert.equal(await page.locator('#cellframe-address-status').innerText(), ''); await sessionReleased();
  await page.locator('#unlock-password').fill('incorrect-password-123'); await page.locator('#unlock-wallet').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Incorrect password'));
  // A failed unlock gives the session lock back.
  await page.waitForFunction(() => !document.querySelector('#unlock-wallet').disabled); await sessionReleased();
  await page.locator('#unlock-password').fill('public-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  assert.equal(await sessionHeld(), true); assert.equal(await page.locator('#session-conflict').isVisible(), false);
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  await page.locator('#vault-password').fill('changed-test-password-123'); await page.locator('#vault-old-password').fill('public-test-password-123');
  assert.equal(await page.locator('#vault-risk-confirm').isChecked(), false);
  await page.locator('#vault-change').click();
  assert.match(await page.locator('#vault-status').innerText(), /read and accept the risks/);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), JSON.parse(stored)['nodus.wallet.v1']);
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-change').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Local password changed'));
  await page.reload(); await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  await page.locator('#unlock-password').fill('changed-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.selectOption('#chain', 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  await page.selectOption('#chain', 'ethereum');
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('confirmed'));
  await page.getByText('Delete saved wallet from this device', { exact: true }).click(); await page.locator('#vault-delete-confirm').check(); await page.locator('#vault-delete').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('saved activity deleted'));
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill('public-test-password-123'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click(); await page.locator('#lock').click(); assert.equal(await page.locator('#nodus-address-status').textContent(), '');
  await page.waitForFunction(() => !document.querySelector('#vault-save').disabled); assert.equal(await page.evaluate(() => localStorage.length), 0);
  await page.locator('#welcome').waitFor({ state: 'visible' }); assert.equal(await page.locator('#receive-address').innerText(), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await page.locator('#create').click(); const created = await readPhrase(page); assert.equal(created.split(' ').length, 24); await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  // E-4 blocks paste on this verify step by design, so the backup check below
  // types each word into its own box instead of pasting the full phrase.
  const boxes = page.locator('#phrase-grid input');
  for (const [i, word] of phrase.split(' ').entries()) await boxes.nth(i).fill(word);
  await page.locator('#phrase-submit').click(); await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('does not match'));
  for (const [i, word] of created.split(' ').entries()) await boxes.nth(i).fill(word);
  await page.locator('#phrase-submit').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.selectOption('#chain', 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  await page.locator('#lock').click(); assert.equal(await page.locator('#receive-address').textContent(), ''); assert.equal(await page.locator('#nodus-address-status').textContent(), '');
  await page.setViewportSize({ width: 390, height: 844 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(errors, []);
  console.log('Browser smoke passed: create/backup/restore, NODUS first and default-selected (receive-only row, no balance shown, no Send), Nodus native address/copy/lock/reopen, 4 external chain addresses, ETH/ERC20 signed mocked broadcasts, wrong-network guard, automatic Cellframe address derivation + CPUNK balance display/error, send disabled on Cellframe, finalized scoped activity, encrypted save/unlock/change/reload/delete, KDF cancellation, temporary storage behavior, mobile layout. No external request reached a blockchain.');
} catch (error) { console.error('UI status:', await page.locator('#wallet-status').textContent(), 'Cellframe:', await page.locator('#cellframe-address-status').textContent(), 'Page errors:', errors, 'Methods:', calls.map(c => c?.method)); throw error; } finally { await browser.close(); server?.kill(); }
