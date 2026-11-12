// Real production bundles, public test phrase, temporary profiles, and no live RPC.
// Proves: restore and the receive address, QR and send gate for all 13 chain/
// network variants of fixtures/pq-receive.json on the web build and the extension
// (plus an encrypted lock/unlock for the extension); the CKB send flow on the web
// build and Connect (see the CKB block below). Nothing is broadcast.
// Needs: built dist/ (web), dist-connect/ (Connect) and dist-extension/unpacked
// (extension); Chromium given by CHROMIUM_PATH (executablePath with channel
// 'chromium'; the file sets no default); the host listens on 127.0.0.1 port 0 and
// every other origin is refused. No flags.
// Leaves: nothing; the temporary profiles and the host are removed in finally.
// Falsely passes: the files served are the built ones, so a stale build passes;
// the send-gate expectations are written out in this file, so a gate changed in
// both places at once is not noticed; the 13 count is asserted, a fixture with
// other entries fails rather than passes.
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, relative, isAbsolute, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright';
import { bech32m } from '@scure/base';
import { pastePhrase } from './browser-phrase.js';
import { ckbNetwork } from '../src/pq/ckb.js';
const root = fileURLToPath(new URL('..', import.meta.url));
const dist = join(root, 'dist'), distConnect = join(root, 'dist-connect'), extension = join(root, 'dist-extension/unpacked');
const fixture = JSON.parse(await readFile(new URL('./fixtures/pq-receive.json', import.meta.url), 'utf8')).vectors[0];
const password = 'Aa9!' + randomBytes(24).toString('hex');
let served = dist;
const server = createServer(async (req, res) => {
  if (/^https?:/.test(req.url)) { res.writeHead(403); res.end(); return; }
  const target = resolve(served, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
  const within = relative(served, target);
  if (within.startsWith('..') || isAbsolute(within)) { res.writeHead(403); res.end(); return; }
  try {
    const file = target === served ? join(served, 'index.html') : target;
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.png': 'image/png' })[extname(file)] || 'application/octet-stream' });
    res.end(data);
  } catch { res.writeHead(404); res.end(); }
});
server.on('connect', (_req, socket) => { socket.on('error', () => {}); socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); });
await new Promise(done => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;
const temporary = await mkdtemp(join(tmpdir(), 'pq-candidate-'));
let context, activePage;
async function choose(page, chain) {
  await page.locator('.wallet-navigation a[href="#"]').click();
  await page.locator('#wallet-home').waitFor({ state: 'visible' });
  await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled);
  if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
  const badge = page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);
  const group = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]');
  const toggle = group.locator('.network-group-toggle');
  if (await toggle.count() && await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  await badge.click();
  await page.locator('.wallet-navigation a[href="#receive"]').click();
}
// A chain's network is chosen in Device & settings only (#network-<chain>; the wallet screen has no chooser). A chain with
// one network (Tidecoin, Soqucoin) has no list and nothing to choose. After a change the script is back on the Receive page.
// How this could falsely pass: for a single-network chain nothing is checked here; the callers wait for the expected address.
async function environment(page, chain, network) {
  const select = page.locator(`#network-${chain}`);
  if (!await select.count() || await select.inputValue() === network) return;
  const settings = await page.locator('#extension-bottom-bar').count() ? page.locator('#extension-bottom-bar button[aria-label="Settings"]') : page.locator('.wallet-navigation a[href="#settings"]');
  await settings.click(); await page.locator('#page-settings').waitFor({ state: 'visible' });
  await select.selectOption(network);
  await page.locator('#page-settings .page-back').click(); await page.locator('#page-settings').waitFor({ state: 'hidden' });
  await page.locator('.wallet-navigation a[href="#receive"]').click();
}
// CKB send on the web wallet and Connect (docs/plans/approved/2026-11-03-pq-send-parity.md
// D3, D5, D6, section 5). A scripted mainnet node (labelled fixture, same answers as
// test/ckb-web-lifecycle.test.js) answers the reads; every simulation request is refused
// as a network error, so the signed transaction never reaches a real node and nothing is
// broadcast. Proves: the review rows are the extension's (extension/src/background/ckb.js:44,
// :35), an uncertain first send keeps a recovery button and no "Mark as abandoned", a failed
// "Review same-transaction recovery" stays unresolved across a page reload and unlock, and a
// new CKB send is then refused. How it could falsely pass: the node is scripted, so it does
// not prove node admission or the lock script on a real chain.
const ckbNet = ckbNetwork('mainnet');
function ckbNode() {
  const H = '0x' + 'ab'.repeat(32), T = '0x' + 'cd'.repeat(32), P = '0x' + 'ef'.repeat(32);
  const payload = bech32m.fromWords(bech32m.decode(fixture.addresses.ckb.mainnet, 1023).words);
  const lock = { code_hash: ckbNet.codeHash, hash_type: ckbNet.hashType, args: '0x' + Buffer.from(payload.slice(34)).toString('hex') };
  const out = { capacity: '0x' + (30000000000n).toString(16), lock, type: null };
  const requests = [];
  const answer = q => {
    switch (q.method) {
      case 'get_block_hash': return q.params[0] === '0x0' ? ckbNet.genesisHash : H;
      case 'get_tip_header': return { hash: H, number: '0x64', timestamp: '0x' + Date.now().toString(16) };
      case 'get_indexer_tip': return { block_number: '0x64', block_hash: H };
      case 'get_cells': return { objects: [{ out_point: { tx_hash: T, index: '0x0' }, block_number: '0x63', tx_index: '0x1', output: out, output_data: '0x' }], last_cursor: '0x00' };
      case 'get_transaction': return q.params[0] === T
        ? { transaction: { hash: T, inputs: [{ previous_output: { tx_hash: P, index: '0x0' }, since: '0x0' }], outputs: [out], outputs_data: ['0x'] }, tx_status: { status: 'committed', block_hash: H, block_number: '0x63', tx_index: '0x1' } }
        : { transaction: null, tx_status: { status: 'unknown' } };
      case 'get_live_cell': return { status: 'live', cell: { output: out, data: { content: '0x' } } };
      case 'tx_pool_info': return { tip_hash: H, tip_number: '0x64', min_fee_rate: '0x3e8', tx_size_limit: '0x7d000' };
      case 'get_fee_rate_statistics': return { mean: '0x103593', median: '0x81c6' };
      default: return undefined;
    }
  };
  async function handle(route) {
    const body = JSON.parse(route.request().postData() || 'null'), calls = Array.isArray(body) ? body : [body];
    for (const q of calls) requests.push(q?.method);
    if (calls.some(q => ['test_tx_pool_accept', 'send_transaction'].includes(q?.method))) return route.abort('failed');
    const reply = q => { const result = answer(q); return result === undefined ? { jsonrpc: '2.0', id: q.id, error: { code: -32601, message: 'Method not found' } } : { jsonrpc: '2.0', id: q.id, result }; };
    return route.fulfill({ status: 200, headers: { 'access-control-allow-origin': '*' }, contentType: 'application/json', body: JSON.stringify(Array.isArray(body) ? calls.map(reply) : reply(body)) });
  }
  return { requests, handle };
}
const reviewNames = page => page.locator('#review-details dt').allTextContents();
const reviewValue = async (page, name) => { const names = await reviewNames(page); return page.locator('#review-details dd').nth(names.indexOf(name)).textContent(); };
async function confirmReview(page) {
  await page.waitForFunction(() => !document.querySelector('#confirm-send').disabled);
  await page.locator('#confirm-send').click();
  await page.waitForFunction(() => !document.querySelector('#review-dialog').open);
}
// Connect opens on its Home tab; the wallet is the "Wallet" tab (test/connect-smoke.js:130).
async function walletTab(page) {
  const tab = page.locator('.app-nav-item[data-tab="wallet"]');
  if (await tab.count()) await tab.click();
}
async function openSend(page) {
  await page.locator('.wallet-navigation a[href="#"]').click();
  await page.locator('#wallet-home').waitFor({ state: 'visible' });
  // The page's own shortcut path clicks the button the same way (src/app.js:714).
  assert.equal(await page.locator('#quick-send').isDisabled(), false);
  await page.locator('#quick-send').evaluate(button => button.click());
  await page.locator('#recipient').waitFor({ state: 'visible' });
}
async function openCkbActivity(page) {
  await choose(page, 'ckb'); await environment(page, 'ckb', 'mainnet');
  await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('Review same-transaction recovery'));
}
async function ckbSendFlow(mode, directory) {
  served = directory;
  console.log(`START ckb-send ${mode}`);
  const node = ckbNode();
  context = await chromium.launchPersistentContext(join(temporary, `ckb-${mode}`), {
    executablePath: process.env.CHROMIUM_PATH, channel: 'chromium', headless: true, chromiumSandbox: true,
    args: [`--proxy-server=${origin}`, '--proxy-bypass-list=127.0.0.1', '--disable-background-networking'],
  });
  context.setDefaultTimeout(20000);
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin === origin) return route.continue();
    if (url.href.replace(/\/$/, '') === ckbNet.rpc.replace(/\/$/, '')) return node.handle(route);
    return route.abort('blockedbyclient');
  });
  await context.routeWebSocket(() => true, ws => ws.close());
  const page = activePage = await context.newPage(), errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.waitForFunction(() => !document.querySelector('#restore').disabled);
  await page.locator('#restore:visible').click(); await pastePhrase(page, fixture.phrase);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await walletTab(page);
  // The extension's Settings is a bottom-bar button (UI pack 2026-11-03); web and Connect keep the rail gear.
  await page.locator(mode === 'extension' ? '#extension-bottom-bar button[aria-label="Settings"]' : '.wallet-navigation a[href="#settings"]').click(); await page.locator('#vault-storage-title').click();
  await page.locator('#vault-password').fill(password); await page.locator('#vault-confirm-password').fill(password);
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-save-status').textContent.includes('Encrypted wallet saved'));
  // Operator decision 2026-11-03 (plan D2): on this page XION, Splendor, QTC and Ixios mainnet
  // show "Send <SYMBOL> from the extension." and no send fields; the extension sends there.
  for (const [chain, symbol] of [['xion', 'XION'], ['splendor', 'SPLD'], ['qtc', 'QTC'], ['ixios', 'IXIOS']]) {
    await choose(page, chain);
    if (chain !== 'ixios') await environment(page, chain, 'mainnet');
    assert.equal(await page.locator('#quick-send').isDisabled(), true, `${mode}:${chain} send gate`);
    assert.equal(await page.locator('#send-disabled-note').textContent(), `Send ${symbol} from the extension.`, `${mode}:${chain} note`);
    assert.equal(await page.locator('#send-fields').isVisible(), false, `${mode}:${chain} has no send fields`);
  }
  await choose(page, 'ckb'); await environment(page, 'ckb', 'mainnet');
  assert.equal(await page.locator('#quick-send').isDisabled(), false, `${mode}: CKB mainnet send is open`);
  // First send: the simulation request is refused after the signed transaction was handed
  // to the request, so the outcome is uncertain (unknown), never "Nothing was broadcast".
  await openSend(page);
  await page.locator('#recipient').fill(fixture.addresses.ckb.mainnet); await page.locator('#amount').fill('100');
  await page.locator('#review-button').click();
  await page.waitForFunction(() => document.querySelector('#review-dialog').open);
  assert.deepEqual(await reviewNames(page), ['Network', 'From', 'To', 'Amount', 'Fee', 'Fee rate', 'Scope', 'Simulation', 'Review expires'], `${mode}: send review rows`);
  assert.equal(await reviewValue(page, 'Network'), 'CKB Mainnet');
  assert.equal(await reviewValue(page, 'Amount'), '100.0 CKB');
  assert.equal(await reviewValue(page, 'Simulation'), 'The configured node receives the signed transaction and could relay it.');
  await confirmReview(page);
  await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('Review same-transaction recovery'));
  let activity = await page.locator('#activity').textContent();
  assert.doesNotMatch(activity, /Mark as abandoned|Nothing was broadcast/, `${mode}: uncertain CKB row`);
  // "Tekrar dene": the recovery review shows the extension's rows; its simulation fails too.
  await page.locator('#activity button', { hasText: 'Review same-transaction recovery' }).click();
  await page.waitForFunction(() => document.querySelector('#review-dialog').open);
  assert.deepEqual(await reviewNames(page), ['Action', 'Transaction ID', 'From', 'To', 'Amount', 'Fee', 'Recovery', 'Review expires'], `${mode}: recovery review rows`);
  assert.equal(await reviewValue(page, 'Action'), 'Resubmit EXACTLY the previously signed transaction; no new signature');
  await confirmReview(page);
  await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('Review same-transaction recovery'));
  assert.doesNotMatch(await page.locator('#activity').textContent(), /Nothing was broadcast/, `${mode}: failed recovery`);
  // The page is opened again: the row is still unresolved and a new CKB send is refused.
  await page.reload();
  await page.locator('#unlock-password:visible').fill(password); await page.locator('#unlock-wallet').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await walletTab(page);
  await openCkbActivity(page);
  activity = await page.locator('#activity').textContent();
  assert.doesNotMatch(activity, /Mark as abandoned|Nothing was broadcast/, `${mode}: after reload`);
  await openSend(page);
  await page.locator('#recipient').fill(fixture.addresses.ckb.mainnet); await page.locator('#amount').fill('100');
  await page.locator('#review-button').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('A previous send on this network has no final result yet'));
  assert.equal(await page.locator('#review-dialog').evaluate(dialog => dialog.open), false);
  assert.equal(node.requests.filter(m => m === 'test_tx_pool_accept').length, 2, `${mode}: one simulation request for the send, one for the recovery`);
  assert.equal(node.requests.includes('send_transaction'), false);
  assert.deepEqual(errors, []);
  console.log(`PASS ckb-send ${mode}: four "from the extension" notes, extension review rows, uncertain first send, failed recovery stays unresolved after reload, new send refused; nothing broadcast`);
  await context.close(); context = null;
}
try {
  for (const mode of ['web', 'extension']) {
    console.log(`START ${mode}`);
    context = await chromium.launchPersistentContext(join(temporary, mode), {
      executablePath: process.env.CHROMIUM_PATH, channel: 'chromium', headless: true, chromiumSandbox: true,
      ignoreDefaultArgs: mode === 'extension' ? ['--disable-extensions'] : [],
      args: [`--proxy-server=${origin}`, '--proxy-bypass-list=127.0.0.1', '--disable-background-networking',
        ...(mode === 'extension' ? [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`] : [])],
    });
    context.setDefaultTimeout(20000);
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      return url.origin === origin || url.protocol === 'chrome-extension:' ? route.continue() : route.abort('blockedbyclient');
    });
    await context.routeWebSocket(() => true, ws => ws.close());
    let url = origin;
    if (mode === 'extension') {
      const worker = context.serviceWorkers().find(w => w.url().startsWith('chrome-extension:')) || await context.waitForEvent('serviceworker');
      url = `chrome-extension://${new URL(worker.url()).hostname}/home.html`;
    }
    const page = activePage = await context.newPage(), errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(url);
    // The extension's first screen is the data notice (2026-11-03 Chrome Web Store decision, plan section 2.7).
    if (mode === 'extension') await page.locator('#privacy-agree:visible').click();
    await page.locator('#restore:visible').click(); await pastePhrase(page, fixture.phrase);
    await page.locator('#backup-confirm').check();
    if (mode === 'extension') {
      await page.locator('#new-password').fill(password); await page.locator('#confirm-password').fill(password);
    }
    await page.locator('#phrase-submit').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
    let checked = 0;
    for (const [chain, networks] of Object.entries(fixture.addresses)) {
      for (const [network, address] of Object.entries(networks)) {
        console.log(`CHECK ${mode}:${chain}:${network}`);
        await choose(page, chain);
        await environment(page, chain, network);
        await page.waitForFunction(expected => document.querySelector('#receive-address').textContent === expected, address);
        assert.equal(await page.locator('#copy-address').isDisabled(), false, `${mode}:${chain}:${network}`);
        assert.equal(await page.locator('#receive-qr svg').count(), 1);
        const send = mode === 'extension'
          ? chain !== 'tidecoin' && (chain === 'asentum' ? network === 'testnet' : network === 'mainnet')
          : ['algorand', 'soqucoin', 'ckb'].includes(chain) ? network === 'mainnet' : chain === 'asentum' && network === 'testnet';
        assert.equal(await page.locator('#quick-send').isDisabled(), !send, `${mode}:${chain}:${network} send gate`);
        // Operator decision 2026-11-03: XION, Splendor and QTC send stays in the extension; the
        // web wallet and Connect say so on mainnet (the extension does send there).
        const fromExtension = { xion: 'XION', splendor: 'SPLD', qtc: 'QTC' }[chain];
        if (mode === 'web' && fromExtension && network === 'mainnet') {
          assert.equal(await page.locator('#send-disabled-note').textContent(), `Send ${fromExtension} from the extension.`, `${mode}:${chain}:${network} note`);
          assert.equal(await page.locator('#send-fields').isVisible(), false, `${mode}:${chain}:${network} has no send fields`);
        }
        checked++;
      }
    }
    assert.equal(checked, 13);
    if (mode === 'extension') {
      await page.locator('.wallet-navigation a[href="#"]').click(); await page.locator('#lock').click();
      await page.locator('#unlock-password:visible').fill(password); await page.locator('#unlock-wallet').click();
      await page.locator('#wallet-open').waitFor({ state: 'visible' });
      await choose(page, 'ckb'); await environment(page, 'ckb', 'mainnet');
      await page.waitForFunction(expected => document.querySelector('#receive-address').textContent === expected, fixture.addresses.ckb.mainnet);
    }
    assert.deepEqual(errors, []);
    console.log(`PASS ${mode}: real restore/keygen, 13 address and send-capability variants, QR rendering${mode === 'extension' ? ', encrypted lock/unlock recovery' : ''}; no broadcasts`);
    await context.close(); context = null;
  }
  await ckbSendFlow('web', dist);
  await ckbSendFlow('connect', distConnect);
} catch (error) {
  console.error('UI DIAGNOSTIC', JSON.stringify(await activePage?.evaluate(() => ({
    chain: document.querySelector('#chain')?.value,
    walletStatus: document.querySelector('#wallet-status')?.textContent,
    phraseError: document.querySelector('#phrase-error')?.textContent,
    invalidFields: [...document.querySelectorAll(':invalid')].map(n => ({ id: n.id, message: n.validationMessage })),
    assets: [...document.querySelectorAll('#balances > *')].map(n => ({ tag: n.tagName, classes: n.className, chain: n.dataset.chain })),
    picker: [...document.querySelectorAll('#wallet-network, #portfolio-networks, #portfolio-networks [data-chain="algorand"]')].map(n => ({ id: n.id, hidden: n.hidden, open: n.open, display: getComputedStyle(n).display, parents: [...(function*(){for(let p=n.parentElement;p;p=p.parentElement)yield p;})()].map(p=>({id:p.id,tag:p.tagName,hidden:p.hidden,open:p.open,display:getComputedStyle(p).display})) }))
  })).catch(() => null)));
  throw error;
} finally {
  await context?.close(); await new Promise(done => server.close(done)); await rm(temporary, { recursive: true, force: true });
}
