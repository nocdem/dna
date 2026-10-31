// Parent gate: real packaged MV3 worker, shipped WASM, Chrome storage and
// IndexedDB; public existing recovery fixture only. Requires extension build.
// Offline proxy blocks all external traffic from browser/worker startup.
// Proves same-window rendering, drafts, shared worker/session, encrypted local
// persistence, lock/reopen and erase counter continuity. An isolated fixture
// writer seeds real encrypted history while the wallet is locked, before any
// network queue can block local work. It is added only to a temporary package
// copy; production scripts/WASM/manifest remain byte-identical. NOT live delivery.
// No compile flags. CHROMIUM_PATH optional; CONNECT_SCREENSHOT_DIR preserves
// screenshots. Temporary browser profile/server are always removed; no skips.
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, mkdir, cp } from 'node:fs/promises';
import { build } from 'esbuild';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { pastePhrase } from './browser-phrase.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const packageRoot = join(root, 'dist-extension/unpacked');
const manifest = JSON.parse(await readFile(join(packageRoot, 'manifest.json'), 'utf8'));
const fixture = JSON.parse(await readFile(new URL('./fixtures/pq-receive.json', import.meta.url), 'utf8')).vectors[0];
const password = 'Pq9!Velvet-Cedar-Moon$47', errors = [], outside = [];
const address = 'a1'.repeat(64), marker = 'PUBLIC-FIXTURE-LOCAL-RECORD';
const temporary = await mkdtemp(join(tmpdir(), 'extension-connect-'));
const extension = join(temporary, 'extension');
const server = createServer((req, res) => { outside.push(req.url); res.writeHead(403); res.end(); });
server.on('connect', (req, socket) => { outside.push(req.url); socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); });
let context;

// Same authenticated controller protocol as the UI; never an untrusted page.
// Raw frames are small here; a chunked/unknown frame fails rather than silently
// dropping it. No production test hook or key access is added.
async function rpcSetup(page) {
  await page.evaluate(async () => {
    const port = chrome.runtime.connect({ name: 'popup' }), pending = new Map();
    let serial = 0, ready;
    const synced = new Promise(resolve => { ready = resolve; });
    port.onMessage.addListener(message => {
      if (typeof message === 'string') throw new Error('Unexpected chunked test frame');
      if (message.name !== 'controller') return;
      const value = message.data;
      if (value.method === 'START_UI_SYNC') { ready(); return; }
      const entry = pending.get(value.id); if (!entry) return;
      pending.delete(value.id);
      if (value.error) entry.reject(new Error(value.error.message)); else entry.resolve(value.result);
    });
    port.onDisconnect.addListener(() => { for (const entry of pending.values()) entry.reject(new Error('Disconnected')); pending.clear(); });
    window.connectTestRpc = (method, params = []) => new Promise((resolve, reject) => {
      const id = ++serial; pending.set(id, { resolve, reject });
      port.postMessage({ name: 'controller', data: { jsonrpc: '2.0', id, method, params } });
    });
    await synced;
  });
}
const rpc = (page, method, params = []) => page.evaluate(({ method, params }) => window.connectTestRpc(method, params), { method, params });
async function connectView(page) {
  await page.locator('#wallet-connect-switch').click();
  await page.locator('#extension-connect:visible').waitFor();
  await page.waitForFunction(() => document.querySelector('#nc-own-id')?.textContent?.length === 128);
}
async function unlock(page) {
  await page.locator('#unlock-password:visible').fill(password);
  await page.locator('#unlock-wallet').click();
  await page.locator('#wallet-open:visible').waitFor();
}
async function screenshot(page, name) {
  if (!process.env.CONNECT_SCREENSHOT_DIR) return;
  await mkdir(process.env.CONNECT_SCREENSHOT_DIR, { recursive: true });
  await page.screenshot({ path: join(process.env.CONNECT_SCREENSHOT_DIR, name), fullPage: true });
}
try {
  await cp(packageRoot, extension, { recursive: true });
  await cp(join(packageRoot, 'wasm/send.wasm'), join(extension, 'send.wasm'));
  await build({ entryPoints: [join(root, 'test/extension-history-fixture.js')], bundle: true, format: 'esm', platform: 'browser',
    outfile: join(extension, 'test-history-fixture.js'), logLevel: 'silent' });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const origin = `http://127.0.0.1:${server.address().port}`;
  context = await chromium.launchPersistentContext(join(temporary, 'profile'), {
    executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', channel: 'chromium', headless: true,
    viewport: { width: 440, height: 800 }, ignoreDefaultArgs: ['--disable-extensions'],
    args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`, `--proxy-server=${origin}`,
      '--proxy-bypass-list=127.0.0.1', '--disable-background-networking'],
  });
  context.setDefaultTimeout(15000);
  await context.route('**/*', route => {
    if (new URL(route.request().url()).protocol === 'chrome-extension:') return route.continue();
    outside.push(route.request().url()); return route.abort('blockedbyclient');
  });
  const worker = context.serviceWorkers().find(w => w.url().startsWith('chrome-extension:')) || await context.waitForEvent('serviceworker');
  const base = `chrome-extension://${new URL(worker.url()).hostname}`;
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message));
  if (process.env.CONNECT_DEBUG_EXCEPTIONS) {
    const cdp = await context.newCDPSession(page);
    const { targetInfos } = await cdp.send('Target.getTargets');
    const target = targetInfos.find(x => x.type === 'service_worker' && x.url === worker.url());
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: target.targetId, flatten: false });
    let id = 0;
    const command = (method, params = {}) => cdp.send('Target.sendMessageToTarget', { sessionId, message: JSON.stringify({ id: ++id, method, params }) });
    cdp.on('Target.receivedMessageFromTarget', event => {
      const message = JSON.parse(event.message);
      if (message.method === 'Debugger.paused') {
        console.error('WORKER EXCEPTION', message.params.reason, message.params.data?.description?.split('\n')[0],
          message.params.callFrames.slice(0, 4).map(f => f.functionName));
        void command('Debugger.resume');
      }
    });
    await command('Debugger.enable'); await command('Debugger.setPauseOnExceptions', { state: 'all' });
  }
  await page.goto(`${base}/${manifest.action.default_popup}`);
  await page.locator('#restore:visible').click(); await pastePhrase(page, fixture.phrase);
  await page.locator('#backup-confirm').check();
  await page.locator('#new-password').fill(password); await page.locator('#confirm-password').fill(password);
  await page.locator('#phrase-submit').click(); await page.locator('#wallet-open:visible').waitFor();
  await rpcSetup(page);
  const tabs = context.pages().length;
  await screenshot(page, 'extension-wallet.png');
  // NODUS correctly disables sending without a connection. Use the existing
  // Ethereum draft form for view-retention coverage; never review or submit it.
  await page.locator('.wallet-navigation a[href="#send-form"]').click();
  await page.locator('#chain').selectOption('ethereum');
  const initialUrl = page.url();
  await page.locator('#recipient').fill('Public draft recipient');
  await page.locator('#amount').fill('1.25');
  await connectView(page);
  let state = await rpc(page, 'getConnectState');
  assert.equal(state.phase, 'open', state.text); assert.equal(state.persistent, true); assert.equal(state.online, false);
  assert.match(state.ownFp, /^[0-9a-f]{128}$/); const fp = state.ownFp;
  assert.equal(JSON.stringify(state).includes(fixture.phrase), false);
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await screenshot(page, 'extension-connect.png');
  await page.getByRole('button', { name: 'Your ID & profile', exact: true }).click();
  await page.locator('#nc-bio').fill('Draft kept while switching');
  await page.locator('#wallet-connect-switch').click(); await page.locator('#wallet-open:visible').waitFor();
  assert.equal(await page.locator('#recipient').inputValue(), 'Public draft recipient');
  assert.equal(await page.locator('#amount').inputValue(), '1.25');
  assert.equal(await page.locator('#chain').inputValue(), 'ethereum');
  await page.locator('#wallet-connect-switch').click();
  assert.equal(await page.locator('#nc-bio').inputValue(), 'Draft kept while switching');
  assert.equal(context.pages().length, tabs); assert.equal(page.url(), initialUrl);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Popup has no horizontal overflow');

  await page.getByRole('button', { name: 'Lock wallet', exact: true }).click();
  await page.locator('#unlock-password:visible').waitFor();
  await page.evaluate(async input => (await import(chrome.runtime.getURL('test-history-fixture.js'))).seedHistory(input),
    { phrase: fixture.phrase, fingerprint: fp, address, marker });
  await unlock(page); await connectView(page); state = await rpc(page, 'getConnectState');
  assert.ok(JSON.stringify(state.vaults).includes(marker), 'Actual worker kept the local fixture');
  const saved = await worker.evaluate(async () => {
    const all = await chrome.storage.local.get(null);
    return { counters: Object.fromEntries(Object.entries(all).filter(([k]) => k.startsWith('nodus.connect.counter.v1.'))), text: JSON.stringify(all), databases: await indexedDB.databases() };
  });
  assert.equal(Object.keys(saved.counters).length, 1);
  const counterKey = Object.keys(saved.counters)[0], count = BigInt(saved.counters[counterKey]);
  assert.ok(count > 0n); assert.equal(saved.text.includes(marker), false); assert.equal(saved.text.includes(fixture.phrase), false);
  assert.ok(saved.databases.some(db => db.name === counterKey.slice('nodus.connect.counter.v1.'.length)));

  const second = await context.newPage(); second.on('pageerror', error => errors.push(error.message));
  await second.goto(`${base}/home.html`); await second.locator('#wallet-open:visible').waitFor();
  await rpcSetup(second); assert.deepEqual(await rpc(second, 'getConnectState'), state, 'Second window uses the same worker session');
  await second.close(); await page.close();
  const reopened = await context.newPage(); reopened.on('pageerror', error => errors.push(error.message));
  await reopened.goto(`${base}/popup.html`); await reopened.locator('#wallet-open:visible').waitFor(); await rpcSetup(reopened);
  assert.equal((await rpc(reopened, 'getConnectState')).epoch, state.epoch, 'Closing windows does not replace the worker session');
  await connectView(reopened); await reopened.getByRole('button', { name: 'Lock wallet', exact: true }).click();
  await reopened.locator('#unlock-password:visible').waitFor();
  assert.equal(await reopened.locator('#extension-connect').count(), 0);
  await assert.rejects(rpc(reopened, 'getConnectState'), /locked/i);
  await unlock(reopened); await connectView(reopened);
  let after = await rpc(reopened, 'getConnectState');
  assert.equal(after.ownFp, fp); assert.ok(after.epoch > state.epoch);
  assert.ok(JSON.stringify(after.vaults).includes(marker), 'Encrypted record opens under the same saved wallet');
  await assert.rejects(rpc(reopened, 'connectAction', [state.epoch, 'sync', {}]), /closed/i);
  await reopened.getByRole('button', { name: 'Your ID & profile', exact: true }).click();
  assert.equal(await reopened.locator('#nc-bio').inputValue(), '', 'Lock drops unsaved drafts');
  await reopened.locator('#nc-bio').fill('Draft must be erased with history');
  await reopened.getByRole('button', { name: 'Delete message history on this device', exact: true }).click();
  await reopened.getByRole('button', { name: 'Confirm: delete all messages on this device', exact: true }).click();
  await reopened.waitForFunction(() => document.querySelector('#extension-connect')?.textContent.includes('Message history deleted'));
  assert.equal(await reopened.locator('#nc-bio').inputValue(), '', 'History erase clears remote drafts without a new client epoch');
  assert.deepEqual(await reopened.locator('.message-list').allTextContents(), ['', ''], 'Direct and group message lists are empty');
  assert.equal(await reopened.locator('dialog[open]').count(), 0);
  const counterAfter = await worker.evaluate(async key => (await chrome.storage.local.get(key))[key], counterKey);
  assert.ok(BigInt(counterAfter) >= count, 'Erasing messages preserves the encryption invocation budget');
  await reopened.getByRole('button', { name: 'Lock wallet', exact: true }).click();
  await unlock(reopened); await connectView(reopened);
  after = await rpc(reopened, 'getConnectState');
  assert.deepEqual(after.vaults, []); assert.equal(after.ownFp, fp);
  // Negative control: blocked transport holds the native queue until its
  // EXISTING watchdog closes it. The worker must immediately drop Connect's
  // public projection, reject that old action and then reopen on a new client.
  const beforeLoss = after;
  const waitingWrite = rpc(reopened, 'connectAction', [beforeLoss.epoch, 'vaultKeep', { address, value: { name: marker } }]);
  await assert.rejects(waitingWrite, /closed|locked|sealed/i);
  const lost = await rpc(reopened, 'getConnectState');
  assert.equal(lost.ownFp, null); assert.notEqual(lost.phase, 'open'); assert.deepEqual(lost.vaults, []);
  await reopened.waitForFunction(() => document.querySelector('#nc-own-id')?.textContent === '');
  await reopened.waitForFunction(() => document.querySelector('#nc-own-id')?.textContent?.length === 128);
  const reconnected = await rpc(reopened, 'getConnectState');
  assert.ok(reconnected.epoch > beforeLoss.epoch); assert.equal(reconnected.phase, 'open');
  assert.equal(reconnected.ownFp, fp); assert.deepEqual(reconnected.vaults, []);
  await assert.rejects(rpc(reopened, 'connectAction', [beforeLoss.epoch, 'sync', {}]), /closed/i);
  assert.deepEqual(errors, []);
  assert.ok(outside.every(url => !url.includes(fixture.phrase)));
  console.log('PASS packaged extension: same-window switch/draft, shared worker, real encrypted history, lock/reopen and erase counter continuity; external transport blocked, live delivery untested');
} catch (error) {
  for (const page of context?.pages() || []) {
    console.error('Browser diagnostic', await page.evaluate(() => ({ url: location.href, text: document.body.innerText })).catch(() => ({})));
    console.error('Worker diagnostic', await page.evaluate(async () => {
      if (!window.connectTestRpc) return null;
      const [wallet, connect] = await Promise.all([window.connectTestRpc('getState'), window.connectTestRpc('getConnectState')]);
      return { nodus: { state: wallet.nodus.state, connection: wallet.nodus.connection }, phase: connect.phase, epoch: connect.epoch, text: connect.text,
        log: JSON.stringify(await window.connectTestRpc('getSessionLog')) };
    }).catch(error => error.message));
  }
  console.error('Page errors', errors); throw error;
} finally {
  await context?.close();
  if (server.listening) await new Promise(done => { server.close(done); server.closeAllConnections(); });
  await rm(temporary, { recursive: true, force: true });
}
