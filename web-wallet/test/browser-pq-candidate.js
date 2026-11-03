// Real production bundles, public test phrase, temporary profiles, and no live RPC.
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, relative, isAbsolute, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright';
import { pastePhrase } from './browser-phrase.js';
const root = fileURLToPath(new URL('..', import.meta.url));
const dist = join(root, 'dist'), extension = join(root, 'dist-extension/unpacked');
const fixture = JSON.parse(await readFile(new URL('./fixtures/pq-receive.json', import.meta.url), 'utf8')).vectors[0];
const password = 'Aa9!' + randomBytes(24).toString('hex');
const server = createServer(async (req, res) => {
  if (/^https?:/.test(req.url)) { res.writeHead(403); res.end(); return; }
  const target = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
  const within = relative(dist, target);
  if (within.startsWith('..') || isAbsolute(within)) { res.writeHead(403); res.end(); return; }
  try {
    const file = target === dist ? join(dist, 'index.html') : target;
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
async function environment(page, network) {
  const select = page.locator('#pq-network-environment');
  if (await select.inputValue() === network) return;
  if (await select.isVisible()) return select.selectOption(network);
  if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
  if (!await page.locator('#wallet-environment').evaluate(node => node.open)) await page.locator('#wallet-environment > summary').click();
  await page.locator(`#wallet-environment [data-environment="${network}"]`).click();
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
        await environment(page, network);
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
      await choose(page, 'ckb'); await environment(page, 'mainnet');
      await page.waitForFunction(expected => document.querySelector('#receive-address').textContent === expected, fixture.addresses.ckb.mainnet);
    }
    assert.deepEqual(errors, []);
    console.log(`PASS ${mode}: real restore/keygen, 13 address and send-capability variants, QR rendering${mode === 'extension' ? ', encrypted lock/unlock recovery' : ''}; no broadcasts`);
    await context.close(); context = null;
  }
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
