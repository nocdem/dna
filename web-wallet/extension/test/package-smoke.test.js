import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Script } from 'node:vm';

const exec = promisify(execFile);
const walletRoot = fileURLToPath(new URL('../../', import.meta.url));
const sourceManifest = JSON.parse(await readFile(new URL('../manifest.json', import.meta.url), 'utf8'));
const zip = join(walletRoot, 'dist-extension', `nodus-wallet-${sourceManifest.version}.zip`);

async function filesBelow(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = `${prefix}${entry.name}`;
    if (entry.isDirectory()) files.push(...await filesBelow(join(directory, entry.name), `${relative}/`));
    else {
      assert.ok(entry.isFile(), `Unexpected archive entry: ${relative}`);
      files.push(relative);
    }
  }
  return files.sort();
}

// Node 22; no compile flags. Environment: CHROMIUM_PATH defaults to /usr/bin/chromium.
// Run after scripts/build-extension.sh. Only an absent versioned zip skips this test.
// Proves archive paths/assets/classic scripts and real Chromium startup/UI/discovery.
// The popup's outside-fetch negative control must fail and be recorded by the route.
// Does not unlock, sign, or contact a chain. The local server also rejects proxy
// traffic, including worker requests made before Playwright installs its routes.
// The extracted extension, browser profile and server are removed even on failure.
// A stale zip could falsely pass against changed source: byte comparisons cover
// copied WASM/assets; the orchestrator must rebuild before checking bundled code.
test('MV3 zip loads in Chromium and announces Nodus Wallet to a local page', { timeout: 60_000 }, async t => {
  try { await access(zip); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    t.skip(`Extension zip absent: ${zip}; run bash scripts/build-extension.sh before this smoke test.`);
    return;
  }

  const temporary = await mkdtemp(join(tmpdir(), 'nodus-extension-smoke-'));
  const extension = join(temporary, 'extension');
  let context, server;
  try {
    const { stdout } = await exec('/usr/bin/unzip', ['-Z1', zip]);
    const entries = stdout.trim().split('\n');
    assert.equal(new Set(entries).size, entries.length, 'Duplicate zip entries');
    for (const entry of entries) {
      assert.ok(entry && !entry.startsWith('/') && !entry.includes('\\') &&
        !entry.split('/').includes('..'), `Unsafe zip entry: ${entry}`);
      assert.ok(!/(^|\/)site-sdk(\/|$)/u.test(entry), 'Site SDK must not ship in the extension');
    }
    await exec('/usr/bin/unzip', ['-q', zip, '-d', extension]);
    const files = await filesBelow(extension);
    for (const file of files) t.diagnostic(`${file}\t${(await stat(join(extension, file))).size} bytes`);
    const manifest = JSON.parse(await readFile(join(extension, 'manifest.json'), 'utf8'));
    assert.equal(manifest.manifest_version, 3);
    assert.equal(manifest.version, sourceManifest.version);
    assert.deepEqual(manifest.content_scripts, sourceManifest.content_scripts);
    assert.deepEqual(manifest.background, sourceManifest.background);
    assert.deepEqual(Object.keys(manifest.icons), Object.keys(sourceManifest.icons));
    assert.deepEqual(Object.keys(manifest.action.default_icon), Object.keys(sourceManifest.action.default_icon));
    for (const [size, path] of [...Object.entries(manifest.icons), ...Object.entries(manifest.action.default_icon)]) {
      assert.match(path, /\.png$/u, 'Manifest icons must be raster PNGs');
      const png = await readFile(join(extension, path));
      assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
      assert.equal(png.readUInt32BE(16), Number(size));
      assert.equal(png.readUInt32BE(20), Number(size));
    }
    const scripts = [manifest.background.service_worker, ...manifest.content_scripts.flatMap(entry => entry.js)];
    for (const script of scripts) {
      const code = await readFile(join(extension, script), 'utf8');
      // Parse as a classic script without executing it: static imports, exports
      // and import.meta are syntax errors. Rollup also must inline dynamic imports.
      assert.doesNotThrow(() => new Script(code, { filename: script }));
      assert.doesNotMatch(code, /\bimport\s*\(/u);
      assert.doesNotMatch(code, /process\.env\.IN_TEST/u);
      assert.doesNotMatch(code, /document\.baseURI/u, `${script} must not read document in a worker or content script`);
    }
    for (const [source, destination] of [
      ['src/nodus/send.wasm', 'wasm/send.wasm'],
      ['src/nodus/mldsa87.wasm', 'wasm/mldsa87.wasm'],
      ['src/cpunk/legacy-dilithium.wasm', 'wasm/legacy-dilithium.wasm'],
      ['src/pq/receive-keygen.wasm', 'wasm/receive-keygen.wasm'],
      ['public/assets/nodus-mark.svg', 'assets/nodus-mark.svg'],
      ['public/assets/fonts/inter-latin.woff2', 'assets/fonts/inter-latin.woff2'],
      ['public/assets/fonts/inter-latin-ext.woff2', 'assets/fonts/inter-latin-ext.woff2'],
      ['public/assets/fonts/OFL.txt', 'assets/fonts/OFL.txt'],
    ]) assert.deepEqual(await readFile(join(extension, destination)), await readFile(join(walletRoot, source)), destination);
    for (const page of ['popup.html', 'notification.html', 'home.html']) assert.ok(files.includes(page), page);
    const licenses = await readFile(join(extension, 'THIRD-PARTY-LICENSES.txt'), 'utf8');
    for (const name of ['@metamask/providers@', 'extension-port-stream@', 'ethers@', 'readable-stream@']) assert.ok(licenses.includes(name), name);

    const blocked = [];
    // The proxy has no Playwright initiator metadata; reject browser traffic here,
    // and count only requests attributed to the smoke flow in the route below.
    server = createServer((request, response) => {
      if (request.url === '/' || request.url === '/favicon.ico') {
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        response.end(`<!doctype html><html><head><title>Local wallet discovery</title></head><body>
          <script>
            window.announcements = []; window.providers = {};
            addEventListener('eip6963:announceProvider', event => {
              window.announcements.push({ ...event.detail.info, request: typeof event.detail.provider.request });
              window.providers[event.detail.info.rdns] = event.detail.provider;
            });
            dispatchEvent(new Event('eip6963:requestProvider'));
          </script></body></html>`);
      } else {
        response.writeHead(403); response.end();
      }
    });
    server.on('connect', (_request, socket) => { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const origin = `http://127.0.0.1:${server.address().port}`;
    const { chromium } = await import('playwright');
    context = await chromium.launchPersistentContext(join(temporary, 'profile'), {
      executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
      channel: 'chromium', headless: true,
      ignoreDefaultArgs: ['--disable-extensions'],
      args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`,
        `--proxy-server=${origin}`, '--proxy-bypass-list=127.0.0.1', '--disable-background-networking'],
    });
    context.setDefaultTimeout(10_000); context.setDefaultNavigationTimeout(15_000);
    const smokePages = new Set();
    const isWorker = worker => worker.url().startsWith('chrome-extension://') && worker.url().endsWith(`/${manifest.background.service_worker}`);
    // Playwright 1.58.2, node_modules/playwright-core/types/types.d.ts:
    // Request.serviceWorker():20538-20547, Request.frame():20389-20418 (can throw
    // for workers/early navigation), Frame.page():7330-7333.
    const isSmokeRequest = request => {
      const serviceWorker = request.serviceWorker();
      if (serviceWorker) return isWorker(serviceWorker);
      let frame;
      try { frame = request.frame(); }
      catch { return false; }
      return smokePages.has(frame.page()) || frame.url().startsWith('chrome-extension://') ||
        frame.page().url().startsWith('chrome-extension://');
    };
    await context.route('**/*', route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.protocol === 'chrome-extension:' || url.origin === origin) return route.continue();
      if (isSmokeRequest(request)) blocked.push(url.href);
      return route.abort('blockedbyclient');
    });
    const worker = context.serviceWorkers().find(isWorker) || await context.waitForEvent('serviceworker', { predicate: isWorker, timeout: 15_000 });
    const extensionUrl = `chrome-extension://${new URL(worker.url()).hostname}`;
    const timestamp = await worker.evaluate(async () => (await chrome.storage.session.get('timestamp')).timestamp);
    assert.ok(Number.isFinite(Date.parse(timestamp)), 'Service worker body executed');

    const errors = [];
    const popup = await context.newPage();
    smokePages.add(popup);
    popup.on('pageerror', error => errors.push(error.message));
    await popup.goto(`${extensionUrl}/${manifest.action.default_popup}`);
    await popup.locator('#welcome:visible').waitFor();
    assert.equal(await popup.getByRole('heading', { name: 'Your wallet', exact: true }).count(), 0);
    assert.equal(await popup.locator('#create').isVisible(), true);
    assert.equal(await popup.locator('#restore').isVisible(), true);
    assert.equal(await popup.locator('#wallet-status').textContent(), '');
    // Proves packaged Inter actually loads on an extension page; a plain-page
    // family check could falsely pass through inheritance. A stale zip can
    // still falsely pass, so rebuild first as required by this test's header.
    const fontFamilies = await popup.evaluate(() => ({
      root: getComputedStyle(document.documentElement).fontFamily,
      body: getComputedStyle(document.body).fontFamily,
      rootSize: getComputedStyle(document.documentElement).fontSize,
      bodySize: getComputedStyle(document.body).fontSize,
    }));
    assert.equal(fontFamilies.body, fontFamilies.root, 'Extension body must use the web wallet font set on :root');
    assert.equal(fontFamilies.bodySize, fontFamilies.rootSize, 'Extension body must inherit the web wallet base font size');
    await popup.evaluate(() => document.fonts.ready);
    assert.equal(await popup.evaluate(() => document.fonts.check('14px Inter')), true);
    assert.equal(await popup.evaluate(() => [...document.fonts].some(font => font.family === 'Inter' && font.status === 'loaded')), true);
    assert.match(await popup.evaluate(() => getComputedStyle(document.body).fontFamily), /^Inter(?:,|$)/u);

    const page = await context.newPage();
    smokePages.add(page);
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(origin);
    assert.equal(await page.evaluate(() => new URL('file:///x.html').origin), 'file://', 'Chromium serializes file origins differently from Node');
    await page.waitForFunction(() => window.announcements.some(info => info.rdns === 'io.nodusnetwork.wallet'));
    const info = await page.evaluate(() => window.announcements.find(info => info.rdns === 'io.nodusnetwork.wallet'));
    assert.equal(info.name, 'Nodus Wallet');
    assert.equal(info.rdns, 'io.nodusnetwork.wallet');
    assert.equal(info.request, 'function');
    // networkClient in background/evm.js answers eth_chainId from local config.
    // This traverses both classic scripts and the worker without a chain call;
    // announcement alone could pass with a broken isolated-world bridge.
    await page.evaluate(() => {
      window.providers['io.nodusnetwork.wallet'].request({ method: 'eth_chainId' })
        .then(value => { window.localChainId = value; }, error => { window.bridgeError = error.message; });
    });
    await page.waitForFunction(() => window.localChainId !== undefined || window.bridgeError !== undefined);
    assert.equal(await page.evaluate(() => window.bridgeError), undefined);
    assert.equal(await page.evaluate(() => window.localChainId), '0x1');
    assert.deepEqual(errors, [], 'Packaged pages must have no uncaught script errors');
    assert.deepEqual(blocked, [], 'Smoke flow must request no external resources or real chains');

    const outside = 'https://package-smoke.invalid/popup-request-filter';
    const [failedRequest, fetched] = await Promise.all([
      popup.waitForEvent('requestfailed', { predicate: request => request.url() === outside }),
      popup.evaluate(url => fetch(url).then(() => true, () => false), outside),
    ]);
    assert.equal(fetched, false, 'Negative-control popup fetch must be blocked');
    assert.equal(failedRequest.frame().page(), popup, 'Negative control must originate in the popup');
    assert.deepEqual(blocked, [outside], 'The request filter must record the outside popup fetch');
  } finally {
    try { await context?.close(); }
    finally {
      try {
        if (server?.listening) await new Promise((resolve, reject) => {
          server.close(error => error ? reject(error) : resolve()); server.closeAllConnections();
        });
      } finally { await rm(temporary, { recursive: true, force: true }); }
    }
  }
});
