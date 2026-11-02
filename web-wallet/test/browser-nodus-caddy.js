// The wasm Nodus module in Chromium, over wss through Caddy, to a localhost
// node (approved 4001 plan 4.3; design 2026-10-28-encrypted-sessions §6 "the
// wasm wallet through Caddy to a localhost node").
//
// What it proves: the SHIPPED module (src/nodus/send.js + send.wasm) opens the
// 4001 secret connection over a wss WebSocket terminated by Caddy and reads
// the balance through it (a read), and reaches the same node a second time
// with a NEW connection that the module notices (session generation);
// a wrong pin never gets READY. The page context accepts Caddy's self-signed
// certificate through Playwright's ignoreHTTPSErrors.
//
// What it does NOT prove (stated, not assumed):
//   - Whether the extension's service-worker WebSocket honours
//     ignoreHTTPSErrors is NOT established; this test runs the module in a
//     page context only. The extension service worker and Connect (same
//     module) are not driven here; that stays an open item for the operator.
//   - The send runs only with NODUS_TEST_SEND_PHRASE (a phrase funded on that
//     chain) and NODUS_TEST_SEND_TO (128 hex): without them it is reported
//     "send NOT RUN" and the exit code is 2. Connect's read (the Messages core,
//     nc_unlock + nc_profile_get, in the same module and session as the
//     wallet's balance read) always runs.
//   - Caddy 2.11.2 (the live nodes' version): the local binary is 2.6.2
//     (`caddy version`); the difference is reported with a result.
//
// Requires: a built module (src/nodus/send.js, send.wasm), Chromium
// (Playwright), `caddy` on PATH, and a RUNNING localhost node on a version-3
// chain with its WebSocket entry on 127.0.0.1:NODUS_TEST_WS_PORT (for example
// a harness node, nodus.json "ws_port"). Environment (all required):
//   NODUS_TEST_WS_PORT   the node's ws_port
//   NODUS_TEST_NODE_FP   the node's identity/nodus.fp (128 hex), or
//   NODUS_TEST_NODE_FP_FILE   the file holding it
//   NODUS_TEST_CHAIN_ID  the chain id (64 hex), or NODUS_TEST_CHAIN_ID_FILE
// Optional: CADDY_TEST_PORT (default 4443), TEST_PAGE_PORT (default 4192),
// CHROMIUM_PATH. Exit 0 = passed, 1 = failed, 2 = NOT RUN (a missing
// prerequisite is missing coverage, never a pass).
// Leaves nothing behind: Caddy and the page server are killed; temp dirs
// removed. Fixed local ports 4443 / 4192 (a busy port fails, never reused).
// False passes: the balance is only read from the node, so a node that is not
// on a v3 chain fails connect (no chain id -> no session) rather than passing.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, extname, normalize, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

const need = name => process.env[name] || null;
const fromFile = (v, f) => v || (need(f) && readFileSync(need(f), 'utf8').trim());
const wsPort = need('NODUS_TEST_WS_PORT');
const nodeFp = fromFile(need('NODUS_TEST_NODE_FP'), 'NODUS_TEST_NODE_FP_FILE');
const chainId = fromFile(need('NODUS_TEST_CHAIN_ID'), 'NODUS_TEST_CHAIN_ID_FILE');
if (!wsPort || !/^[0-9a-f]{128}$/.test(nodeFp || '') || !/^[0-9a-f]{64}$/.test(chainId || '')) {
  console.log('NOT RUN: set NODUS_TEST_WS_PORT, NODUS_TEST_NODE_FP[_FILE] (128 hex) and NODUS_TEST_CHAIN_ID[_FILE] (64 hex) for a running localhost node on a version-3 chain.');
  process.exit(2);
}
const caddyPort = Number(process.env.CADDY_TEST_PORT || 4443);
const pagePort = Number(process.env.TEST_PAGE_PORT || 4192);
const here = new URL('.', import.meta.url).pathname;
const srcRoot = resolve(here, '../src');
for (const f of ['nodus/send.js', 'nodus/send.wasm', 'nodus/send-module.js']) {
  if (!existsSync(join(srcRoot, f))) { console.log(`NOT RUN: ${f} is missing (build the module: scripts/build-nodus-send-wasm.sh).`); process.exit(2); }
}

const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm', '.html': 'text/html' };
const page = `<!doctype html><meta charset=utf-8><body><script type=module>
import { createNodusSendModule } from '/nodus/send-module.js';
window.runModule = async (network, seedHex) => {
  const seed = Uint8Array.from(seedHex.match(/../g), h => parseInt(h, 16));
  const mod = await createNodusSendModule(network, { startIndex: 0 });
  await mod.identify({ seed });
  await mod.connectNetwork();
  return await mod.balance();
};
// A send through the same session: list the coins, build and sign one native
// transfer, submit it. Resolves { accepted, intentId, wireId, message }.
window.runSend = async (network, seedHex, to, amount) => {
  const seed = Uint8Array.from(seedHex.match(/../g), h => parseInt(h, 16));
  const mod = await createNodusSendModule(network, { startIndex: 0 });
  await mod.identify({ seed });
  await mod.connectNetwork();
  const listed = await mod.list();
  if (!listed.coins.length) throw new Error('the funded identity has no native coin');
  const built = await mod.buildAndSign({ to, tokenId: '0'.repeat(128), amount,
    expiryHeight: String(BigInt(listed.tip) + 50n), coins: listed.coins.slice(0, 8) });
  const res = await mod.submit({ envelope: built.envelope });
  return { accepted: res.accepted, message: res.message || '', intentId: built.intentId, wireId: built.wireId };
};
// Connect's read through the SAME session as the wallet's balance read: the
// Messages core (nc_* exports of the one module) unlocks with the phrase and
// reads a profile record from the node. Resolves { balance, profile }.
window.runConnectRead = async (network, seedHex, wordsText, fp) => {
  const seed = Uint8Array.from(seedHex.match(/../g), h => parseInt(h, 16));
  const mod = await createNodusSendModule(network, { startIndex: 0 });
  await mod.identify({ seed });
  await mod.connectNetwork();
  const balance = await mod.balance();
  const words = new TextEncoder().encode(wordsText);
  const profile = await mod.connect(async api => {
    const at = api.num('nc_words_alloc', ['number'], [words.length]);
    if (!at) throw new Error('out of memory');
    api.heap().set(words, at);
    if (await api.call('nc_unlock', ['number'], [1]) !== 0) throw new Error(api.str('nc_error') || 'nc_unlock failed');
    if (await api.call('nc_profile_get', ['string'], [fp]) !== 0) throw new Error(api.str('nc_error') || 'nc_profile_get failed');
    return JSON.parse(api.str('nc_result'));
  });
  mod.lock();
  return { balance, profile };
};
window.ready = true;
</script>`;

const staticServer = createServer((req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (path === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(page); return; }
  const file = normalize(join(srcRoot, path));
  if (!file.startsWith(srcRoot) || !existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
  res.end(readFileSync(file));
});

const work = mkdtempSync(join(tmpdir(), 'nodus-caddy-'));
let caddy = null, browser = null, failed = false, skipped = false;
try {
  await new Promise((ok, no) => { staticServer.once('error', no); staticServer.listen(pagePort, '127.0.0.1', ok); });
  caddy = spawn('caddy', ['run', '--config', join(here, 'nodus-caddy.Caddyfile'), '--adapter', 'caddyfile'], {
    env: { ...process.env, CADDY_TEST_PORT: String(caddyPort), CADDY_TEST_WS_PORT: String(wsPort),
           XDG_DATA_HOME: join(work, 'data'), XDG_CONFIG_HOME: join(work, 'config') },
    stdio: 'pipe' });
  let caddyOut = '';
  caddy.stderr.on('data', d => { caddyOut += d; });
  caddy.on('exit', code => { if (code) caddyOut += `\n[caddy exited ${code}]`; });
  const ver = spawn('caddy', ['version']); let verOut = ''; ver.stdout.on('data', d => { verOut += d; });
  await delay(2500);   // Caddy readiness: the test page load below fails closed if it is not up
  console.log(`Caddy: ${verOut.trim() || 'unknown'} (live nodes run 2.11.2)`);

  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const tab = await context.newPage();
  tab.setDefaultTimeout(60000);
  await tab.goto(`http://127.0.0.1:${pagePort}/`);
  await tab.waitForFunction(() => window.ready === true);

  const network = pin => ({ chainId, scheme: 'wss', endpoints: [{ host: '127.0.0.1', port: caddyPort }], pins: [pin] });
  const seed = '5a'.repeat(32);   // a public test seed

  // 1. A read through Caddy (the secret connection over wss).
  const bal = await tab.evaluate(({ n, s }) => window.runModule(n, s), { n: network(nodeFp), s: seed });
  assert.ok(typeof bal.total === 'string' && /^[0-9]+$/.test(bal.total), 'balance total is a decimal string');
  console.log(`read through Caddy: total ${bal.total} spendable ${bal.spendable}`);

  // 2. A second, fresh module to the same node: a new connection reads again.
  const bal2 = await tab.evaluate(({ n, s }) => window.runModule(n, s), { n: network(nodeFp), s: seed });
  assert.equal(bal2.total, bal.total);

  // 3. A wrong pin never reaches READY: the module refuses before it can read.
  const other = nodeFp.replace(/^./, c => (c === 'a' ? 'b' : 'a'));
  const refused = await tab.evaluate(({ n, s }) => window.runModule(n, s).then(() => 'connected', e => String(e.message || e)),
                                     { n: network(other), s: seed });
  assert.notEqual(refused, 'connected', 'a pin that is not the node\'s key must be refused');
  console.log(`wrong pin refused: ${refused}`);

  // 4. Connect's read through the same session (the phrase here is a public test
  //    phrase unless NODUS_TEST_PHRASE is given; any valid 24-word phrase reads).
  const phrase = process.env.NODUS_TEST_PHRASE || `${'abandon '.repeat(23)}art`;
  const { nodusSigningSeed } = await import('../src/nodus/derive.js');
  const phraseSeed = Buffer.from(nodusSigningSeed(phrase)).toString('hex');
  const ownFp = process.env.NODUS_TEST_CONNECT_FP || nodeFp;   // any fingerprint the node can answer for
  const cr = await tab.evaluate(({ n, s, w, f }) => window.runConnectRead(n, s, w, f),
                                { n: network(nodeFp), s: phraseSeed, w: phrase, f: ownFp });
  assert.ok(cr.balance && typeof cr.balance.total === 'string', 'wallet balance read on the Connect session');
  assert.ok(cr.profile && typeof cr.profile === 'object', 'Connect profile read returned a result');
  console.log(`Connect read through the same session: balance ${cr.balance.total}, profile ${JSON.stringify(cr.profile).slice(0, 120)}`);

  // 5. A send (needs a funded identity: NODUS_TEST_SEND_PHRASE, NODUS_TEST_SEND_TO 128 hex).
  const sendPhrase = process.env.NODUS_TEST_SEND_PHRASE, sendTo = process.env.NODUS_TEST_SEND_TO;
  if (sendPhrase && /^[0-9a-f]{128}$/.test(sendTo || '')) {
    const sendSeed = Buffer.from(nodusSigningSeed(sendPhrase)).toString('hex');
    const sent = await tab.evaluate(({ n, s, t, a }) => window.runSend(n, s, t, a),
                                    { n: network(nodeFp), s: sendSeed, t: sendTo, a: process.env.NODUS_TEST_SEND_AMOUNT || '1' });
    assert.equal(sent.accepted, true, `the node did not accept the send: ${sent.message}`);
    console.log(`send accepted through Caddy: intent ${sent.intentId.slice(0, 16)}...`);
  } else {
    console.log('send NOT RUN: set NODUS_TEST_SEND_PHRASE (a phrase funded on this chain) and NODUS_TEST_SEND_TO (128 hex).');
    skipped = true;
  }
  console.log(`${skipped ? 'PARTIAL' : 'PASS'} browser-nodus-caddy (page context only; extension service worker not established)`);
} catch (error) {
  failed = true;
  console.error('FAIL browser-nodus-caddy:', error && error.stack || error);
} finally {
  if (browser) await browser.close().catch(() => {});
  if (caddy) caddy.kill('SIGKILL');
  staticServer.close();
  rmSync(work, { recursive: true, force: true });
}
process.exit(failed ? 1 : skipped ? 2 : 0);   // a part that did not run is missing coverage, never a pass
