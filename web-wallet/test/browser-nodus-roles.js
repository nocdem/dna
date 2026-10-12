// Nodus Connect "Nodus" page (src/nodus-roles.js, HF-6 screens; design
// docs/plans/2026-10-12-connect-hf6-screens-design.md rev 1) in a real
// browser, WITHOUT a network. Run: npm run test:roles
// (node test/browser-nodus-roles.js; CHROMIUM_PATH = a Chromium binary if
// Playwright's own is not installed).
//
// What it proves:
// - the page shows its three rows (Become a witness, Become a storage node,
//   Change your node's key), with the bonds read from the module's hf6Rules;
// - at rule-set generation 3 the amber note shows and Review stays disabled
//   even for a consent that passes every check — the checks still run;
// - a consent that fails a check shows that line with ✗ and its reason, and
//   Review stays disabled; a passing consent enables Review at generation 4;
// - the Review shows the node key fingerprint the module read back from the
//   signed bytes and, when the consent expires before the transaction's
//   validity, the expiry warning; Confirm records the transaction (the host
//   recorder's broadcast runs BEFORE the submission) and says it is tracked;
// - "Change your node's key" lists only the generation-4 witnesses owned by
//   this wallet;
// - "Your storage nodes" lists this wallet's nodes, with Leave on an active
//   one only, and Leave opens a Review that says what leaving means;
// - nothing scrolls sideways at 390 px and 320 px on any of these screens.
// How it mounts: vite serves the real sources; a harness page holds the
// panel and root and imports src/nodus-roles.js and the real adapter; the
// wallet client is an in-memory fake in the shape src/nodus/client.js gives
// (state 'ready', hf6Rules, consentCheck, hf6Build, storageByOwner, …).
// Requires: nothing beyond `npm ci` and a Chromium. Leaves nothing behind (a
// fresh browser profile; nothing is written to storage).
// How it can lie: the client is a fake — the module's consent checks,
// signature verification and envelope bytes are NOT exercised (the fake
// answers the check lines from the pasted text); the harness is the panel
// alone, not the whole Connect page, so the sideways-scroll check covers
// this page's own content inside a plain body. All numbers are fixtures.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const PORT = 4187;
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'], PORT);
const url = server.url;
const harness = `${url}/__nodus-roles.html`;
const HTML = '<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/src/style.css"></head><body><main class="wallet-page" style="padding:12px"><section id="nodus-roles-panel" class="dashboard-panel roles-panel" hidden><h3 id="nodus-roles-title">Nodus</h3><div id="nodus-roles-root"></div></section></main></body></html>';
const errors = [], unexpected = [];
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const page = await browser.newPage({ viewport: { width: 390, height: 900 } });
  page.setDefaultTimeout(15000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
    const req = route.request();
    if (req.url() === harness) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: HTML });
    if (req.url().startsWith(`${url}/`) && req.method() === 'GET') return route.continue();
    unexpected.push(req.url());
    return route.abort();
  });
  await page.goto(harness);
  await page.evaluate(async () => {
    const roles = await import('/src/nodus-roles.js');
    const OWN = '1a'.repeat(64), OTHER = '2b'.repeat(64), NODE = '3c'.repeat(64), CHAIN = '77'.repeat(32);
    const coin = { nullifier: 'aa'.repeat(64), amount: '350000000000000' };
    window.__t = { OWN, NODE, generation: '3', tip: '1000', events: [] };
    const IDS = ['format', 'op', 'chain', 'owner', 'subject', 'expiry', 'signature'];
    // The fake module check: a text holding "owner other" fails the owner
    // line; "expiry N" sets the consent's expiry; anything else passes.
    const consentCheck = ({ text }) => {
      const expiry = (/expiry (\d+)/.exec(text) || [])[1] || '1700';
      const checks = IDS.map(id => ({ id, ok: !(id === 'owner' && /owner other/.test(text)), detail: id === 'owner' && /owner other/.test(text) ? 'This consent names another wallet as the owner. Run the command shown on this screen: it carries this wallet\'s address.' : `${id} passed` }));
      return { ok: checks.every(c => c.ok), checks, nodeFp: NODE, expiry };
    };
    const witness = (fp, vid, owner, status = 0) => ({ fingerprint: fp, selfStake: '200000000000000', delegated: '0', commissionBps: 500, status, delegators: 0, hasV2: !!owner, validatorId: owner ? vid : '', ownerFp: owner || '' });
    const node = (fp, status) => ({ fp, status, bond: '100000000000000', failStreak: 0, graceUntil: '0', registered: '900', exit: status === 3 ? '950' : '0', member: status === 1, segments: '0' });
    const client = {
      state: 'ready', identified: true, hf6able: true, stakeable: true, fingerprint: OWN, chainId: CHAIN,
      hf6Rules: { stakeMin: '200000000000000', storageBond: '100000000000000', consentWindow: '720', generation: 4, minTenureBlocks: '1440', storageExitLockEpochs: '12' },
      stakingRules: { minDelegation: '10000000000', selfStake: '1000000000000000', commissionMaxBps: '5000', undelegateLockEpochs: '1', epochLength: '720', maxDelegators: '2048' },
      consentCheck,
      rulesetInfo: async () => ({ tip: window.__t.tip, generation: window.__t.generation, gen2Height: '0' }),
      balance: async () => ({ total: coin.amount, spendable: coin.amount }),
      list: async () => ({ tip: window.__t.tip, coins: [coin], truncated: false }),
      validators: async () => ({ truncated: false, validators: [
        witness('41'.repeat(64), '51'.repeat(64), OWN), witness('42'.repeat(64), '52'.repeat(64), OWN, 4),
        witness('43'.repeat(64), '53'.repeat(64), OTHER), witness('44'.repeat(64), '', '')
      ] }),
      storageByOwner: async () => ({ tip: window.__t.tip, total: '2', epochStart: '720', set: true, setCount: 3, nodes: [node('61'.repeat(64), 1), node('62'.repeat(64), 3)] }),
      hf6Build: async args => {
        window.__t.events.push(`build:${args.op}`);
        const fee = 1000000n, bond = BigInt(args.amount);
        const check = args.op === 'storageExit' ? null : consentCheck({ text: args.consent });
        return {
          envelope: new Uint8Array([1, 2, 3]), intentId: 'cd'.repeat(64), wireId: 'ef'.repeat(64),
          decoded: { op: args.op, owner: OWN, nodeFp: args.op === 'storageExit' ? args.nodeFp : NODE, validatorId: args.op === 'rotate' ? args.validatorId : '', bond: args.amount, commissionBps: args.commissionBps, consentExpiry: check ? check.expiry : '', fee: String(fee), change: String(BigInt(coin.amount) - bond - fee), expiryHeight: args.expiryHeight, chainId: CHAIN, inputs: [coin.nullifier] }
        };
      },
      submit: async () => { window.__t.events.push('submit'); return { accepted: true }; }
    };
    roles.mountNodusRoles({ panelNode: document.getElementById('nodus-roles-panel'), rootNode: document.getElementById('nodus-roles-root') });
    roles.nodusRolesExtension.nodusReady({
      client, lockedInputs: () => new Set(),
      roleRecorder: (transfer, title) => ({
        broadcast: async details => { window.__t.events.push(`record:${title}:${details.hash}`); },
        settled: ok => { window.__t.events.push(`settled:${ok}`); }
      })
    });
  });
  const root = page.locator('#nodus-roles-root');
  const noSideways = async what => {
    for (const width of [390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      assert.ok(over <= 0, `${what}: scrolls sideways by ${over}px at ${width}px`);
    }
    await page.setViewportSize({ width: 390, height: 900 });
  };

  // The page and its three rows, the amber note at generation 3.
  await root.locator('.roles-row').first().waitFor();
  assert.deepEqual(await root.locator('.roles-row strong').allInnerTexts(), ['Become a witness', 'Become a storage node', 'Change your node’s key']);
  assert.match(await root.locator('[data-role="witness"]').innerText(), /2,000,000\.0 NODUS/);
  assert.match(await root.locator('[data-role="storage"]').innerText(), /1,000,000\.0 NODUS/);
  await root.locator('.roles-amber').waitFor();
  assert.match(await root.locator('.roles-amber').innerText(), /cannot send/);
  await noSideways('the page');

  // Become a witness at generation 3: the command, the checks run, Review disabled.
  await root.locator('[data-role="witness"]').click();
  await root.locator('.roles-cmd').waitFor();
  const command = await root.locator('.roles-cmd').innerText();
  assert.ok(command.includes(`validator consent --op stake --owner ${'1a'.repeat(64)} --expiry 1710`), command);
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nop 1\nexpiry 1700\n');
  await root.locator('.roles-checks li[data-check="signature"]').waitFor();
  assert.equal(await root.locator('.roles-checks li[data-ok="false"]').count(), 0, 'every module line passed');
  await root.locator('input[data-field="commission"]').fill('10');
  assert.ok(await root.locator('[data-action="review"]').isDisabled(), 'Review is disabled before the HF-6 generation');
  assert.match(await root.locator('.roles-amber').first().innerText(), /cannot send/);
  await noSideways('witness, generation 3');

  // A failing check line: shown with its reason, Review disabled.
  await page.evaluate(() => { window.__t.generation = '4'; });
  await root.locator('.roles-back').click();
  await root.locator('[data-role="witness"]').click();
  await root.locator('.roles-cmd').waitFor();
  assert.equal(await root.locator('.roles-amber').count(), 0, 'no amber note at generation 4');
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nowner other\n');
  const failed = root.locator('.roles-checks li[data-check="owner"]');
  await failed.waitFor();
  assert.equal(await failed.getAttribute('data-ok'), 'false');
  assert.match(await failed.innerText(), /another wallet/);
  await root.locator('input[data-field="commission"]').fill('10');
  assert.ok(await root.locator('[data-action="review"]').isDisabled(), 'Review is disabled for a failing consent');

  // A passing paste whose consent expires before the transaction's validity
  // (tip 1000 + 90 = 1090 > 1050): Review shows the node fp and the warning.
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1050\n');
  await page.waitForFunction(() => document.querySelectorAll('.roles-checks li[data-ok="false"]').length === 0);
  assert.ok(!(await root.locator('[data-action="review"]').isDisabled()), 'Review is enabled for a passing consent at generation 4');
  await root.locator('[data-action="review"]').click();
  await root.locator('.roles-review').waitFor();
  assert.equal(await root.locator('.roles-fp-value').innerText(), '3c'.repeat(64));
  assert.match(await root.locator('.roles-fp-note').innerText(), /matches the fingerprint your node printed/);
  const warning = root.locator('[data-warning="consent-expiry"]');
  assert.match(await warning.innerText(), /expires at block 1,050, before this transaction’s validity ends \(block 1,090\)/);
  assert.match(await root.locator('.roles-review').innerText(), /Rewards go to this wallet/);
  assert.match(await root.locator('.roles-review').innerText(), /at or after block 2,441/);
  await noSideways('witness review');
  await root.locator('[data-action="confirm"]').click();
  await root.locator('.roles-status').waitFor();
  assert.match(await root.locator('.roles-status').innerText(), /tracked in Activity/);
  const events = await page.evaluate(() => window.__t.events);
  assert.ok(events.indexOf(`record:Witness bond:${'cd'.repeat(64)}`) >= 0 && events.indexOf(`record:Witness bond:${'cd'.repeat(64)}`) < events.indexOf('submit'), `recorded before the submission: ${events}`);
  assert.ok(events.includes('settled:true'));

  // Change your node's key: only this wallet's generation-4 witnesses.
  await root.locator('.roles-back').click();
  await root.locator('[data-role="rotate"]').click();
  await root.locator('label.roles-radio').first().waitFor();
  assert.deepEqual(await root.locator('label.roles-radio').evaluateAll(nodes => nodes.map(n => n.dataset.witness)), ['51'.repeat(64), '52'.repeat(64)]);
  await root.locator('label.roles-radio').first().click();
  await root.locator('.roles-cmd').waitFor();
  assert.ok((await root.locator('.roles-cmd').innerText()).includes(`--op rotate --owner ${'1a'.repeat(64)} --subject ${'51'.repeat(64)}`));
  await noSideways('rotate');

  // Your storage nodes: Leave on the active one only; its Review.
  await root.locator('.roles-back').click();
  await root.locator('[data-role="storage"]').click();
  await root.locator('.roles-node').first().waitFor();
  assert.equal(await root.locator('.roles-node').count(), 2);
  assert.equal(await root.locator(`.roles-node[data-node="${'61'.repeat(64)}"] [data-action="leave"]`).count(), 1);
  assert.equal(await root.locator(`.roles-node[data-node="${'62'.repeat(64)}"] [data-action="leave"]`).count(), 0);
  await noSideways('storage');
  await root.locator('[data-action="leave"]').click();
  await root.locator('.roles-review').waitFor();
  const leave = await root.locator('.roles-review').innerText();
  assert.match(leave, /no longer paid/);
  assert.match(leave, /locked until block 10,080/);
  assert.match(leave, /two epoch boundaries/);
  assert.match(leave, /Turning the node off is not leaving/);
  await noSideways('leave review');

  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, []);
  console.log('Nodus roles test passed: three rows, the generation gate, failing and passing consent checks, the Review with the node key and the expiry warning, the record before the submission, the rotate list, the storage list with Leave, no sideways scroll at 390 / 320 px.');
} finally {
  await browser?.close();
  server.stop();
}
