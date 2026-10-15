// Nodus Connect "Nodus" page (src/nodus-roles.js, HF-6 screens; design
// docs/plans/2026-10-12-connect-hf6-screens-design.md rev 1) in a real
// browser, WITHOUT a network. Run: npm run test:roles
// (node test/browser-nodus-roles.js; CHROMIUM_PATH = a Chromium binary if
// Playwright's own is not installed).
//
// What it proves:
// - the page shows its three rows (Become a witness, Become a storage node,
//   My registered nodes — operator 2026-10-15), with the bonds the NODE reports (hf6Bonds — values
//   other than the compiled defaults here; BUGS W-20) — no
//   "Change your node's key" (the khan removed key ROTATE from HF-6,
//   decision 2026-10-13-kurultay-18-summary.md item 1);
// - at rule-set generation 3 the amber note shows and Review stays disabled
//   even for a consent that passes every check — the checks still run;
// - a consent that fails a check shows that line with ✗ and its reason, and
//   Review stays disabled; a passing consent enables Review at generation 4;
// - a consent that expires before the transaction's validity fails its
//   line (no Review); while the witness list is partial the node-key line
//   says it could not be checked (no Review); when the bonds cannot be read
//   the page says they are unknown (no Review) — BUGS W-20 / W-21;
// - the Review shows the node key fingerprint the module read back from the
//   signed bytes; Confirm records the transaction (the host
//   recorder's broadcast runs BEFORE the submission) and says it is tracked;
// - "Become a storage node" is the consent flow only: no storage list;
// - "My registered nodes" shows both cards — "Your witnesses" and "Your
//   storage nodes" — on one screen; while one card's Review is open the
//   other card is not shown; after a submission the screen shows both again;
// - "Your storage nodes" lists this wallet's nodes, with Leave on an active
//   one only, and Leave opens a Review that says what leaving means; Confirm
//   records "Leaving storage";
// - "Your witnesses" lists this wallet's generation-4 witnesses, with "Stop
//   being a witness" on an active or eligible one only (not on a leaving
//   one, never on another wallet's); at generation 3 the amber note shows
//   and the buttons are disabled; at generation 4 the button opens a Review
//   that says the witness leaves at an epoch boundary (no date), the bond
//   comes back locked for the unbond block count after it leaves, the
//   delegations are returned, that it cannot be undone, and how a witness
//   moves to a new key now (stop it, become a witness again from the new
//   node) — no node key block, no bond line; Confirm records "Leaving the
//   witnesses";
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
// "No storage list on Become a storage node" is checked after the screen's
// check lines have rendered (the storage list would have been read and drawn
// right after the facts); test/nodus-roles.test.js SCREEN_LISTS pins that the
// screen does not ask for the list at all.
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
    // bondsFail: hf6Bonds rejects; truncated: the witness list is partial
    window.__t = { OWN, NODE, generation: '3', tip: '1000', events: [], bondsFail: false, truncated: false };
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
      hf6Rules: { consentWindow: '720', generation: 4, minTenureBlocks: '1440', storageExitLockEpochs: '12', validatorUnbondEpochs: '84' },
      // the node's role bonds (chain params 19 / 21): 1,500,000 and 500,000
      // NODUS — not the compiled 2,000,000 / 1,000,000
      hf6Bonds: async () => { if (window.__t.bondsFail) throw new Error('The network\'s bond amounts could not be read (rc=-1).'); return { stakeMin: '150000000000000', storageBond: '50000000000000' }; },
      stakingRules: { minDelegation: '10000000000', selfStake: '1000000000000000', commissionMaxBps: '5000', undelegateLockEpochs: '1', epochLength: '720', maxDelegators: '2048' },
      consentCheck,
      rulesetInfo: async () => ({ tip: window.__t.tip, generation: window.__t.generation, gen2Height: '0' }),
      balance: async () => ({ total: coin.amount, spendable: coin.amount }),
      list: async () => ({ tip: window.__t.tip, coins: [coin], truncated: false }),
      validators: async () => ({ truncated: window.__t.truncated, validators: [
        // witness 51 runs on the machine that is also this wallet's active
        // storage node 61 (its key fingerprint = the storage node's fp)
        witness('61'.repeat(64), '51'.repeat(64), OWN), witness('42'.repeat(64), '52'.repeat(64), OWN, 4),
        witness('43'.repeat(64), '53'.repeat(64), OTHER), witness('44'.repeat(64), '', ''),
        witness('45'.repeat(64), '55'.repeat(64), OWN, 1)   // this wallet's, already leaving
      ] }),
      storageByOwner: async () => ({ tip: window.__t.tip, total: '2', epochStart: '720', set: true, setCount: 3, nodes: [node('61'.repeat(64), 1), node('62'.repeat(64), 3)] }),
      hf6Build: async args => {
        window.__t.events.push(`build:${args.op}`);
        const fee = 1000000n, bond = BigInt(args.amount);
        const check = args.op === 'storageExit' || args.op === 'unstake' ? null : consentCheck({ text: args.consent });
        return {
          envelope: new Uint8Array([1, 2, 3]), intentId: 'cd'.repeat(64), wireId: 'ef'.repeat(64),
          decoded: { op: args.op, owner: OWN, nodeFp: args.op === 'storageExit' ? args.nodeFp : args.op === 'unstake' ? '' : NODE, validatorId: args.op === 'unstake' ? args.validatorId : '', bond: args.amount, commissionBps: args.commissionBps, consentExpiry: check ? check.expiry : '', fee: String(fee), change: String(BigInt(coin.amount) - bond - fee), expiryHeight: args.expiryHeight, chainId: CHAIN, inputs: [coin.nullifier] }
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
  assert.deepEqual(await root.locator('.roles-row strong').allInnerTexts(), ['Become a witness', 'Become a storage node', 'My registered nodes']);
  assert.equal(await root.locator('[data-role="nodes"] small').innerText(), 'See the witness and storage nodes this wallet owns; stop a witness or leave storage and get the bond back. Fee only.');
  assert.equal(await root.locator('[data-role="witnesses"]').count(), 0, 'no separate "Your witnesses" row');
  assert.equal(await root.locator('[data-role="rotate"]').count(), 0, 'no key change row');
  await page.waitForFunction(() => /NODUS/.test(document.querySelector('[data-role="storage"]')?.innerText || ''));
  assert.match(await root.locator('[data-role="witness"]').innerText(), /1,500,000\.0 NODUS/, 'the node\'s stake minimum');
  assert.match(await root.locator('[data-role="storage"]').innerText(), /500,000\.0 NODUS/, 'the node\'s storage bond');
  await root.locator('.roles-amber').waitFor();
  assert.match(await root.locator('.roles-amber').innerText(), /cannot send/);
  await noSideways('the page');

  // Become a witness at generation 3: the command, the checks run, Review disabled.
  await root.locator('[data-role="witness"]').click();
  await root.locator('.roles-cmd').waitFor();
  const command = await root.locator('.roles-cmd').innerText();
  assert.equal(command, `sudo nodus-cli consent nodus-consent-v1:witness:${'1a'.repeat(64)}:1710:${'77'.repeat(32)}`);
  assert.equal(await root.locator('input[data-field="bond"]').inputValue(), '1500000.0', 'the bond starts at the node\'s minimum');
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nop 1\nexpiry 1700\n');
  await root.locator('.roles-checks li[data-check="key"][data-ok="true"]').waitFor();
  assert.equal(await root.locator('.roles-checks li[data-ok="false"]').count(), 0, 'every line passed (the module\'s seven, the margin, the node key)');
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

  // A consent that passes the module's lines but expires before the
  // transaction's validity (tip 1000 + 90 = 1090 > 1050): its margin line
  // fails with the plain reason and Review stays disabled (BUGS W-21).
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1050\n');
  const margin = root.locator('.roles-checks li[data-check="margin"]');
  await margin.waitFor();
  assert.equal(await margin.getAttribute('data-ok'), 'false');
  assert.match(await margin.innerText(), /This consent expires before this transaction could be included; make a new consent on the node\./);
  assert.ok(await root.locator('[data-action="review"]').isDisabled(), 'Review is disabled for a consent that ends too early');
  // A passing paste: Review shows the node fp; no expiry warning exists any more.
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1700\n');
  await page.waitForFunction(() => document.querySelectorAll('.roles-checks li[data-ok="false"]').length === 0 && !!document.querySelector('.roles-checks li[data-check="key"][data-ok="true"]'));
  assert.ok(!(await root.locator('[data-action="review"]').isDisabled()), 'Review is enabled for a passing consent at generation 4');
  await root.locator('[data-action="review"]').click();
  await root.locator('.roles-review').waitFor();
  assert.equal(await root.locator('.roles-fp-value').innerText(), '3c'.repeat(64));
  assert.match(await root.locator('.roles-fp-note').innerText(), /matches the fingerprint your node printed/);
  assert.equal(await root.locator('[data-warning="consent-expiry"]').count(), 0);
  assert.match(await root.locator('.roles-review').innerText(), /Lock 1,500,000\.0 NODUS/, 'the bond built is the node\'s minimum');
  assert.match(await root.locator('.roles-review').innerText(), /Rewards go to this wallet/);
  assert.match(await root.locator('.roles-review').innerText(), /at or after block 2,441/);
  await noSideways('witness review');
  await root.locator('[data-action="confirm"]').click();
  await root.locator('.roles-status').waitFor();
  assert.match(await root.locator('.roles-status').innerText(), /tracked in Activity/);
  const events = await page.evaluate(() => window.__t.events);
  assert.ok(events.indexOf(`record:Witness bond:${'cd'.repeat(64)}`) >= 0 && events.indexOf(`record:Witness bond:${'cd'.repeat(64)}`) < events.indexOf('submit'), `recorded before the submission: ${events}`);
  assert.ok(events.includes('settled:true'));

  // Become a storage node: the consent flow only — no storage list.
  await root.locator('.roles-back').click();          // "← Nodus" always goes home (goto('home'))
  await root.locator('[data-role="storage"]').click();
  await root.locator('.roles-cmd').waitFor();
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1700\n');
  await root.locator('.roles-checks li[data-check="margin"][data-ok="true"]').waitFor();
  assert.equal(await root.locator('.roles-node').count(), 0, 'no storage list on Become a storage node');
  assert.doesNotMatch(await root.innerText(), /Your storage nodes/);
  assert.equal(await root.locator('[data-action="leave"]').count(), 0);

  // My registered nodes: both cards on one screen. Your storage nodes:
  // Leave on the active one only; its Review; Confirm records it and the
  // screen shows both cards again.
  await page.evaluate(() => { window.__t.events = []; });
  await root.locator('.roles-back').click();
  await root.locator('[data-role="nodes"]').click();
  await root.locator('.roles-node[data-node]').first().waitFor();
  await root.locator('.roles-node[data-witness]').first().waitFor();
  assert.deepEqual(await root.locator('.roles-step').allTextContents(), ['Your witnesses', 'Your storage nodes']);
  assert.equal(await root.locator('.roles-node[data-witness]').count(), 3, 'this wallet\'s three witnesses');
  assert.equal(await root.locator('.roles-node[data-node]').count(), 2, 'this wallet\'s two storage nodes');
  assert.equal(await root.locator(`.roles-node[data-node="${'61'.repeat(64)}"] [data-action="leave"]`).count(), 1);
  assert.equal(await root.locator(`.roles-node[data-node="${'62'.repeat(64)}"] [data-action="leave"]`).count(), 0);
  await page.waitForFunction(() => { const b = document.querySelector('[data-action="leave"]'); return !!b && !b.disabled; });
  await noSideways('my registered nodes');
  await root.locator('[data-action="leave"]').click();
  await root.locator('.roles-review').waitFor();
  const leave = await root.locator('.roles-review').innerText();
  assert.match(leave, /no longer paid/);
  assert.match(leave, /The 1,000,000\.0 NODUS bond comes back/, 'the node\'s own registered bond, from the storage list on this screen');
  assert.match(leave, /locked until block 10,080/);
  assert.match(leave, /two epoch boundaries/);
  assert.match(leave, /Turning the node off is not leaving/);
  assert.equal(await root.locator('.roles-node[data-witness]').count(), 0, 'the witnesses card is not shown while the Leave Review is open');
  assert.equal(await root.locator('[data-action="unstake"]').count(), 0);
  await noSideways('leave review');
  await root.locator('[data-action="confirm"]').click();
  await root.locator('.roles-status').waitFor();
  assert.match(await root.locator('.roles-status').innerText(), /Leaving storage submitted/);
  const leaveEvents = await page.evaluate(() => window.__t.events);
  assert.ok(leaveEvents.includes('build:storageExit'), `${leaveEvents}`);
  assert.ok(leaveEvents.indexOf(`record:Leaving storage:${'cd'.repeat(64)}`) >= 0 && leaveEvents.indexOf(`record:Leaving storage:${'cd'.repeat(64)}`) < leaveEvents.indexOf('submit'), `recorded before the submission: ${leaveEvents}`);
  await root.locator('.roles-node[data-node]').first().waitFor();
  await root.locator('.roles-node[data-witness]').first().waitFor();
  assert.equal(await root.locator('.roles-review').count(), 0);
  assert.deepEqual(await root.locator('.roles-step').allTextContents(), ['Your witnesses', 'Your storage nodes'], 'still on My registered nodes after the submission');

  // A partial witness list: the node-key line "could not be checked", no
  // Review (BUGS W-21).
  await page.evaluate(() => { window.__t.truncated = true; });
  await root.locator('.roles-back').click();
  await root.locator('[data-role="witness"]').click();
  await root.locator('.roles-cmd').waitFor();
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1700\n');
  await root.locator('input[data-field="commission"]').fill('10');
  await page.waitForFunction(() => /only part of the witnesses/.test(document.querySelector('.roles-checks li[data-check="key"]')?.innerText || ''));
  assert.equal(await root.locator('.roles-checks li[data-check="key"]').getAttribute('data-ok'), 'false');
  assert.match(await root.locator('.roles-checks li[data-check="key"]').innerText(), /could not be checked/);
  assert.ok(await root.locator('[data-action="review"]').isDisabled(), 'Review is disabled while the node key is unchecked');
  await page.evaluate(() => { window.__t.truncated = false; });

  // The bonds cannot be read: the page says the amounts are unknown, and
  // neither becoming a witness nor a storage node offers Review (BUGS W-20).
  await page.evaluate(() => { window.__t.bondsFail = true; });
  await root.locator('.roles-back').click();
  await root.locator('[data-note="bonds-unknown"]').waitFor();
  assert.match(await root.locator('[data-note="bonds-unknown"]').innerText(), /bond amounts are unknown/);
  assert.match(await root.locator('[data-role="witness"]').innerText(), /bond amounts are unknown/);
  assert.doesNotMatch(await root.locator('[data-role="storage"]').innerText(), /NODUS\./);
  await root.locator('[data-role="storage"]').click();
  await root.locator('[data-note="bonds-unknown"]').waitFor();
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1700\n');
  await root.locator('.roles-checks li[data-check="margin"][data-ok="true"]').waitFor();
  assert.ok(await root.locator('[data-action="review"]').isDisabled(), 'no storage Review without the node\'s bond');
  await root.locator('.roles-back').click();
  await root.locator('[data-role="witness"]').click();
  await root.locator('[data-note="bonds-unknown"]').waitFor();
  await root.locator('textarea.roles-paste').fill('nodus-valbind-consent v1\nexpiry 1700\n');
  await root.locator('input[data-field="bond"]').fill('2000000');
  await root.locator('input[data-field="commission"]').fill('10');
  await root.locator('.roles-checks li[data-check="key"][data-ok="true"]').waitFor();
  assert.ok(await root.locator('[data-action="review"]').isDisabled(), 'no witness Review without the node\'s minimum');
  await page.evaluate(() => { window.__t.bondsFail = false; });

  // My registered nodes at generation 3: this wallet's three witnesses
  // listed, "Stop being a witness" on the active and the eligible one only,
  // both disabled, Leave disabled too, the amber note shown.
  await page.evaluate(() => { window.__t.generation = '3'; });
  await root.locator('.roles-back').click();
  await root.locator('[data-role="nodes"]').click();
  await root.locator('.roles-node[data-witness]').first().waitFor();
  await root.locator('.roles-node[data-node]').first().waitFor();
  assert.ok(await root.locator('[data-action="leave"]').isDisabled(), 'Leave disabled before the HF-6 generation');
  await root.locator('.roles-amber').waitFor();
  assert.deepEqual(await root.locator('.roles-node[data-witness]').evaluateAll(nodes => nodes.map(n => n.dataset.witness)), ['51'.repeat(64), '52'.repeat(64), '55'.repeat(64)], 'only this wallet\'s witnesses');
  const stopOn = vid => root.locator(`.roles-node[data-witness="${vid}"] [data-action="unstake"]`);
  assert.equal(await stopOn('51'.repeat(64)).count(), 1, 'active: offered');
  assert.equal(await stopOn('52'.repeat(64)).count(), 1, 'waiting for a seat: offered');
  assert.equal(await stopOn('55'.repeat(64)).count(), 0, 'already leaving: not offered');
  assert.equal(await stopOn('53'.repeat(64)).count(), 0, 'another wallet\'s: not offered');
  assert.ok(await stopOn('51'.repeat(64)).isDisabled(), 'disabled before the HF-6 generation');
  assert.match(await root.locator('.roles-amber').first().innerText(), /cannot send/);
  await noSideways('your witnesses, generation 3');

  // At generation 4: the button opens the Review; Confirm records it.
  await page.evaluate(() => { window.__t.generation = '4'; window.__t.events = []; });
  await root.locator('.roles-back').click();
  await root.locator('[data-role="nodes"]').click();
  await page.waitForFunction(vid => { const b = document.querySelector(`.roles-node[data-witness="${vid}"] [data-action="unstake"]`); return !!b && !b.disabled; }, '51'.repeat(64));
  assert.equal(await root.locator('.roles-amber').count(), 0, 'no amber note at generation 4');
  await stopOn('51'.repeat(64)).click();
  await root.locator('.roles-review').waitFor();
  const stop = await root.locator('.roles-review').innerText();
  assert.match(stop, /Stop being a witness/);
  assert.ok(stop.includes(`Witness ${'51'.repeat(64)} leaves the witnesses at an epoch boundary`), stop);
  assert.match(stop, /usually after one or two boundaries/);
  assert.match(stop, /No date is promised/);
  assert.match(stop, /comes back to this wallet as one coin, locked for 60,480 blocks after the witness leaves/);
  assert.match(stop, /Delegations to this witness are returned to their delegators at the same boundary, each as a coin locked for 720 blocks/);
  assert.match(stop, /This cannot be undone/);
  assert.match(stop, /new bond and your node’s consent/);
  assert.ok(stop.includes('To move a witness to a new key, stop it here and become a witness again from the new node (a new witness ID; delegators delegate again).'), stop);
  assert.ok(!/\bdays?\b|\bhours?\b/.test(stop), 'block counts only, never hours or days');
  assert.equal(await root.locator('.roles-review .roles-fp').count(), 0, 'no node key block');
  assert.deepEqual(await root.locator('.roles-review .roles-kv dt').allInnerTexts(), ['Network fee', 'Change back to you', 'Balance after', 'Valid until block'], 'no bond, no consent line: fee and the signed change only');
  assert.equal(await root.locator('.roles-node[data-node]').count(), 0, 'the storage card is not shown while the Stop Review is open');
  assert.equal(await root.locator('[data-action="leave"]').count(), 0);
  await noSideways('stop being a witness review');
  await root.locator('[data-action="confirm"]').click();
  await root.locator('.roles-status').waitFor();
  assert.match(await root.locator('.roles-status').innerText(), /Leaving the witnesses submitted/);
  const stopEvents = await page.evaluate(() => window.__t.events);
  assert.ok(stopEvents.includes('build:unstake'), `${stopEvents}`);
  assert.ok(stopEvents.indexOf(`record:Leaving the witnesses:${'cd'.repeat(64)}`) >= 0 && stopEvents.indexOf(`record:Leaving the witnesses:${'cd'.repeat(64)}`) < stopEvents.indexOf('submit'), `recorded before the submission: ${stopEvents}`);
  await root.locator('.roles-node[data-witness]').first().waitFor();
  await root.locator('.roles-node[data-node]').first().waitFor();
  assert.deepEqual(await root.locator('.roles-step').allTextContents(), ['Your witnesses', 'Your storage nodes'], 'still on My registered nodes after the submission');

  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, []);
  console.log('Nodus roles test passed: three rows (no key change), the generation gate, failing and passing consent checks, the Review with the node key and the expiry warning, the record before the submission, no storage list on Become a storage node, My registered nodes with both cards: the storage list with Leave (Review, record, back on the screen), your witnesses with Stop being a witness (gate, offered rows, Review with the new-key line, record), no sideways scroll at 390 / 320 px.');
} finally {
  await browser?.close();
  server.stop();
}
