// Shared vaults page (src/vaults/ui.js, 0.1.83 design): screenshots and a
// layout check, WITHOUT a network.
//
// How it mounts: `vite` (dev server, the wallet's vite.config.js, root
// web-wallet/) serves the real sources; the page itself is a fixed HTML
// answered by page.route (nothing written to disk) with the same parts the
// sites wrap the panel in (index.html / connect-site/index.html: .wallet-card
// > #page-vaults.wallet-page > #vault-panel with its page heading, the
// #chain selector on NODUS) and the sites' Content-Security-Policy, so an
// inline style would be refused here as it would be there. The panel is the
// REAL module, mounted with mountVaults() and started with
// vaultExtension.nodusReady({ client }); `client` and the Messages host are
// fakes answering fixed data in the shapes ui.js and core.js check
// (vaultOpen / vaultBalance / vaultCoins / vaultHistory / vaultReview /
// nameOf / nameLookup / vaultCreate). The Foundation preset is listed
// because the fake vaultOpen answers its documented address with this
// wallet as a member. Every request that is not a GET to the dev server is
// refused and reported.
//
// Run: npm run test:vaults (CHROMIUM_PATH = a Chromium binary if
// Playwright's own is not installed; SCREENSHOT_DIR = where the PNGs go —
// without it nothing is written). Shots, at 1280 and 390 px wide:
// vaults-list, vaults-vault (members, a request waiting 1 of 2 and one
// ready 2 of 2, the opened "Finished requests" section with a request the
// module refused, history), vaults-create (members checked, address shown).
// Asserted: the requests are read on Open with no Review pressed (0.1.85);
// the refused one (the fake throws NSW_MS_NOT_OWNED's text) sits in the
// collapsed Finished section with that text on its own card, pill "Not
// valid", only "Check again", and the top status line empty; one whose
// review cannot be done (the fake throws "The current Nodus block height
// is unknown (rc=-1).") stays among the OPEN requests, pill "Not checked",
// a neutral notice and only "Check again"; (0.1.86) "Send payment" on the
// ready one, refused by the fake network, puts the refusal on THAT card
// (.vault-note, data-kind "error") with the status line empty; after the
// fake's coins drop that request's coin, ONE background pass (driven by
// pollVaultNow(); the panel's own timer is held with holdVaultPoll(true) so
// no pass starts in the middle of a click) moves the card to Finished as
// "Coins spent" with no Approve / Send payment, and while that pass waits on
// its (held) coin read no panel button is disabled and the status line is
// empty; a create whose fake vaultCreate gives the family vault's address
// says "This vault is already in your list as “Family savings”." with
// "Open it" and no "Create vault", and the listed vault keeps its name
// (BUGS W-06); no horizontal
// scroll at 390 and 320 px on each of the three, no page error, no refused
// (CSP) load, no unexpected request.
//
// What it does NOT prove: that the 30-second timer itself starts and stops
// (held here; only the pass it runs is driven), the 5-second pass after new
// vault messages (the fake host never calls onChange) or the 15-second read
// after an accepted send (the fake refuses every send); the background
// pass dropping its answer when an action starts or the record changes
// mid-pass; Watch / a share card finding an already listed vault; the
// W-05 loading log lines (the fake's kept record always loads); anything about the
// module (send.wasm) or the
// node — every answer is the fake's; the page's behaviour is covered by
// test/vaults.test.js (core) and the Connect smoke test.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const PORT = 4198;
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'], PORT);
const url = server.url;
const harness = `${url}/__vaults-harness.html`;
const shots = process.env.SCREENSHOT_DIR || '';
if (shots) mkdirSync(shots, { recursive: true });

// The sites' policy (connect-site/index.html <meta http-equiv>).
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' https: wss:; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'";
const HTML = `<!doctype html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${CSP}"><title>Shared vaults (harness)</title><link rel="stylesheet" href="/src/style.css"></head>
<body>
<main class="wrap">
<div id="wallet-open" class="card wallet-card">
  <select id="chain" hidden><option value="nodus" selected>NODUS</option></select>
  <a id="nav-vaults" href="#vaults" hidden>Shared vaults</a>
  <div id="page-vaults" class="wallet-page" data-page="vaults"><button type="button" class="secondary small page-back"><span aria-hidden="true">←</span> Back to wallet</button>
  <section id="vault-panel" class="dashboard-panel vault-panel" aria-labelledby="vaults-title" hidden><header class="panel-heading page-heading"><span class="page-icon" aria-hidden="true"><svg class="app-icon" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="15" rx="2"/><circle cx="12" cy="11.5" r="3.5"/><path d="M12 8v1M12 14v1M7 19v2M17 19v2"/></svg></span><div class="page-heading-text"><h3 id="vaults-title" tabindex="-1">Shared vaults</h3><p class="page-subtitle">NODUS that can only be spent when enough of its members approve.</p></div><div class="page-heading-actions"><span class="page-chip">NODUS · Testnet</span></div></header><div id="vaults-root"></div></section></div>
</div>
</main>
</body>
</html>`;

const errors = [], refused = [], unexpected = [];
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.setDefaultTimeout(60000);
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to/i.test(message.text())) refused.push(message.text()); });
  await page.route('**/*', route => {
    const req = route.request();
    if (req.url() === harness) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: HTML });
    if (req.url().startsWith(`${url}/`) && req.method() === 'GET' && !req.postData()) return route.continue();
    unexpected.push({ url: req.url(), method: req.method() });
    return route.abort();
  });
  await page.goto(harness);

  // ── mount the real panel with a fake client and a fake Messages host ──
  await page.evaluate(async () => {
    const ui = await import('/src/vaults/ui.js');
    const { FOUNDATION_VAULT } = await import('/src/vaults/foundation.js');
    const core = await import('/src/vaults/core.js');
    const { parseAddrHistory } = await import('/src/nodus/history.js');
    const id = byte => byte.repeat(64);                  // 128 hex
    const OWN = id('1a'), ALICE = id('2b'), BOB = id('3c'), CAROL = id('4d'), DAVE = id('5e');
    const FAMILY = id('6f');
    const code = (m, keys) => `4e44532e4d5349472e7631${'00'.repeat(5)}${m.toString(16).padStart(2, '0')}${keys.length.toString(16).padStart(2, '0')}${keys.map(k => k.repeat(2592)).join('')}`;
    const familyInfo = { descriptor: code(2, ['a1', 'b2', 'c3']), address: FAMILY, m: 2, n: 3, members: [OWN, ALICE, BOB], isMember: true };
    const foundationInfo = { descriptor: FOUNDATION_VAULT.descriptor, address: FOUNDATION_VAULT.address, m: 2, n: 3, members: [ALICE, OWN, CAROL], isMember: true };
    const chainNames = new Map([[OWN, 'punk'], [ALICE, 'alice'], [CAROL, 'carol'], [DAVE, 'dave']]);
    const coin = (byte, amount, height) => ({ id: id(byte), amount, unlock: '0', height });
    const coins = {
      [FAMILY]: [coin('c1', '7500000000', '4300'), coin('c2', '5000000000', '5010')],
      [FOUNDATION_VAULT.address]: [coin('f1', '150000000000000', '1'), coin('f2', '25000000000000', '1')]
    };
    const balances = {
      [FAMILY]: { total: '12500000000', spendable: '12500000000' },
      [FOUNDATION_VAULT.address]: { total: '175000000000000', spendable: '175000000000000' }
    };
    const native = '0'.repeat(128);
    const history = address => parseAddrHistory({
      enabled: true, from_height: '4200',
      entries: address === FAMILY ? [
        { h: '5010', i: '0', q: '0', kind: 'spend_in', amount: '5000000000', token: native, fee: '0', peer: OWN, wire: id('e1'), ts: '1759900000' },
        { h: '4800', i: '1', q: '0', kind: 'spend_out', amount: '1200000000', token: native, fee: '1000000', peer: CAROL, wire: id('e2'), ts: '1759800000' },
        { h: '4300', i: '0', q: '0', kind: 'spend_in', amount: '8701000000', token: native, fee: '0', peer: ALICE, wire: id('e3'), ts: '1759700000' }
      ] : [
        { h: '4400', i: '0', q: '0', kind: 'spend_in', amount: '25000000000000', token: native, fee: '0', peer: DAVE, wire: id('e4'), ts: '1759750000' }
      ]
    });
    const infoFor = descriptor => descriptor === FOUNDATION_VAULT.descriptor ? foundationInfo : descriptor === familyInfo.descriptor ? familyInfo : null;
    // Three requests on the family vault: WAITING (1 of 2 checked: Alice),
    // READY (2 of 2: Bob and this wallet), and one the module REFUSES with
    // its "coins this vault does not hold" text (crypto/nodus-send-wasm.c
    // NSW_MS_NOT_OWNED — an older request already spent them).
    const request = byte => ({ chain: 'c0'.repeat(32), tip: '5012', signers: '2', digest: id(byte), env: '00ff00ff' });
    const reviewOf = {
      [id('d1')]: { verifiedSigners: [ALICE], to: DAVE, amount: '2500000000', change: '4999000000', inputs: [id('c2')] },
      [id('d2')]: { verifiedSigners: [BOB, OWN], to: CAROL, amount: '1000000000', change: '6499000000', inputs: [id('c1')] }
    };
    const NOT_OWNED = 'This request spends coins this vault does not hold — do not approve it. Refresh the vault if you think this is wrong.';
    const refuse = new Set([id('d3')]);
    // and one whose review cannot be done right now (nsw_msig_review's tip
    // query failed, crypto/nodus-send-wasm.c :3716): not a verdict
    const TIP_UNKNOWN = 'The current Nodus block height is unknown (rc=-1).';
    const cannot = new Set([id('d4')]);
    // `at` in ms (Messages' Date.now()); drawn newest first: the waiting one
    // on top, then ready, then the unchecked one (still open); the refused
    // one in "Finished requests"
    const messages = [
      { fp: ALICE, dir: 'in', text: core.encodeRequest({ vault: FAMILY, request: request('d1') }), at: 1759990000000 },
      { fp: BOB, dir: 'in', text: core.encodeRequest({ vault: FAMILY, request: request('d2') }), at: 1759980000000 },
      { fp: ALICE, dir: 'in', text: core.encodeRequest({ vault: FAMILY, request: request('d3') }), at: 1759970000000 },
      { fp: BOB, dir: 'in', text: core.encodeRequest({ vault: FAMILY, request: request('d4') }), at: 1759960000000 }
    ];
    const readBack = digest => {
      const x = reviewOf[digest];
      return {
        vault: FAMILY, approvals: 2, verifiedSigners: x.verifiedSigners, refused: 0, member: true, expired: false, tip: '5012', expiryHeight: '5102',
        fee: '1000000', inputs: x.inputs, outputs: [{ owner: x.to, amount: x.amount, change: false }, { owner: FAMILY, amount: x.change, change: true }]
      };
    };
    // "Send payment" on the ready request: the network refuses it (another
    // member's payment already spent its coins; the text is the fake's)
    const SEND_REFUSED = 'The network refused this payment: its coins are already spent.';
    // the other member's payment lands (window.__vaultsSpendReady, called by
    // the test before it drives one background pass): from then on the
    // family vault's coins no longer hold c1, the ready request's input
    window.__vaultsSpendReady = () => { coins[FAMILY] = coins[FAMILY].filter(c => c.id !== id('c1')); };
    // the coin read can be held open (window.__vaultsHoldCoins / __vaultsReleaseCoins)
    // so the test can look at the panel WHILE a background pass is reading;
    // __vaultsCoinsAsked counts the coin reads asked for
    let coinsGate = null;
    window.__vaultsCoinsAsked = 0;
    window.__vaultsHoldCoins = () => {
      let release;
      coinsGate = new Promise(resolve => { release = resolve; });
      window.__vaultsReleaseCoins = () => { coinsGate = null; release(); };
    };
    const client = {
      state: 'ready', vaultable: true, nameable: true, fingerprint: OWN,
      async vaultOpen({ descriptor }) { const info = infoFor(descriptor); if (!info) throw new Error('This is not a vault code.'); return { ...info, members: [...info.members] }; },
      async vaultBalance({ descriptor }) { return balances[infoFor(descriptor).address]; },
      async vaultCoins({ descriptor }) {
        window.__vaultsCoinsAsked++;
        if (coinsGate) await coinsGate;
        return { coins: [...coins[infoFor(descriptor).address]], truncated: false };
      },
      async vaultHistory({ descriptor }) { return history(infoFor(descriptor).address); },
      async nameOf({ owner }) { const name = chainNames.get(owner); return name ? { found: true, name, committedHeight: '5012' } : { found: false, committedHeight: '5012' }; },
      async nameLookup({ name }) { const owner = [...chainNames].find(([, n]) => n === name)?.[0]; return owner ? { found: true, owner } : { found: false }; },
      async vaultReview({ request: r }) {
        if (refuse.has(r.digest)) throw new Error(NOT_OWNED);
        if (cannot.has(r.digest)) throw new Error(TIP_UNKNOWN);
        return readBack(r.digest);
      },
      async vaultSubmit({ request: r }) { return { accepted: false, message: SEND_REFUSED, review: readBack(r.digest) }; },
      async vaultCreate({ members, m }) {
        // BUGS W-06: the family vault's members and approvals give the family
        // vault's address again (the address is a hash of the code)
        if (m === 2 && members.length === 2 && members.includes(ALICE) && members.includes(BOB)) return { ...familyInfo, members: [...familyInfo.members] };
        const all = [OWN, ...members];
        return { descriptor: code(m, all.map((_, i) => ['a1', 'b2', 'c3', 'd4', 'e5', 'f6', '07'][i])), address: id('7a'), m, n: all.length, members: all };
      }
    };
    const kept = [{ address: FAMILY, value: core.recordForStorage(core.makeVaultRecord({ info: familyInfo, label: 'Family savings', created: '4200' })) }];
    const host = {
      isOpen: () => true,
      vaults: () => kept,
      async keepVault() {}, async dropVault() {},
      name: fp => (fp === BOB ? 'Bob (contact)' : undefined),
      messages: () => messages,
      contacts: () => [{ fp: ALICE, name: 'alice' }, { fp: BOB, name: 'Bob (contact)' }, { fp: CAROL, name: 'carol' }],
      async send() {},
      setPayloadView() {}, onChange() {}
    };
    // no background pass on its own timer during the test (it would run in
    // the middle of the clicks below); the test drives one with
    // pollVaultNow()
    ui.holdVaultPoll(true);
    ui.mountVaults({ panelNode: document.getElementById('vault-panel'), rootNode: document.getElementById('vaults-root'), messagesHost: host });
    ui.vaultExtension.nodusReady({ client });
  });

  // No action running: every button usable again, the status line empty.
  const settled = () => page.waitForFunction(() => {
    const root = document.getElementById('vaults-root');
    return ![...root.querySelectorAll('button')].some(b => b.disabled) && !root.querySelector('.vault-status').textContent;
  });
  const back = async () => { await page.getByRole('button', { name: '← All shared vaults' }).click(); await page.locator('.vault-grid').waitFor(); };
  async function open(name) {
    await page.getByRole('button', { name: `Open ${name}` }).click();
    await page.locator('.vault-history').waitFor();
    await settled();
  }
  async function shoot(name) {
    await page.evaluate(() => document.fonts.ready);
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      if (shots) await page.screenshot({ path: `${shots}/${name}-${width}.png`, fullPage: true });
    }
    for (const width of [390, 320]) {
      await page.setViewportSize({ width, height: 800 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${name}: horizontal scroll at ${width}px`);
    }
    await page.setViewportSize({ width: 1280, height: 900 });
  }

  // The list: both vaults, balances read by opening each once.
  await page.waitForFunction(() => document.querySelectorAll('#vaults-root .vault-tile').length === 2);
  await settled();
  await open('Foundation vault'); await back();
  await open('Family savings'); await back();
  assert.deepEqual(await page.locator('.vault-tile h5').allInnerTexts(), ['Family savings', 'Foundation vault']);
  assert.equal(await page.locator('.vault-tile .vault-amount').count(), 2);
  await shoot('vaults-list');

  // A vault: members, the requests read on Open (no Review pressed), history.
  // The Open pass yields between its calls, so settled() alone could pass
  // in a gap: first wait until every request card has its final state.
  await page.getByRole('button', { name: 'Open Family savings' }).click();
  await page.locator('.vault-history').waitFor();
  await page.waitForFunction(() => document.querySelectorAll('#vaults-root .vault-request[data-state]').length === 4);
  await settled();
  assert.equal(await page.getByRole('button', { name: 'Review', exact: true }).count(), 0);
  assert.deepEqual(await page.locator('.vault-open-requests .vault-request .vault-state').allInnerTexts(), ['Waiting for approvals', 'Ready to send', 'Not checked']);
  assert.deepEqual(await page.locator('.vault-open-requests .vault-approvals-text').allInnerTexts(), ['1 of 2 approvals checked', '2 of 2 approvals checked']);
  assert.equal(await page.locator('.vault-open-requests .vault-received').count(), 3);
  // the one that could not be checked (not a verdict): OPEN, a neutral
  // notice with the module's text, only "Check again"
  const notChecked = page.locator('.vault-open-requests .vault-request[data-state="unchecked"]');
  assert.equal(await notChecked.count(), 1);
  assert.equal(await notChecked.locator('.vault-unchecked').textContent(), 'This request could not be checked right now: The current Nodus block height is unknown (rc=-1).');
  assert.deepEqual(await notChecked.locator('button').allTextContents(), ['Check again']);
  // the refused one: in the collapsed Finished section, the module's text on
  // its own card, no approve / send, the top status line empty
  assert.equal(await page.locator('details.vault-finished > summary').textContent(), 'Finished requests (1)');
  assert.equal(await page.locator('details.vault-finished').evaluate(node => node.open), false);
  // (named refusedCard: `refused` is the CSP-refusal list checked at the end)
  const refusedCard = page.locator('details.vault-finished .vault-request[data-state="refused"]');
  assert.equal(await refusedCard.count(), 1);
  assert.equal(await refusedCard.locator('.vault-refusal').textContent(), 'This request spends coins this vault does not hold — do not approve it. Refresh the vault if you think this is wrong.');
  assert.equal(await refusedCard.locator('.vault-state').textContent(), 'Not valid');
  assert.deepEqual(await refusedCard.locator('button').allTextContents(), ['Check again']);
  assert.equal(await page.locator('#vaults-root .vault-status').textContent(), '');
  await page.locator('details.vault-finished > summary').click();
  await refusedCard.locator('.vault-refusal').waitFor();
  assert.equal(await page.locator('.vault-member').count(), 3);
  assert.equal(await page.locator('.vault-member .vault-you').count(), 1);
  assert.equal(await page.locator('.vault-history .activity-row').count(), 3);
  // no card prints a missing value as text ("null" / "undefined")
  // (a text node whose whole value is the word: textContent glues it to the
  // next button's text, so a word-boundary match on textContent misses it)
  assert.equal(await page.locator('#vaults-root').evaluate(root => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) if (/^\s*(null|undefined)\s*$/.test(n.nodeValue)) return true;
    return false;
  }), false, 'a card prints "null" or "undefined"');
  await shoot('vaults-vault');

  // Send payment on the ready request, refused by the network: the refusal
  // is on THAT card (red), the top status line stays empty (0.1.86).
  const readyCard = page.locator('.vault-open-requests .vault-request[data-state="ready"]');
  await readyCard.getByRole('button', { name: 'Send payment' }).click();
  await settled();
  const sendNote = page.locator('.vault-request .vault-note[data-kind="error"]');
  assert.equal(await sendNote.count(), 1);
  assert.equal(await sendNote.textContent(), 'The network refused this payment: its coins are already spent.');
  assert.equal(await readyCard.locator('.vault-note').count(), 1);
  assert.equal(await page.locator('#vaults-root .vault-status').textContent(), '');

  // Another member's payment spent the ready request's coin: one background
  // pass (the 30-second read, driven here) reads the coins again, and that
  // card moves to Finished as "Coins spent" with no Approve / Send payment;
  // the waiting one is reviewed again and stays open.
  // The pass never greys the buttons: its coin read is held open, and while
  // it waits no button of the panel is disabled and the status line is
  // empty; then the read is let go and the pass ends.
  await page.evaluate(() => { window.__vaultsSpendReady(); window.__vaultsHoldCoins(); });
  const during = await page.evaluate(async () => {
    const ui = await import('/src/vaults/ui.js');
    const asked = window.__vaultsCoinsAsked;
    window.__vaultsPass = ui.pollVaultNow();
    for (let i = 0; window.__vaultsCoinsAsked === asked; i++) {
      if (i > 500) throw new Error('the background pass never asked for the coins');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    const root = document.getElementById('vaults-root');
    return { disabled: [...root.querySelectorAll('button')].filter(b => b.disabled).length, status: root.querySelector('.vault-status').textContent };
  });
  assert.deepEqual(during, { disabled: 0, status: '' }, 'buttons greyed or status set while a background pass reads');
  assert.equal(await page.evaluate(() => { window.__vaultsReleaseCoins(); return window.__vaultsPass; }), true);
  await settled();
  assert.deepEqual(await page.locator('.vault-open-requests .vault-request .vault-state').allInnerTexts(), ['Waiting for approvals', 'Not checked']);
  assert.equal(await page.locator('details.vault-finished > summary').textContent(), 'Finished requests (2)');
  const spentCard = page.locator('details.vault-finished .vault-request[data-state="spent"]');
  assert.equal(await spentCard.count(), 1);
  assert.equal(await spentCard.locator('.vault-state').textContent(), 'Coins spent');
  assert.equal(await spentCard.getByRole('button', { name: 'Send payment' }).count(), 0);
  assert.equal(await spentCard.getByRole('button', { name: 'Approve' }).count(), 0);
  assert.equal(await page.locator('.vault-open-requests').getByRole('button', { name: 'Send payment' }).count(), 0);
  assert.equal(await page.locator('#vaults-root .vault-status').textContent(), '');
  await back();

  // Create: a typed chain name and a picked contact, members checked.
  await page.getByRole('button', { name: 'Create a shared vault' }).click();
  await page.getByLabel('Vault name (only for you and the members)').fill('Team budget');
  await page.getByLabel('Other members').fill('carol');
  await page.locator('.vault-contact', { hasText: 'alice' }).locator('input').check();
  await page.getByRole('button', { name: 'Check members' }).click();
  await page.locator('.vault-preview').waitFor();
  await settled();
  assert.equal(await page.locator('.vault-preview .vault-member').count(), 3);
  await shoot('vaults-create');

  // BUGS W-06: the family vault's members (alice, Bob) with 2 approvals give
  // the family vault's address — the create screen says it is already in
  // the list under its own name, offers "Open it" and no "Create vault";
  // the listed vault keeps its name.
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.locator('.vault-grid').waitFor();
  await page.getByRole('button', { name: 'Create a shared vault' }).click();
  await page.getByLabel('Vault name (only for you and the members)').fill('Copy of family');
  await page.getByLabel('Other members').fill('alice');
  await page.locator('.vault-contact', { hasText: 'Bob' }).locator('input').check();
  await page.getByRole('button', { name: 'Check members' }).click();
  await page.locator('.vault-preview').waitFor();
  await settled();
  assert.equal(await page.locator('.vault-preview .vault-already .vault-notice').textContent(), 'This vault is already in your list as “Family savings”.');
  assert.equal(await page.getByRole('button', { name: 'Create vault' }).count(), 0);
  await page.getByRole('button', { name: 'Open it' }).click();
  await page.locator('.vault-hero').waitFor();
  assert.equal(await page.locator('.vault-hero h4').textContent(), 'Family savings');
  await settled();
  await back();
  assert.deepEqual(await page.locator('.vault-tile h5').allInnerTexts(), ['Family savings', 'Foundation vault']);

  assert.deepEqual(errors, [], 'page errors');
  assert.deepEqual(refused, [], 'loads refused by the Content-Security-Policy');
  assert.deepEqual(unexpected, [], 'requests outside the dev server');
  console.log(`Shared vaults page: list, vault and create drawn; no horizontal scroll at 390 / 320 px${shots ? `; screenshots in ${shots}` : ''}.`);
} finally {
  await browser?.close();
  server.stop();
}
