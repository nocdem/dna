// Messages conversation (web 0.1.89): message actions and the polished
// conversation, in a real browser, WITHOUT a network.
//
// How it mounts: `vite` (dev server, web-wallet/) serves the real sources;
// the page is a fixed HTML answered by page.route with the sites'
// Content-Security-Policy. The REAL Messages module (src/connect/ui/
// messages.js) is mounted with mountMessages() and opened through its wallet
// extension (nodusIdentified, then nodusReady) on a FAKE wallet client whose
// module answers each nc_* export with fixed JSON in the shapes core.js
// checks — one contact (B) with a salt, and B's day bucket holding: a chat
// text with an https link, a reply in the app's "↩ Re:" form, a text and
// B's delete notice for it, and B's ❤️ reaction to the first text. The
// content hashes are computed in the page with src/connect/ui/actions.js
// (whose hash is checked against the app library in
// test/connect-actions.test.js). Every request that is not a GET to the dev
// server is refused and reported.
//
// Asserted: the link is an <a> to the https URL (new tab, no referrer); the
// reply shows its quote block and only its own text; the deleted text shows
// "This message was deleted by the sender."; the ❤️ chip under the first
// text; right click opens the menu (8 emojis, Reply, Copy, Delete on this
// device — no "for everyone" on a received message), Esc closes it; 👍 from
// the menu publishes the app's reaction form with op "add" for that
// message's hash and draws "👍"; a touch held 450 ms opens the menu; Reply
// shows the reply bar and the next send publishes "↩ Re: <name>\n> <quote>
// \n<text>"; "Delete for everyone" on that own message publishes the app's
// delete notice with its hash and draws "You deleted this message.";
// "Delete on this device" hides B's first text with no publish; no page
// error, no CSP refusal, no other request.
//
// How it can lie: every answer is the fake's — nothing proves a real node
// stores or returns these records (the C side is the native tests'
// test_nc_classify K1-K12; the hash the oracle test). The memory-only
// history (no vault id) is used; IndexedDB is not exercised.
//
// Run: npm run test:messages (CHROMIUM_PATH = a Chromium binary if
// Playwright's own is not installed; SCREENSHOT_DIR = where the PNGs go —
// without it nothing is written: messages-conversation, messages-menu,
// messages-reply-390).
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const PORT = 4197;
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'], PORT);
const url = server.url;
const harness = `${url}/__messages-harness.html`;
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' https: wss:; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'";
const HTML = `<!doctype html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${CSP}"><title>Messages (harness)</title><link rel="stylesheet" href="/src/style.css"><link rel="stylesheet" href="/src/connect/ui/messenger.css"></head>
<body><main id="nc-root" style="height:100vh"></main></body>
</html>`.replace(' style="height:100vh"', '');

// The middle of a bubble can be its link, whose right click stays the
// browser's own (0.1.90): press on the bubble's first plain word instead.
async function rightClickText(bubble) {
  const position = await bubble.evaluate(b => {
    const walk = document.createTreeWalker(b, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
      if (n.parentElement.closest('a') || !n.textContent.trim()) continue;
      const r = document.createRange(); r.setStart(n, 0); r.setEnd(n, Math.min(3, n.length));
      const t = r.getBoundingClientRect(), o = b.getBoundingClientRect();
      return { x: t.left - o.left + t.width / 2, y: t.top - o.top + t.height / 2 };
    }
    throw new Error('no plain text in the bubble');
  });
  await bubble.click({ button: 'right', position });
}
const errors = [], refused = [], unexpected = [];
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, hasTouch: true });
  const page = await context.newPage();
  page.setDefaultTimeout(30000);
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

  await page.evaluate(async () => {
    const { mountMessages, walletExtension } = await import('/src/connect/ui/messages.js');
    const { contentHash, buildReaction, buildDelete } = await import('/src/connect/ui/actions.js');
    const OWN = '1a'.repeat(64), B = '2b'.repeat(64), SALT = '11'.repeat(32), TODAY = '20370';
    const hex = s => Array.from(new TextEncoder().encode(s), b => b.toString(16).padStart(2, '0')).join('');
    const T = n => String(1791500000 + n);
    const first = 'hello see https://nodusnetwork.io/wiki.', gone = 'this will be deleted';
    // Payment cards (0.1.90): one B really paid (the fake history has the
    // matching spend_in), one forged (its wire's row says 1 raw unit).
    const { buildTransfer } = await import('/src/connect/ui/actions.js');
    const WIRE_OK = 'e1'.repeat(64), WIRE_FAKE = 'e2'.repeat(64), NATIVE = '0'.repeat(128);
    window.__history = [
      { h: 900n, i: 0n, q: 0n, kind: 'spend_in', amount: 250000000n, token: NATIVE, fee: 0n, peer: B, wire: WIRE_OK, ts: 1n },
      { h: 901n, i: 0n, q: 0n, kind: 'spend_in', amount: 1n, token: NATIVE, fee: 0n, peer: B, wire: WIRE_FAKE, ts: 1n }
    ];
    const inbox = [
      { seq: '6', sender_ts: T(0), text_hex: hex(buildTransfer({ amount: '2.5', wire: WIRE_OK, to: OWN, name: 'me' })), kind: 'transfer' },
      { seq: '7', sender_ts: T(0), text_hex: hex(buildTransfer({ amount: '1000', wire: WIRE_FAKE, to: OWN, name: 'me' })), kind: 'transfer' },
      // the real card sent again: one payment, one "Received"
      { seq: '8', sender_ts: T(0), text_hex: hex(buildTransfer({ amount: '2.5', wire: WIRE_OK, to: OWN, name: 'me again' })), kind: 'transfer' },
      { seq: '1', sender_ts: T(1), text_hex: hex(first), kind: 'chat' },
      { seq: '2', sender_ts: T(2), text_hex: hex('↩ Re: me\n> my first message\nyes indeed'), kind: 'chat' },
      { seq: '3', sender_ts: T(3), text_hex: hex(gone), kind: 'chat' },
      { seq: '4', sender_ts: T(4), text_hex: hex(buildDelete([contentHash(B, OWN, gone, T(3))])), kind: 'delete' },
      { seq: '5', sender_ts: T(5), text_hex: hex(buildReaction(contentHash(B, OWN, first, T(1)), '❤️', 'add')), kind: 'reaction' }
    ];
    window.__hashFirst = contentHash(B, OWN, first, T(1));
    const profile = fp => ({ outcome: 'found', why: 'none', foreign: '0', record: '{}',
      profile: { fingerprint: fp, claimed_name: '', bio: '', location: '', website: '', avatar_base64: '', wallets: {}, socials: {}, has_mlkem: true, version: '3', timestamp: '1' } });
    const day = (d, messages = []) => ({ outcome: messages.length ? 'found' : 'empty', why: 'none', day: d, blob: messages.length ? 'ab'.repeat(32) : undefined, unchanged: false, dropped: '0', other: '0', messages });
    const answers = {
      nc_unlock: () => ({ fingerprint: OWN, fresh: false }),
      nc_profile_get: args => profile(args[0]),
      nc_contacts_get: () => ({ outcome: 'found', why: 'none', invalid: '0', timestamp: '1', contacts: [{ fp: B, salt: SALT }] }),
      nc_contacts_add: () => ({ status: 'unchanged', outcome: 'found', why: 'none', created: false, count_before: '1', count_after: '1', salt_kept: '0', put_rc: 0 }),
      nc_requests_get: () => ({ outcome: 'empty', why: 'none', partial: true, truncated: false, dropped: {}, requests: [] }),
      nc_salt_reconcile: () => ({ status: 'nothing_to_write', outcome: 'found', why: 'none', wrong_pair: '0', choice: 'keep_local', salt: SALT, put_rc: 0 }),
      nc_contact_reads: args => ({ contacts: JSON.parse(args[0]).map(c => ({ ack: { outcome: 'empty', why: 'none' }, days: c.days.map(x => day(x.day, x.day === TODAY ? inbox : [])) })) }),
      nc_outbox_send: args => ({ day: TODAY, alg: 1, count: String(JSON.parse(args[2]).length) }),
      nc_ack_send: () => ({})
    };
    window.__published = [];
    let last, lastArgs;
    const api = {
      num: (name, types, args) => { last = name; lastArgs = args; return name === 'nc_words_alloc' ? 64 : 0; },
      call: async (name, types, args) => { last = name; lastArgs = args; if (name === 'nc_outbox_send') window.__published.push(JSON.parse(args[2])); return 0; },
      str: name => (name === 'nc_result' ? JSON.stringify(answers[last] ? answers[last](lastArgs || []) : {}) : name === 'nc_day_today' ? TODAY : ''),
      heap: () => new Uint8Array(4096)
    };
    const client = {
      state: 'identified', fingerprint: OWN, localConnectable: true,
      connect: async run => run(api), connectLocal: async run => run(api), connectSync: run => run(api),
      nameOf: async () => { throw new Error('no names here'); },
      historyReadable: true,
      addrHistory: async () => ({ enabled: true, fromHeight: 1n, entries: window.__history })
    };
    window.__paid = [];
    window.__walletExtension = walletExtension;
    mountMessages(document.getElementById('nc-root'), { payContact: fp => window.__paid.push(fp) });
    await Promise.all(walletExtension.nodusIdentified({ client, phrase: 'alpha beta gamma', vaultId: null, fresh: false }));
    client.state = 'ready';
    walletExtension.nodusReady({ client });
  });

  // The contact row appears once the first check round stored B's day.
  await page.waitForFunction(() => document.querySelector('.contact-row .contact-preview')?.textContent.includes('yes indeed') || document.querySelector('.contact-row'));
  await page.locator('.contact-row').first().click();
  await page.waitForFunction(() => document.querySelectorAll('.message-list .message').length >= 3);

  // The link, the reply's quote, the deleted text, the reaction chip.
  const link = page.locator('.message-text a').first();
  assert.equal(await link.getAttribute('href'), 'https://nodusnetwork.io/wiki');
  assert.equal(await link.getAttribute('target'), '_blank');
  assert.match(await link.getAttribute('rel'), /noreferrer/);
  assert.equal(await page.locator('.message-quote-text').first().textContent(), 'my first message');
  assert.ok((await page.locator('.message-text').allTextContents()).includes('yes indeed'), 'a reply shows only its own text');
  // 0.1.93 (operator screenshot, Samsung Internet: "Yes" one letter wide):
  // at phone width every short text is laid out on ONE line — its bubble is
  // never narrower than the text it holds.
  await page.setViewportSize({ width: 360, height: 800 });
  const squeezed = await page.evaluate(() => [...document.querySelectorAll('.message-text')].filter(t => {
    const text = t.textContent;
    if (!text || text.length > 20 || text.includes('\n')) return false;
    const lineHeight = parseFloat(getComputedStyle(t).lineHeight);
    return t.getBoundingClientRect().height > lineHeight * 1.5;
  }).map(t => t.textContent));
  assert.deepEqual(squeezed, [], 'a short message wraps inside its own bubble');
  await page.setViewportSize({ width: 1280, height: 900 });
  assert.ok((await page.locator('.message-gone .message-text').allTextContents()).includes('This message was deleted by the sender.'));
  assert.equal(await page.locator('.reaction-chip').first().textContent(), '❤️');
  const shots = process.env.SCREENSHOT_DIR || '';
  if (shots) await page.screenshot({ path: `${shots}/messages-conversation.png` });

  // Right click: the menu; no "for everyone" on a received message; Esc closes.
  const firstBubble = page.locator('.message-in .message-bubble', { hasText: 'hello see' });
  // A right click on the link inside keeps the link's own menu (0.1.90).
  await firstBubble.locator('a').click({ button: 'right' });
  assert.equal(await page.evaluate(() => document.querySelector('.message-menu-layer').hidden), true);
  await rightClickText(firstBubble);
  await page.locator('.message-menu-layer:not([hidden])').waitFor();
  assert.equal(await page.locator('.menu-emoji').count(), 8);
  const items = await page.locator('.menu-item').allTextContents();
  assert.deepEqual(items, ['Reply', 'Copy', 'Delete on this device']);
  if (shots) await page.screenshot({ path: `${shots}/messages-menu.png` });
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => document.querySelector('.message-menu-layer').hidden);

  // 👍 from the menu: the app's reaction form for that message's hash.
  await rightClickText(firstBubble);
  await page.locator('.menu-emoji', { hasText: '👍' }).click();
  await page.waitForFunction(() => window.__published.some(set => set.some(m => m.text.includes('"op":"add"') && m.text.includes('👍'))));
  const hashFirst = await page.evaluate(() => window.__hashFirst);
  const sentReaction = (await page.evaluate(() => window.__published.flat())).find(m => m.text.includes('👍'));
  assert.equal(sentReaction.text, `{"target":"${hashFirst}","emoji":"👍","op":"add"}`);
  await page.waitForFunction(() => [...document.querySelectorAll('.reaction-chip')].some(c => c.textContent === '👍' && c.classList.contains('reaction-mine')));

  // A touch held 450 ms opens the menu (no contextmenu needed: iOS sends none).
  await page.evaluate(() => {
    const b = [...document.querySelectorAll('.message-in .message-bubble')].find(x => x.textContent.includes('hello see'));
    const r = b.getBoundingClientRect();
    b.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, pointerType: 'touch', clientX: r.left + 5, clientY: r.top + 5 }));
  });
  await page.waitForTimeout(600);
  assert.equal(await page.locator('.message-menu-layer').isHidden(), false, 'long press opened the menu');

  // Reply: the bar, then the app's quote form on send.
  await page.locator('.menu-item', { hasText: 'Reply' }).click();
  await page.locator('.composer-reply:not([hidden])').waitFor();
  if (shots) { await page.setViewportSize({ width: 390, height: 800 }); await page.screenshot({ path: `${shots}/messages-reply-390.png` }); await page.setViewportSize({ width: 1280, height: 900 }); }
  await page.locator('#nc-send-text').fill('my answer');
  await page.locator('#nc-send-text').press('Enter');
  await page.waitForFunction(() => window.__published.flat().some(m => m.text.startsWith('↩ Re: ')));
  const reply = (await page.evaluate(() => window.__published.flat())).find(m => m.text.startsWith('↩ Re: '));
  assert.match(reply.text, /^↩ Re: [^\n]+\n> hello see https:\/\/nodusnetwork\.io\/wiki\.\nmy answer$/);
  assert.equal(await page.locator('.composer-reply').isHidden(), true, 'the reply bar closes after sending');

  // Delete for everyone on that own message: the app's delete notice.
  const own = page.locator('.message-out .message-bubble').last();
  await own.click({ button: 'right' });
  assert.deepEqual(await page.locator('.menu-item').allTextContents(), ['Reply', 'Copy', 'Delete for everyone', 'Delete on this device']);
  await page.locator('.menu-item', { hasText: 'Delete for everyone' }).click();
  await page.waitForFunction(() => window.__published.flat().some(m => m.text.startsWith('{"type":"delete"')));
  const notice = JSON.parse((await page.evaluate(() => window.__published.flat())).find(m => m.text.startsWith('{"type":"delete"')).text);
  assert.equal(notice.action, 0);
  assert.equal(notice.hashes.length, 1);
  await page.waitForFunction(() => [...document.querySelectorAll('.message-gone .message-text')].some(n => n.textContent === 'You deleted this message.'));

  // Delete on this device: B's first text disappears, nothing published.
  const before = (await page.evaluate(() => window.__published.flat())).length;
  await rightClickText(page.locator('.message-in .message-bubble', { hasText: 'hello see' }));
  await page.locator('.menu-item', { hasText: 'Delete on this device' }).click();
  await page.waitForFunction(() => ![...document.querySelectorAll('.message-text')].some(n => n.textContent.includes('hello see')));
  const after = (await page.evaluate(() => window.__published.flat())).length;
  assert.ok(after <= before + 3, 'a local delete adds no new item (sets republish the same items)');
  assert.ok(!(await page.evaluate(() => window.__published.flat())).some(m => m.text.includes('"hide"')), 'the local mark is never sent');

  // Payment cards: the real one is "Received · block 900" (own history:
  // spend_in, that wire, from B, 2.5 NODUS); the forged one says it does not
  // match. The chat list never takes the card's word.
  await page.waitForFunction(() => [...document.querySelectorAll('.transfer-state')].some(n => n.textContent === 'Received · block 900'));
  const states = await page.locator('.transfer-card').evaluateAll(cards => cards.map(c => [c.querySelector('.transfer-amount').textContent, c.querySelector('.transfer-state').textContent, c.className]));
  assert.deepEqual(states.map(s => s[1]), ['Received · block 900', 'Not confirmed by your account history — do not rely on this card', 'A copy of a payment card shown above — not a second payment']);
  assert.match(states[1][2], /transfer-mismatch/);
  if (shots) await page.screenshot({ path: `${shots}/messages-payments.png` });

  // "Send NODUS": the host opens the wallet's form for this contact; the
  // wallet's accepted transfer to THAT contact posts one card in the app's form.
  await page.locator('.conversation-pay').click();
  assert.deepEqual(await page.evaluate(() => window.__paid), ['2b'.repeat(64)]);
  const WIRE_NEW = 'e3'.repeat(64);
  await page.evaluate(w => window.__walletExtension.nodusSent({ to: '9f'.repeat(64), amount: '1', wire: w }), WIRE_NEW);
  await page.waitForTimeout(300);
  assert.ok(!(await page.evaluate(() => window.__published.flat())).some(m => m.text.includes('token_transfer') && m.text.includes('9f9f')), 'a transfer to someone else posts no card');
  await page.evaluate(w => window.__walletExtension.nodusSent({ to: '2b'.repeat(64), amount: '1.25', wire: w }), WIRE_NEW);
  await page.waitForFunction(() => window.__published.flat().some(m => m.text.includes('"type":"token_transfer"')));
  const card = JSON.parse((await page.evaluate(() => window.__published.flat())).find(m => m.text.includes('"type":"token_transfer"')).text);
  assert.deepEqual({ ...card, recipientName: undefined }, { type: 'token_transfer', amount: '1.25', token: 'NODUS', network: 'Nodus', chain: 'nodus', txHash: WIRE_NEW, recipientAddress: '2b'.repeat(64), recipientName: undefined });
  await page.waitForFunction(() => [...document.querySelectorAll('.message-out .transfer-state')].some(n => n.textContent === 'Waiting for the chain'));
  // 0.1.94: a card not settled yet offers "Check now"; once this device's
  // history holds the payment, pressing it settles the card at once, and a
  // settled card offers nothing more to check.
  const waitingCard = page.locator('.message-out .transfer-card', { hasText: 'Waiting for the chain' });
  assert.equal(await waitingCard.locator('.transfer-check').count(), 1);
  await page.evaluate(w => window.__history.unshift({ h: 950n, i: 0n, q: 0n, kind: 'spend_out', amount: 125000000n, token: '0'.repeat(128), fee: 0n, peer: '2b'.repeat(64), wire: w, ts: 2n }), WIRE_NEW);
  await waitingCard.locator('.transfer-check').click();
  await page.waitForFunction(() => [...document.querySelectorAll('.message-out .transfer-state')].some(n => n.textContent === 'Sent · block 950'));
  assert.equal(await page.locator('.message-out .transfer-card', { hasText: 'Sent · block 950' }).locator('.transfer-check').count(), 0);
  // (A card's bubble carries no message menu at all — messages.js renders
  // wireMenu only for chat texts — so nothing to assert about the menu here.)
  await page.evaluate(w => window.__walletExtension.nodusSent({ to: '2b'.repeat(64), amount: '1.25', wire: w }), 'e4'.repeat(64));
  await page.waitForTimeout(300);
  // Sets are republished whole: count the distinct cards, not the sends.
  assert.equal(new Set((await page.evaluate(() => window.__published.flat())).filter(m => m.text.includes('"type":"token_transfer"')).map(m => m.text)).size, 1, 'exactly one card');
  assert.ok(!(await page.evaluate(() => window.__published.flat())).some(m => m.text.includes('e4e4')), 'one card per "Send NODUS"');

  assert.deepEqual(errors, [], 'no page error');
  assert.deepEqual(refused, [], 'no CSP refusal');
  assert.deepEqual(unexpected, [], 'no other request');
  console.log('Messages browser test passed: link, reply quote, deleted-by-sender, reaction chips; menu by right click and by a 450 ms touch, Esc; 👍 publishes the app\'s reaction form; Reply publishes the app\'s quote form; Delete for everyone publishes the app\'s delete notice; Delete on this device publishes nothing.');
} finally {
  await browser?.close();
  await server.stop();
}
