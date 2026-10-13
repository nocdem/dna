// Messages with a SAVED wallet and the wallet's ONE operation queue (web
// 0.1.105), in a real browser, WITHOUT a network.
//
// What it proves: an own reaction and an own message are drawn at once even
// while a contact's network read holds the queue. Keeping a saved wallet's
// history seals each record in the module through that same queue
// (src/connect/core.js historyEncrypt is a queued "local" call,
// src/nodus/client.js "ONE operation queue"); until 0.1.105 the page drew
// the reaction / message only after keeping it, so it waited behind the
// read — the operator's report "ben gönderdiğim halde benim ekranıma bile geç
// düşüyor". Also: neither is published before it is kept (the publish
// follows the held read), and both are published once the read is let go.
// On 0.1.104's messages.js it fails at "the reaction is drawn while the
// read is held".
//
// How it mounts: as test/browser-messages.js (vite serves the real sources,
// the REAL messages.js on a FAKE wallet client), but the fake client runs
// connect / connectLocal through one serial queue like the real one, and the
// history is a saved wallet's (a vault id: IndexedDB + the module's history
// exports, faked as identity "encryption" with the real record shapes).
//
// Requires: nothing beyond `npm ci` and a Chromium (CHROMIUM_PATH).
// Leaves nothing behind (a fresh browser profile). How it can lie: the
// module is a fake — the queue's order is modelled, not the real module's
// timing; the history "encryption" is not encryption.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const PORT = 4196;
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'], PORT);
const url = server.url;
const harness = `${url}/__queue-harness.html`;
const HTML = '<!doctype html><html lang="en"><head><meta charset="UTF-8"><link rel="stylesheet" href="/src/style.css"><link rel="stylesheet" href="/src/connect/ui/messenger.css"></head><body><main id="nc-root"></main></body></html>';
const errors = [], unexpected = [];
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
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
  await page.clock.install();
  await page.evaluate(async () => {
    const { mountMessages, walletExtension } = await import('/src/connect/ui/messages.js');
    const OWN = '1a'.repeat(64), B = '2b'.repeat(64), SALT = '11'.repeat(32), TODAY = '20370';
    const hex = s => Array.from(new TextEncoder().encode(s), b => b.toString(16).padStart(2, '0')).join('');
    const inbox = [{ seq: '1', sender_ts: '1791500001', text_hex: hex('hello from B'), kind: 'chat' }];
    const profile = fp => ({ outcome: 'found', why: 'none', foreign: '0', record: '{}',
      profile: { fingerprint: fp, claimed_name: '', bio: '', location: '', website: '', avatar_base64: '', wallets: {}, socials: {}, has_mlkem: true, version: '3', timestamp: '1' } });
    const day = (d, messages = []) => ({ outcome: messages.length ? 'found' : 'empty', why: 'none', day: d, blob: messages.length ? 'ab'.repeat(32) : undefined, unchanged: false, dropped: '0', other: '0', messages });
    window.__sent = []; window.__unknown = [];
    const answers = {
      nc_unlock: () => ({ fingerprint: OWN, fresh: false }),
      nc_profile_get: args => profile(args[0]),
      nc_contacts_get: () => ({ outcome: 'found', why: 'none', invalid: '0', timestamp: '1', contacts: [{ fp: B, salt: SALT }] }),
      nc_contacts_add: () => ({ status: 'unchanged', outcome: 'found', why: 'none', created: false, count_before: '1', count_after: '1', salt_kept: '0', put_rc: 0 }),
      nc_requests_get: () => ({ outcome: 'empty', why: 'none', partial: true, truncated: false, dropped: {}, requests: [] }),
      nc_salt_reconcile: () => ({ status: 'nothing_to_write', outcome: 'found', why: 'none', wrong_pair: '0', choice: 'keep_local', salt: SALT, put_rc: 0 }),
      nc_contact_reads: args => ({ contacts: JSON.parse(args[0]).map(c => ({ ack: { outcome: 'empty', why: 'none' }, days: c.days.map(x => day(x.day, x.day === TODAY ? inbox : [])) })) }),
      nc_outbox_send: args => { window.__sent.push(JSON.parse(args[2]).map(m => m.text)); return { day: TODAY, alg: 1, count: String(JSON.parse(args[2]).length) }; },
      nc_ack_send: () => ({}),
      // A saved wallet's history, "sealed" as the identity (shapes only).
      nc_hist_key: () => ({}),
      // Since 0.1.112 the record's bytes come through the heap input buffer
      // (nc_group_in_alloc), not as an argument (BUGS W-15).
      nc_hist_encrypt: args => ({ nonce: '00'.repeat(12), ct: takeIn(), tag: '00'.repeat(16), counter: String(BigInt(args[2]) + 1n) }),
      nc_hist_decrypt: () => ({ pt: takeIn() })
    };
    // The module's heap and its one input buffer (src/connect/core.js putHistory).
    const HEAP = new Uint8Array(1 << 21), IN_AT = 1024;
    let inLen = 0;
    const takeIn = () => { const h = Array.from(HEAP.subarray(IN_AT, IN_AT + inLen), b => b.toString(16).padStart(2, '0')).join(''); inLen = 0; return h; };
    // One api object per call, so a call that waits keeps its own result.
    function api() {
      let last, lastArgs;
      const answer = () => {
        if (answers[last]) return answers[last](lastArgs || []);
        window.__unknown.push(last); return {};
      };
      return {
        num: (name, types, args) => {
          if (name === 'nc_group_in_alloc') { inLen = args[0]; return IN_AT; }
          last = name; lastArgs = args; return name === 'nc_words_alloc' ? 64 : 0;
        },
        call: async (name, types, args) => {
          last = name; lastArgs = args;
          // A contact read the test holds: the queue stays busy meanwhile.
          if (name === 'nc_contact_reads' && window.__hold) { window.__held = true; await window.__hold.promise; }
          return 0;
        },
        str: name => (name === 'nc_result' ? JSON.stringify(answer()) : name === 'nc_day_today' ? TODAY : ''),
        heap: () => HEAP
      };
    }
    // The wallet client's ONE queue (src/nodus/client.js): connect and
    // connectLocal run one at a time, in order; connectSync does not queue.
    let queue = Promise.resolve();
    const serial = run => { const p = queue.then(() => run(api())); queue = p.catch(() => {}); return p; };
    const client = { state: 'identified', fingerprint: OWN, localConnectable: true,
      connect: serial, connectLocal: serial, connectSync: run => run(api()),
      nameOf: async () => { throw new Error('no names here'); } };
    mountMessages(document.getElementById('nc-root'), {});
    await Promise.all(walletExtension.nodusIdentified({ client, phrase: 'alpha beta gamma', vaultId: btoa(String.fromCharCode(...new Uint8Array(16).fill(7))), fresh: false }));
    client.state = 'ready';
    walletExtension.nodusReady({ client });
  });
  await page.waitForFunction(() => document.querySelector('.messenger-sync')?.textContent.startsWith('Last checked'));
  await page.locator('.contact-row').first().click();
  const bubble = page.locator('.message-in', { hasText: 'hello from B' }).locator('.message-bubble');
  await bubble.waitFor();

  // The next check round: its contact read is held, so the queue is busy.
  await page.evaluate(() => { window.__hold = Promise.withResolvers(); window.__held = false; window.__sent.length = 0; });
  await page.clock.fastForward(31000);
  await page.waitForFunction(() => window.__held === true);

  // React 👍 from the menu while the read is held.
  await bubble.locator('.message-text').click({ button: 'right' });
  await page.locator('.message-menu button[aria-label="React 👍"]').click();
  await page.waitForFunction(() => [...document.querySelectorAll('.message-in .reaction-chip')].some(c => c.textContent.includes('👍')), null, { timeout: 2000 })
    .catch(() => { throw new Error('the reaction is drawn while the read is held: it is not (it waits for the queue)'); });
  // A message written meanwhile is drawn at once too.
  await page.locator('#nc-send-text').fill('sent while busy');
  await page.locator('#nc-send-text').press('Enter');
  await page.waitForFunction(() => [...document.querySelectorAll('.message-out')].some(m => m.textContent.includes('sent while busy')), null, { timeout: 2000 })
    .catch(() => { throw new Error('the message is drawn while the read is held: it is not'); });
  assert.equal(await page.locator('#nc-send-text').inputValue(), '', 'the composer is empty at once');
  // Nothing is published before it is kept, and keeping waits for the queue.
  assert.deepEqual(await page.evaluate(() => window.__sent), [], 'nothing published while the read is held');

  // Let the read go: both are kept, then published.
  await page.evaluate(() => { window.__hold.resolve(); window.__hold = undefined; });
  await page.waitForFunction(() => window.__sent.some(texts => texts.some(t => t.includes('"emoji":"👍"'))) && window.__sent.some(texts => texts.includes('sent while busy')));
  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, []);
  assert.deepEqual(await page.evaluate(() => window.__unknown), []);
  console.log('Connect queue test passed: with a saved wallet, an own reaction and message are drawn while a contact read holds the wallet queue, published only once kept.');
} finally {
  await browser?.close();
  server.stop();
}
