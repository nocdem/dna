// Real Messages UI + core.js, with an in-memory substitute for the WASM
// network exports. Reproduces losing an unsaved outgoing request between
// sessions, then receiving its acceptance. No live account or node is used.
// Run: node test/browser-connect-requests.js
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const port = 4199;
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(port), '--strictPort'], port);
const url = server.url;
const harness = `${url}/__connect-requests.html`;
const errors = [], unexpected = [];
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
    const request = route.request();
    if (request.url() === harness) return route.fulfill({ contentType: 'text/html', body: '<!doctype html><link rel="stylesheet" href="/src/connect/ui/messenger.css"><div id="messages"></div>' });
    if (request.url().startsWith(`${url}/`) && request.method() === 'GET') return route.continue();
    unexpected.push(request.url());
    return route.abort();
  });
  await page.routeWebSocket(() => true, socket => socket.close());
  await page.goto(harness);
  await page.clock.install();
  await page.evaluate(async () => {
    const ui = await import('/src/connect/ui/messages.js');
    const { CONTACT_ACCEPTED_MSG } = await import('/src/connect/core.js');
    const ids = { a: '11'.repeat(64), b: '22'.repeat(64), c: '33'.repeat(64), d: '44'.repeat(64) };
    const salt = '55'.repeat(32);
    const network = { inbox: {}, contacts: {}, writes: [] };
    const request = (sender, acceptance = false, message = '') => ({ sender, acceptance, message: acceptance ? CONTACT_ACCEPTED_MSG : message, salt, timestamp: String(Math.floor(Date.now() / 1000)) });
    const putRequest = (to, value) => {
      network.inbox[to] = [...(network.inbox[to] || []).filter(r => r.sender !== value.sender), value];
    };
    function client(owner) {
      function api() {
        let result = {};
        return {
          heap: () => new Uint8Array(4096),
          num: name => {
            if (name === 'nc_words_alloc') return 64;
            if (name === 'nc_lock') return 0;
            throw new Error(`Unexpected local export: ${name}`);
          },
          str: name => name === 'nc_day_today' ? '20735' : JSON.stringify(result),
          call: async (name, types, args = []) => {
            switch (name) {
              case 'nc_unlock': result = { fingerprint: owner, fresh: false }; break;
              case 'nc_profile_get': result = { outcome: 'found', profile: { fingerprint: args[0], has_mlkem: true } }; break;
              case 'nc_contacts_get': result = { outcome: 'found', contacts: structuredClone(network.contacts[owner] || []) }; break;
              case 'nc_requests_get': result = { outcome: 'found', requests: structuredClone(network.inbox[owner] || []) }; break;
              case 'nc_request_new':
              case 'nc_request_approve':
                network.writes.push({ owner, name, args });
                putRequest(args[0], request(owner, name === 'nc_request_approve', args[1]));
                result = { salt };
                break;
              case 'nc_request_withdraw':
                network.writes.push({ owner, name, args });
                network.inbox[args[0]] = (network.inbox[args[0]] || []).filter(r => r.sender !== owner);
                result = {};
                break;
              case 'nc_contacts_add': {
                network.writes.push({ owner, name, args });
                const contacts = network.contacts[owner] ||= [];
                for (const entry of JSON.parse(args[0])) if (!contacts.some(c => c.fp === entry.fp)) contacts.push(entry);
                result = { status: 'published', outcome: 'found' };
                break;
              }
              case 'nc_salt_reconcile': result = { status: 'unchanged', salt }; break;
              case 'nc_contact_reads':
                result = { contacts: JSON.parse(args[0]).map(c => ({ ack: { outcome: 'empty' }, days: c.days.map(d => ({ day: d.day, outcome: 'empty', messages: [] })) })) };
                break;
              default: throw new Error(`Unexpected network export: ${name}`);
            }
            return 0;
          }
        };
      }
      return { state: 'ready', fingerprint: owner, localConnectable: true, nameable: false,
        connect: async run => run(api()), connectLocal: async run => run(api()), connectSync: run => run(api()) };
    }
    ui.mountMessages(document.querySelector('#messages'));
    window.requestsTest = { ui, ids, network, request, putRequest,
      open: actor => ui.openMessages({ client: client(ids[actor]), phrase: 'test fixture only' }) };
  });
  const settled = () => page.waitForFunction(() => document.querySelector('.messenger-sync').textContent.startsWith('Last checked'));
  const open = async actor => { await page.evaluate(actor => window.requestsTest.open(actor), actor); await settled(); };
  const contacts = () => page.evaluate(() => window.requestsTest.ui.vaultHost.contacts().map(c => c.fp));
  const requestRows = page.locator('.messenger-contacts .request-list').first().locator('.request-row');
  const requests = () => page.evaluate(() => window.requestsTest.ui.messagesNavigate('requests'));

  // A sends; B accepts; A's next unlock has lost the memory-only pending
  // request. The verified acceptance must still be available for consent.
  await open('a');
  await page.evaluate(() => window.requestsTest.ui.messagesNavigate('add'));
  await page.locator('#nc-add-id').fill('22'.repeat(64));
  await page.locator('#nc-add-form button[type="submit"]').click();
  await page.waitForFunction(() => window.requestsTest.network.inbox[window.requestsTest.ids.b]?.length === 1);
  await page.waitForFunction(() => document.querySelector('#nc-add-form').textContent.includes('Request sent.'));
  await open('b');
  await requests();
  await requestRows.getByRole('button', { name: 'Accept', exact: true }).click();
  await page.waitForFunction(() => window.requestsTest.network.contacts[window.requestsTest.ids.b]?.length === 1);
  await open('a');
  await requests();
  assert.deepEqual(await contacts(), [], 'a lost pending request must never allow automatic approval');
  assert.equal(await requestRows.count(), 1, 'the acceptance must remain visible after losing the pending request');
  await requestRows.getByRole('button', { name: 'Accept', exact: true }).click();
  await page.waitForFunction(() => window.requestsTest.network.contacts[window.requestsTest.ids.a]?.length === 1);
  assert.deepEqual(await contacts(), ['22'.repeat(64)]);
  assert.equal(await requestRows.count(), 0);
  // Already accepted on B: A's reciprocal acceptance does not duplicate it.
  await open('b');
  await requests();
  assert.deepEqual(await contacts(), ['11'.repeat(64)]);
  assert.equal(await requestRows.count(), 0);

  // An unsolicited acceptance also needs an explicit decision; declining
  // it suppresses the same record on subsequent polling without any write.
  await page.evaluate(() => {
    const t = window.requestsTest;
    t.putRequest(t.ids.c, t.request(t.ids.b, true));
    t.network.writes.length = 0;
  });
  await open('c');
  await requests();
  assert.deepEqual(await contacts(), []);
  assert.equal(await requestRows.count(), 1);
  assert.deepEqual(await page.evaluate(() => window.requestsTest.network.writes), []);
  await requestRows.getByRole('button', { name: 'Decline', exact: true }).click();
  await page.clock.fastForward(30000);
  await settled();
  assert.equal(await requestRows.count(), 0);
  assert.deepEqual(await contacts(), []);
  assert.deepEqual(await page.evaluate(() => window.requestsTest.network.writes), []);

  // Retaining the outgoing request still permits the normal automatic
  // completion, including withdrawing the original request from B's inbox.
  await open('d');
  await page.evaluate(() => window.requestsTest.ui.messagesNavigate('add'));
  await page.locator('#nc-add-id').fill('22'.repeat(64));
  await page.locator('#nc-add-form button[type="submit"]').click();
  await page.waitForFunction(() => document.querySelector('#nc-add-form').textContent.includes('Request sent.'));
  await page.evaluate(() => {
    const t = window.requestsTest;
    t.putRequest(t.ids.d, t.request(t.ids.b, true));
  });
  await page.clock.fastForward(30000);
  await page.waitForFunction(() => window.requestsTest.network.contacts[window.requestsTest.ids.d]?.length === 1);
  await settled();
  assert.deepEqual(await contacts(), ['22'.repeat(64)]);
  assert.equal(await page.evaluate(() => window.requestsTest.network.inbox[window.requestsTest.ids.b].some(r => r.sender === window.requestsTest.ids.d)), false);
  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, []);
  console.log('Connect requests passed: session-loss recovery, explicit consent, decline, no duplicate, and pending auto-approval.');
} finally {
  await browser?.close();
  server.stop();
}
