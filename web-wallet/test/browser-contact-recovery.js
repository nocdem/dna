// Bounded recovery regression: real shipped WASM/state codec/history encryption
// and Chromium IndexedDB, with explicit synthetic network exports. Public test
// mnemonic vectors only; no real identity, node, account or message send.
// Requires npm dependencies, built send.wasm, Chromium. No compile flags.
// CONTACT_RECOVERY_REMOTE=1 exercises the extension's public snapshot renderer;
// otherwise the receiver is the web renderer. CHROMIUM_PATH selects Chromium.
// All non-local requests/WebSockets are refused; temporary browser/server close.
// This cannot prove real node availability, actual Mina's missing-list cause,
// or exactly-once network delivery through a crash after an acknowledged write.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPreview } from './preview-server.js';

const port = 4194, errors = [], outside = [];
const server = await startPreview(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(port), '--strictPort'], port);
const url = server.url, harness = `${url}/__recovery.html`;
let browser;
try {
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true });
  const page = await browser.newPage(); page.setDefaultTimeout(20000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
    const r = route.request();
    if (r.url() === harness) return route.fulfill({ contentType: 'text/html', body: '<!doctype html><link rel="stylesheet" href="/src/style.css"><link rel="stylesheet" href="/src/connect/ui/messenger.css"><main id="recovery"></main>' });
    if (r.url().startsWith(`${url}/`) && r.method() === 'GET') return route.continue();
    outside.push(r.url()); return route.abort();
  });
  await page.routeWebSocket(() => true, socket => { outside.push(socket.url()); socket.close(); });
  await page.goto(harness);
  await page.clock.install({ time: new Date('2026-10-31T12:00:00Z') });
  await page.evaluate(async remote => {
    const { recoveryFixture } = await import('/test/contact-recovery-fixture.js');
    window.r = await recoveryFixture(document.querySelector('#recovery'), remote);
  }, process.env.CONTACT_RECOVERY_REMOTE === '1');
  const state = label => page.evaluate(label => r.state(label), label);
  const sync = label => page.evaluate(label => r.action(label, 'sync'), label);
  const open = async label => {
    const first = await page.evaluate(label => r.open(label), label);
    if (first.phase !== 'open') console.error('Synthetic session log', await page.evaluate(async () => (await import('/src/session-log.js')).sessionLog.text()));
    assert.equal(first.phase, 'open', JSON.stringify(first));
    await page.waitForFunction(label => r.state(label).caughtUp, label);
  };
  const a = await page.evaluate(() => r.actors.a.fp), b = await page.evaluate(() => r.actors.b.fp);
  const approvals = () => page.evaluate(() => r.net.writes.filter(w => w.name === 'nc_request_approve'));
  const accept = () => page.evaluate(() => r.action('b', 'contactAccept', { fp: r.actors.a.fp }).catch(e => ({ error: e.message })));
  const injectOrdinary = timestamp => page.evaluate(timestamp => { r.put(r.actors.b.fp, r.record(r.actors.a.fp, false, r.OFFER, timestamp)); }, timestamp);
  await open('b');
  const history = await page.evaluate(() => r.messageBytes('b'));
  assert.equal((await state('b')).messages[0].text, 'KEPT SYNTHETIC HISTORY');
  await page.evaluate(() => { r.net.outcomes[r.actors.a.fp] = 'empty'; });
  await open('a');
  assert.equal((await state('a')).contacts.length, 0);
  await page.evaluate(() => r.action('a', 'contactAdd', { input: r.actors.b.fp }));
  const ordinary = await page.evaluate(() => structuredClone(r.net.inbox[r.actors.b.fp][0]));
  await sync('b'); await page.evaluate(() => r.requests());
  assert.equal((await state('b')).requests.length, 1, 'known receiver must expose an ordinary restored-sender request');
  assert.equal((await state('b')).contacts.filter(c => c.fp === a).length, 1);
  const row = page.locator('.request-row').filter({ has: page.getByRole('button', { name: 'Reconnect', exact: true }) });
  assert.equal(await row.count(), 1, 'existing contact has an explicit Reconnect prompt');
  assert.doesNotMatch(await row.innerText(), /Not a contact/);
  const publicRequest = (await state('b')).requests[0];
  assert.equal('salt' in publicRequest, false, 'extension projection never exposes request salts');
  assert.equal('requestRecovery' in (await state('b')), false, 'durable receipts stay private');
  if (process.env.RECOVERY_SCREENSHOT) await page.screenshot({ path: process.env.RECOVERY_SCREENSHOT, fullPage: true });
  for (let n = 0; n < 3; n++) await sync('b');
  assert.equal((await approvals()).length, 0, 'polling never sends an acceptance');
  // An acceptance response from an existing peer is not a reconnect request.
  await page.evaluate(() => r.put(r.actors.b.fp, r.record(r.actors.a.fp, true, r.OFFER)));
  await sync('b'); assert.equal((await state('b')).requests.length, 0);
  assert.equal((await approvals()).length, 0);
  await page.evaluate(value => r.put(r.actors.b.fp, value), ordinary); await sync('b');
  // Concurrent explicit accepts may only enter the transport once.
  await page.evaluate(() => {
    r.net.heldAck = new Promise(resolve => { r.releaseAck = resolve; });
    r.presses = [r.action('b', 'contactAccept', { fp: r.actors.a.fp }), r.action('b', 'contactAccept', { fp: r.actors.a.fp })].map(p => p.catch(e => ({ error: e.message })));
  });
  await page.waitForFunction(() => r.net.writes.some(w => w.name === 'nc_request_approve'));
  assert.equal((await approvals()).length, 1);
  await page.evaluate(async () => { r.releaseAck(); r.net.heldAck = null; await Promise.all(r.presses); });
  assert.equal((await approvals())[0].args[1], '5a'.repeat(32), 'receiver replies with its established salt');
  await sync('a');
  assert.equal((await state('a')).contacts.filter(c => c.fp === b).length, 1);
  assert.equal((await state('a')).outgoing.length, 0);
  // A saved/reopened wallet is fresh=false even when it has never had a
  // network list. Keep the existing firstRecordAllowed policy: unknown
  // absence cannot prove that it is a restored list or a never-created list.
  const firstList = await page.evaluate(() => r.net.writes.filter(w => w.owner === r.actors.a.fp && w.name === 'nc_contacts_add'));
  assert.equal(firstList.length, 1, 'reopened wallet can create its first list under the existing never-seen gate');
  assert.equal(firstList[0].args[1], 1, 'first publication retains the existing first_ok contract');
  assert.equal((await approvals()).length, 1, 'acceptance completion never echoes another acceptance');
  await page.evaluate(value => r.put(r.actors.b.fp, value), ordinary);
  for (let n = 0; n < 3; n++) await sync('b');
  assert.equal((await state('b')).requests.length, 0, 'same request replay suppressed');
  await open('b'); await sync('b');
  assert.equal((await state('b')).requests.length, 0, 'receipt survives actual encrypted history reopen');
  await injectOrdinary(String(BigInt(ordinary.timestamp) - 1n)); await sync('b');
  assert.equal((await state('b')).requests.length, 0, 'older request replay suppressed');
  assert.deepEqual(await page.evaluate(() => r.messageBytes('b')), history, 'history ciphertext is unchanged');

  // Stale ACKs never complete a later pending request. A genuine ACK may
  // have the SAME seconds timestamp as the request (no artificial delay).
  await page.evaluate(() => r.action('a', 'contactAdd', { input: r.OTHER }));
  const pendingAt = await page.evaluate(() => r.state('a').outgoing.find(x => x.fp === r.OTHER).at);
  await page.evaluate(at => r.put(r.actors.a.fp, r.record(r.OTHER, true, r.OFFER, String(BigInt(at) - 1n))), pendingAt);
  await sync('a');
  assert.ok((await state('a')).outgoing.some(x => x.fp === '7c'.repeat(64)));
  assert.equal((await state('a')).contacts.some(x => x.fp === '7c'.repeat(64)), false);
  await page.evaluate(at => r.put(r.actors.a.fp, r.record(r.OTHER, false, r.OFFER, at)), pendingAt);
  await sync('a');
  assert.ok((await state('a')).outgoing.some(x => x.fp === '7c'.repeat(64)), 'ordinary request does not act as an acceptance');
  await page.evaluate(at => r.put(r.actors.a.fp, r.record(r.OTHER, true, r.OFFER, at)), pendingAt);
  await sync('a');
  assert.equal((await state('a')).outgoing.some(x => x.fp === '7c'.repeat(64)), false);
  assert.ok((await state('a')).contacts.some(x => x.fp === '7c'.repeat(64)));
  await page.evaluate(() => r.put(r.actors.a.fp, r.record(r.REMOVED, true, r.OFFER)));
  await sync('a');
  assert.equal((await state('a')).contacts.some(x => x.fp === '8d'.repeat(64)), false, 'unsolicited acceptance is never automatic');
  assert.ok((await state('a')).requests.some(x => x.sender === '8d'.repeat(64)));
  await page.evaluate(() => r.action('a', 'contactAccept', { fp: r.REMOVED }));
  assert.ok((await state('a')).contacts.some(x => x.fp === '8d'.repeat(64)));
  assert.equal((await approvals()).length, 1, 'explicit acceptance of a response sends no reciprocal ACK');

  // A failed local write must occur before any acceptance is sent.
  const newer = String(BigInt(ordinary.timestamp) + 1n);
  await injectOrdinary(newer); await sync('b');
  await page.evaluate(() => { r.net.failSeal = 1; }); await accept();
  assert.equal((await approvals()).length, 1, 'failed intent persistence sends nothing');
  assert.equal((await state('b')).requests.length, 1);
  // An uncertain transport result stays explicit; reopening never auto-sends.
  await page.evaluate(() => { r.net.failAck = true; }); await accept();
  assert.equal((await approvals()).length, 2);
  for (let n = 0; n < 3; n++) await sync('b');
  await open('b'); await sync('b');
  assert.equal((await approvals()).length, 2, 'pending intent is not an automatic retry');
  assert.equal((await state('b')).requests.length, 1, 'failed acceptance can be retried explicitly');
  await page.evaluate(() => { r.net.failAck = false; }); await accept();
  assert.equal((await approvals()).length, 3);
  assert.equal((await state('b')).requests.length, 0);
  // Successful network write + failed completion save: only save is retried.
  await injectOrdinary(String(BigInt(newer) + 1n)); await sync('b');
  await page.evaluate(() => { r.net.failAfterAck = true; }); await accept();
  assert.equal((await approvals()).length, 4);
  assert.equal((await state('b')).requests[0].saveOnly, true, 'successful reply with failed save offers save-only retry');
  await sync('b'); await accept();
  assert.equal((await approvals()).length, 4, 'same-session completion retry never repeats a successful ACK');
  await open('b'); await sync('b');
  assert.equal((await state('b')).requests.length, 0);
  // Declining reconnect leaves the established contact/history untouched.
  await injectOrdinary(String(BigInt(newer) + 2n)); await sync('b');
  await page.evaluate(() => r.action('b', 'contactDecline', { fp: r.actors.a.fp }));
  await sync('b');
  assert.equal((await state('b')).requests.length, 0);
  assert.equal((await state('b')).contacts.filter(c => c.fp === a).length, 1);
  assert.equal((await approvals()).length, 4, 'declining sends no acceptance');
  assert.deepEqual(await page.evaluate(() => r.messageBytes('b')), history);

  // Missing/unreadable own list is visible and retried by normal polling;
  // a later list is merged without replacing local salts/removals/history.
  await page.evaluate(() => { r.net.outcomes[r.actors.b.fp] = 'empty'; });
  await open('b');
  assert.match(JSON.stringify((await state('b')).feedback), /contact.*(list|recover)|list.*(read|recover)/i);
  const reads = await page.evaluate(() => r.net.reads.filter(x => x.owner === r.actors.b.fp && x.name === 'nc_contacts_get').length);
  await page.evaluate(() => { r.net.outcomes[r.actors.b.fp] = 'unreadable'; });
  await page.clock.fastForward(30000);
  await page.waitForFunction(previous => r.net.reads.filter(x => x.owner === r.actors.b.fp && x.name === 'nc_contacts_get').length > previous, reads);
  await sync('b');
  assert.equal((await state('b')).contacts.length, 1, 'transient miss keeps existing contact');
  const listWrites = await page.evaluate(() => r.net.writes.filter(w => w.owner === r.actors.b.fp && w.name === 'nc_contacts_add').length);
  await page.evaluate(() => { r.net.outcomes[r.actors.b.fp] = 'throw'; });
  await sync('b');
  assert.match(JSON.stringify((await state('b')).feedback), /network contact list could not be read.*checking again automatically/);
  assert.equal((await state('b')).contacts.length, 1);
  assert.equal(await page.evaluate(() => r.net.writes.filter(w => w.owner === r.actors.b.fp && w.name === 'nc_contacts_add').length), listWrites,
    'read exceptions never trigger a replacement-list publication');
  await page.evaluate(() => {
    r.net.outcomes[r.actors.b.fp] = 'found';
    r.net.lists[r.actors.b.fp] = [{ fp: r.actors.a.fp, salt: r.OFFER }, { fp: r.OTHER, salt: r.OFFER }, { fp: r.REMOVED, salt: r.OFFER }];
  });
  await sync('b');
  assert.deepEqual((await state('b')).contacts.map(c => c.fp).sort(), [a, '7c'.repeat(64)].sort());
  assert.deepEqual(await page.evaluate(() => r.messageBytes('b')), history);
  const storedA = await page.evaluate(() => r.stored('a'));
  const storedB = await page.evaluate(() => r.stored('b'));
  assert.equal(storedA.contacts.find(c => c.fp === b).salt, '5a'.repeat(32), 'restored sender adopts authenticated acceptance salt');
  assert.equal(storedB.contacts.find(c => c.fp === a).salt, '5a'.repeat(32), 'list merge never replaces established salt');
  assert.ok(storedB.removed.includes('8d'.repeat(64)));
  // The own-list read can recover a contact while explicit approval is
  // awaiting its profile. A subsequent local removal during the acceptance
  // transport must remain a removal, including when it was unknown at entry.
  await open('b');
  // A prior removal is different from removal DURING this action: explicit
  // consent may add an old removed peer back without resetting its history.
  await page.evaluate(() => r.put(r.actors.b.fp, r.record(r.REMOVED)));
  await sync('b');
  await page.evaluate(() => r.action('b', 'contactAccept', { fp: r.REMOVED }));
  assert.ok((await state('b')).contacts.some(c => c.fp === '8d'.repeat(64)));
  // A save-only retry must preserve a removal made AFTER its successful
  // transport and failed completion save, without acknowledging again.
  await page.evaluate(() => {
    const at = String(BigInt(r.net.inbox[r.actors.b.fp].find(x => x.sender === r.REMOVED).timestamp) + 1n);
    r.put(r.actors.b.fp, r.record(r.REMOVED, false, r.OFFER, at));
  });
  await sync('b');
  await page.evaluate(async () => { r.net.failAfterAck = true; await r.action('b', 'contactAccept', { fp: r.REMOVED }).catch(() => {}); });
  assert.ok((await state('b')).requests.find(x => x.sender === '8d'.repeat(64)).saveOnly);
  const repliedBeforeRetryRemoval = (await approvals()).length;
  await page.evaluate(() => r.action('b', 'contactRemove', { fp: r.REMOVED, confirmed: true }));
  await page.evaluate(() => r.action('b', 'contactAccept', { fp: r.REMOVED }));
  assert.equal((await state('b')).contacts.some(c => c.fp === '8d'.repeat(64)), false);
  assert.equal((await approvals()).length, repliedBeforeRetryRemoval);
  assert.match((await state('b')).feedback.requestsStatus, /removed/i);
  await page.evaluate(() => { r.RACE = '9e'.repeat(64); r.net.unavailableProfile = r.RACE; r.put(r.actors.b.fp, r.record(r.RACE)); });
  await sync('b');
  await page.evaluate(() => {
    r.net.holdProfileFp = r.RACE;
    r.net.unavailableProfile = null;
    r.net.heldProfile = new Promise(resolve => { r.releaseProfile = resolve; });
    r.net.heldAck = new Promise(resolve => { r.releaseAck = resolve; });
    r.approvalRace = r.action('b', 'contactAccept', { fp: r.RACE }).catch(e => ({ error: e.message }));
  });
  await page.waitForFunction(() => r.net.profileHeld);
  await page.evaluate(() => {
    r.net.lists[r.actors.b.fp].push({ fp: r.RACE, salt: r.OLD });
    r.syncRace = r.action('b', 'sync'); r.net.heldProfile = null; r.releaseProfile();
  });
  await page.waitForFunction(() => r.state('b').contacts.some(c => c.fp === r.RACE) &&
    r.net.writes.some(w => w.name === 'nc_request_approve' && w.args[0] === r.RACE));
  await page.evaluate(() => { r.removeRace = r.action('b', 'contactRemove', { fp: r.RACE, confirmed: true }); });
  await page.waitForFunction(() => !r.state('b').contacts.some(c => c.fp === r.RACE));
  await page.evaluate(async () => { r.net.heldAck = null; r.releaseAck(); await Promise.all([r.approvalRace, r.syncRace, r.removeRace]); });
  assert.equal((await state('b')).contacts.some(c => c.fp === '9e'.repeat(64)), false,
    'removal during approval must not be undone by a recovered contact that was unknown at action entry');
  assert.match((await state('b')).feedback.requestsStatus, /removed/i);
  const repliedBeforeRemoval = (await approvals()).length;
  await sync('b'); await open('b'); await sync('b');
  assert.equal((await state('b')).contacts.some(c => c.fp === '9e'.repeat(64)), false);
  assert.equal((await approvals()).length, repliedBeforeRemoval, 'successful reply receipt survives removal and reopen');
  assert.deepEqual(await page.evaluate(() => r.messageBytes('b')), history);
  const afterRemoval = await page.evaluate(() => r.stored('b'));
  assert.ok(afterRemoval.removed.includes('9e'.repeat(64)));
  assert.equal(await page.evaluate(() => r.net.writes.filter(w => w.name === 'nc_outbox_send').length), 0);
  // A corrupt durable receipt is a closed-history error, never a fresh empty
  // replay fence. The unchanged message ciphertext remains on disk.
  await page.evaluate(async () => {
    const { databaseNameForVault, STORE_STATE } = await import('/src/connect/store.js');
    const db = await new Promise((resolve, reject) => { const q = indexedDB.open(databaseNameForVault(r.actors.b.vaultId)); q.onsuccess = () => resolve(q.result); q.onerror = () => reject(q.error); });
    try {
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_STATE, 'readwrite'), store = tx.objectStore(STORE_STATE), get = store.get('request-recovery-v1');
        get.onsuccess = () => { const record = get.result; if (!record) { tx.abort(); return; } const bytes = new Uint8Array(record.ct); bytes[0] ^= 1; record.ct = bytes; store.put(record); };
        tx.oncomplete = resolve; tx.onabort = () => reject(new Error('Missing recovery record')); tx.onerror = () => reject(tx.error);
      });
    } finally { db.close(); }
  });
  const beforeCorruptOpen = (await approvals()).length;
  const closed = await page.evaluate(() => r.open('b'));
  assert.equal(closed.phase, 'closed', 'tampered replay metadata fails closed');
  assert.equal((await approvals()).length, beforeCorruptOpen);
  assert.deepEqual(await page.evaluate(() => r.messageBytes('b')), history);
  await page.evaluate(() => r.close());
  assert.deepEqual(errors, []); assert.deepEqual(outside, []);
  console.log(`PASS contact recovery (${process.env.CONTACT_RECOVERY_REMOTE === '1' ? 'remote' : 'web'}): explicit reconnect, ordinary/acceptance distinction, salts, durable replay fence, failure/retry, contact-list recovery, unchanged encrypted history; synthetic transport only`);
} catch (error) {
  console.error('Recovery failure:', error);
  throw error;
} finally { await browser?.close(); server.stop(); }
