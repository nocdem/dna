// Proves the extension's attention module (toolbar badge, the system notification for waiting approvals, the one for
// new messages, and the notification clicks) against the REAL approval controller (through createApprovals) and the real
// Messenger. Chrome's action, notifications, tabs and windows APIs, the unread total, the clock and the interface state
// are in-memory fakes that record every call; the fakes prove the calls the module makes, not what a real browser or
// operating system shows (whether notifications are shown, or focus is honoured, is a manual check on the user's screen).
// Needs: Node >=22.14, no flags, network, files or ports. Leaves: nothing; globalThis.chrome and globalThis.stateHooks
// are set only by the waking-click test and restored by it.
// Falsely passes: a recording fake that is never read at its latest entry (every step reads the last call and the call
// count); a fake controller that never emits stateChange on resolve (the real ApprovalController is used, so the end of
// a spell is a real state change); a clock that never advances (the message tests move it explicitly on both sides of
// the 2000 ms gap).
import test from 'node:test';
import assert from 'node:assert/strict';
import { Messenger } from '@metamask/messenger';
import { createApprovals } from '../src/background/approvals.js';
import { createAttention } from '../src/background/attention.js';
import { SWAP_PAYMENT_APPROVAL } from '../src/constants/swap.js';
import { onDebugLine } from '../../src/debug-log.js';

const APPROVAL_ID = 'nodus-approval', MESSAGE_ID = 'nodus-messages';
const ICON = 'chrome-extension://test-extension/icons/nodus-128.png';
const CONNECT_URL = 'chrome-extension://test-extension/home.html?view=connect';
const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(resolve => setImmediate(resolve)); };

// Everything the module may call, recorded. `trace` is one ordered list over notifications.clear, tabs and windows calls.
function rig(t, options = {}) {
  const badge = [], log = [], trace = [], clickListeners = [], outcomes = [], ids = [];
  const clock = { now: 1_000_000 }, unread = { value: { count: 0, caughtUp: false } };
  const ui = { popupCount: 0, tabIds: new Set() };
  const showConnectCalls = [], created = [], focused = [], open = [];
  const action = {
    setBadgeText({ text }) { if (options.badgeThrows) throw new Error('no badge'); badge.push({ fn: 'text', value: text }); },
    setBadgeBackgroundColor({ color }) { if (options.badgeThrows) throw new Error('no badge'); badge.push({ fn: 'bg', value: color }); },
    setBadgeTextColor({ color }) { badge.push({ fn: 'fg', value: color }); },
  };
  const notifications = {
    async create(id, details) { log.push({ fn: 'create', id, options: details }); if (options.createFails) throw new Error('notification refused'); return id; },
    async clear(id) { log.push({ fn: 'clear', id }); trace.push(['clear', id]); return true; },
    onClicked: {
      addListener(fn) { if (options.addListenerThrows) throw new Error('listener refused'); clickListeners.push(fn); },
      removeListener(fn) { if (options.removeListenerThrows) throw new Error('listener removal refused'); const i = clickListeners.indexOf(fn); if (i >= 0) clickListeners.splice(i, 1); },
      hasListener: fn => clickListeners.includes(fn),
    },
  };
  const tabs = {
    active: [],
    async query() { return tabs.active; },
    async create(details) { trace.push(['tabs.create', details]); if (options.tabsCreateFails) throw new Error('no tab'); return { id: 99, windowId: 5 }; },
    async update(id, details) { trace.push(['tabs.update', id, details]); return { id, windowId: 5 }; },
  };
  // The windows the attention module uses for a message click (a full page's window); the approval window has its own fake.
  const attentionWindows = {
    async update(id, details) { trace.push(['windows.update', id, details]); },
    async create(details) { trace.push(['windows.create', details]); return { id: 6 }; },
  };
  const approvalWindows = {
    onRemoved: { addListener() {}, removeListener() {} },
    async getAll() { return open; }, async getLastFocused() { return { left: 20, top: 30, width: 1000 }; },
    async create(details) { created.push(details); const win = { ...details, id: created.length }; open.push(win); return win; },
    async update(id, details) { if (details.focused) focused.push({ id, ...details }); },
  };
  const runtime = { id: 'test-extension', getURL: path => `chrome-extension://test-extension/${path}` };
  const messenger = new Messenger({ namespace: 'Background' });
  const getUiState = () => ui;
  const approvals = createApprovals({ messenger, runtime, windows: approvalWindows, tabs, getUiState });
  if (options.lazy) {
    const saved = new Map(['chrome', 'stateHooks'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
    t.after(() => { for (const [key, descriptor] of saved) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; } });
    options.lazy.calls = [];
    globalThis.chrome = { notifications };
    globalThis.stateHooks = { lazyListener: { addListener(namespace, name, callback) {
      options.lazy.calls.push([namespace, name]);
      if (options.lazy.throws) throw new Error('lazy registration refused');
      for (const args of options.lazy.buffered) callback(...args);
    } } };
  }
  const attention = createAttention({ action: options.noAction ? undefined : action, notifications: options.minimalNotifications ? { create: notifications.create } : notifications,
    runtime, windows: attentionWindows, tabs, messenger, approvals, getUnread: () => unread.value, getUiState,
    showConnectIn: tabId => { trace.push(['showConnect', tabId]); showConnectCalls.push(tabId); }, now: () => clock.now });
  let destroyed = false;
  const destroyAttention = () => { if (!destroyed) { destroyed = true; attention.destroy(); } };
  t.after(() => { destroyAttention(); approvals.destroy(); });
  // Adds a waiting approval of the given type through the real controller (no window is requested by this call).
  function add(id, type, origin = 'https://site.example', requestData) {
    ids.push(id);
    const promise = approvals.controller.add({ id, origin, type, ...(requestData ? { requestData } : {}) });
    outcomes.push(promise.then(() => 'accepted', error => error.code));
  }
  // The same through the call that asks for the approval window (a page-less site request), so triggerUi runs.
  function addShow(id, type, origin = 'https://site.example') {
    ids.push(id);
    outcomes.push(approvals.controller.addAndShowApprovalRequest({ id, origin, type }).then(() => 'accepted', error => error.code));
  }
  const accept = id => approvals.controller.acceptRequest(id, true);
  const click = async id => { await Promise.all([...clickListeners].map(listener => listener(id))); await settle(); };
  const of = (fn, id) => log.filter(entry => entry.fn === fn && entry.id === id);
  return { badge, log, trace, clickListeners, clock, unread, ui, showConnectCalls, created, focused, tabs, attention, destroyAttention, approvals, add, addShow, accept, click, ids, outcomes,
    creates: () => of('create', APPROVAL_ID), clears: () => of('clear', APPROVAL_ID), messageCreates: () => of('create', MESSAGE_ID), messageClears: () => of('clear', MESSAGE_ID),
    text: () => badge.filter(entry => entry.fn === 'text').at(-1)?.value, color: () => badge.filter(entry => entry.fn === 'bg').at(-1)?.value };
}
const unreadStep = async (r, count, caughtUp, advance = 0) => {
  r.clock.now += advance; r.unread.value = { count, caughtUp }; r.attention.messagesChanged(); await settle();
};

// T1. Proves the badge: empty at start (the first computation always writes, which clears a stale label), the unread
// total in blue capped at 99+, '!' in red while any approval waits and winning over the count, back to the count when
// the approval is gone, empty at zero; white text colour is set; a synchronous burst of Connect changes is one write that
// reads the final state; and an identical recompute makes no API call. Can falsely pass if a fake recorded stale entries:
// each step reads the latest call and the call count.
test('toolbar badge shows ! for a waiting approval, else the unread total, else nothing, and writes only on change', async t => {
  const r = rig(t); await settle();
  assert.equal(r.text(), ''); assert.ok(r.badge.some(entry => entry.fn === 'text'), 'the start always writes');
  const quiet = async () => { const before = r.badge.length; r.attention.messagesChanged(); await settle(); assert.equal(r.badge.length, before, 'an identical recompute makes no API call'); };
  await unreadStep(r, 3, true); assert.equal(r.text(), '3'); assert.equal(r.color(), '#0376C9'); await quiet();
  await unreadStep(r, 120, true); assert.equal(r.text(), '99+'); assert.equal(r.color(), '#0376C9'); await quiet();
  r.add('a', 'personal_sign'); await settle(); assert.equal(r.text(), '!'); assert.equal(r.color(), '#e8706a'); await quiet();
  r.accept('a'); await settle(); assert.equal(r.text(), '99+'); assert.equal(r.color(), '#0376C9');
  await unreadStep(r, 0, true); assert.equal(r.text(), ''); await quiet();
  assert.ok(r.badge.some(entry => entry.fn === 'fg' && entry.value === '#FFFFFF'), 'the badge text colour is white');
  const writes = r.badge.filter(entry => entry.fn === 'text').length;
  r.unread.value = { count: 5, caughtUp: true }; r.attention.messagesChanged();
  r.unread.value = { count: 6, caughtUp: true }; r.attention.messagesChanged();
  r.unread.value = { count: 7, caughtUp: true }; r.attention.messagesChanged();
  await settle();
  assert.equal(r.badge.filter(entry => entry.fn === 'text').length, writes + 1, 'a burst is one write');
  assert.equal(r.text(), '7', 'the write reads the final state');
});

// T2. Proves each approval type of the plan alone gives '!' and the badge clears when it is answered. Every type is named in
// the loop, so a type filter that happens to match all of them cannot hide a missing type. The connect type is added through
// the controller's add, the call the permission controller's request ends in.
test('each approval type alone gives the red exclamation mark', async t => {
  for (const type of ['personal_sign', 'eth_signTypedData', 'transaction', 'wallet_switchEthereumChain', SWAP_PAYMENT_APPROVAL, 'nodus_signMessage', 'wallet_requestPermissions']) {
    const r = rig(t); await settle(); assert.equal(r.text(), '', type);
    r.add(`id-${type}`, type); await settle();
    assert.equal(r.text(), '!', type); assert.equal(r.color(), '#e8706a', type);
    r.accept(`id-${type}`); await settle(); assert.equal(r.text(), '', type);
  }
});

// T3. Proves the approval notification is ONE per spell (a spell is the time while at least one approval waits): the exact
// generic text and no origin, type name or request data in it; a second origin and bursts of the types exempt from the
// per-origin limit create nothing more; nothing is cleared until the queue is empty and then exactly one clear; the next
// approval starts a new spell and gets one notification; an active full-page tab (no window opens) still gives one for
// the whole burst. Every step asserts exact create and clear counts, so "create was called" cannot pass with one per id.
test('one approval notification per spell, with generic text, cleared when the queue empties', async t => {
  const r = rig(t); await settle();
  const startClears = r.clears().length;
  r.add('a', 'wallet_requestPermissions', 'https://a.example', { sentinel: 'SENTINEL-REQUEST-DATA' }); await settle();
  assert.equal(r.creates().length, 1);
  const { options } = r.creates()[0];
  assert.equal(options.title, 'Approval requests are waiting'); assert.equal(options.message, 'Open Nodus Connect to review them.');
  assert.equal(options.requireInteraction, true); assert.equal(options.iconUrl, ICON); assert.equal(options.type, 'basic');
  const text = JSON.stringify(r.creates()[0]);
  for (const secret of ['a.example', 'wallet_requestPermissions', 'SENTINEL-REQUEST-DATA']) assert.equal(text.includes(secret), false, secret);
  r.add('b', 'wallet_requestPermissions', 'https://b.example'); await settle(); assert.equal(r.creates().length, 1, 'a second origin');
  for (let n = 0; n < 20; n++) { r.add(`p${n}`, 'personal_sign', 'https://burst.example'); r.add(`s${n}`, 'nodus_signMessage', 'https://burst.example'); }
  await settle(); assert.equal(r.creates().length, 1, 'a burst of exempt types'); assert.equal(r.clears().length, startClears);
  const [last, ...rest] = [...r.ids].reverse();
  for (const id of rest) r.accept(id);
  await settle(); assert.equal(r.clears().length, startClears, 'one approval still waits: no clear');
  r.accept(last); await settle(); assert.equal(r.clears().length, startClears + 1, 'the queue is empty: exactly one clear');
  r.add('next', 'personal_sign'); await settle(); assert.equal(r.creates().length, 2, 'a new spell gets its notification');
  r.accept('next'); await settle(); assert.equal(r.clears().length, startClears + 2);
  // An active full-page tab: triggerUi opens no window, and the notification is still one for the whole burst.
  r.ui.tabIds = new Set([7]); r.tabs.active = [{ id: 7 }];
  const burstStart = r.ids.length;
  for (let n = 0; n < 20; n++) { r.addShow(`tp${n}`, 'personal_sign', 'https://tab.example'); r.addShow(`ts${n}`, 'nodus_signMessage', 'https://tab.example'); }
  await r.approvals.whenUiSettled(); await settle();
  assert.equal(r.created.length, 0, 'no approval window opens while a full-page tab is active');
  assert.equal(r.creates().length, 3, 'exactly one more notification for the whole burst');
  for (const id of r.ids.slice(burstStart)) r.accept(id);
  await settle(); assert.equal(r.clears().length, startClears + 3);
  await Promise.all(r.outcomes);
});

// T3 (popup). Proves a toolbar popup open at the spell start gives that spell no notification, also after the popup closes
// while approvals still wait and further approvals arrive; after that spell ends, a new approval with no popup gives one.
// Can falsely pass if popupCount were read at every recompute: the popup is closed before the later approvals, so only a
// test that was started with the popup open and checks after it closes sees the difference.
test('a toolbar popup open at the spell start suppresses that spell notification only', async t => {
  const r = rig(t); await settle();
  r.ui.popupCount = 1; r.add('a', 'personal_sign'); await settle(); assert.equal(r.creates().length, 0);
  r.ui.popupCount = 0; r.add('b', 'personal_sign', 'https://other.example'); await settle(); assert.equal(r.creates().length, 0, 'same spell, popup closed');
  r.accept('a'); r.accept('b'); await settle(); assert.equal(r.creates().length, 0);
  r.add('c', 'personal_sign'); await settle(); assert.equal(r.creates().length, 1, 'a new spell without a popup');
  r.accept('c'); await Promise.all(r.outcomes);
});

// T3 (failure). Proves a refused notification is written as the debug line `attention notification-failed`, is not retried
// within the spell, and affects no approval. Can falsely pass if the line were written by another module: the line is read
// from the debug listener by area and event.
test('a failed notification create is logged once and not retried within the spell', async t => {
  const lines = [], stop = onDebugLine(line => lines.push(`${line.area} ${line.event}`)); t.after(stop);
  const r = rig(t, { createFails: true }); await settle();
  r.add('a', 'personal_sign'); await settle(); r.add('b', 'personal_sign', 'https://other.example'); await settle();
  assert.equal(r.creates().length, 1, 'one attempt for the spell');
  assert.equal(lines.filter(line => line === 'attention notification-failed').length, 1);
  assert.equal(r.text(), '!'); r.accept('a'); r.accept('b'); assert.deepEqual(await Promise.all(r.outcomes), ['accepted', 'accepted']);
});

// T4. Proves the message notification follows the alert rule (grew = caughtUp && primed && n > last; last = n;
// primed = caughtUp), at most one per 2000 ms, generic text, cleared when an open session whose first check finished has
// nothing unread, and NOT cleared nor created by a closed session ({ 0, false }); reopening resets the rule so the catch-up
// is not announced again. Can falsely pass with a clock that never moves: the test moves it on both sides of the gap; the
// closed steps assert that no `clear` for the message id happened, which a test checking only "no create" would miss.
test('message notification: growth rule, gap, clear at zero when caught up, closed session keeps it', async t => {
  const r = rig(t); await settle();
  await unreadStep(r, 1, false); await unreadStep(r, 2, false); assert.equal(r.messageCreates().length, 0, 'growth before caughtUp');
  await unreadStep(r, 2, true); assert.equal(r.messageCreates().length, 0, 'the first caughtUp value primes');
  await unreadStep(r, 3, true); assert.equal(r.messageCreates().length, 1);
  const { options } = r.messageCreates()[0];
  assert.equal(options.title, 'Nodus Connect — new message'); assert.equal(options.message, 'Open Nodus Connect to read it.'); assert.equal(options.iconUrl, ICON);
  await unreadStep(r, 4, true, 500); assert.equal(r.messageCreates().length, 1, 'growth within 2000 ms');
  await unreadStep(r, 5, true, 2500); assert.equal(r.messageCreates().length, 2, 'growth after the gap');
  await unreadStep(r, 0, true); assert.equal(r.messageClears().length, 1, 'caught up with nothing unread');
  await unreadStep(r, 1, true, 3000); assert.equal(r.messageCreates().length, 3);
  await unreadStep(r, 0, false); await unreadStep(r, 0, false);
  assert.equal(r.messageClears().length, 1, 'a closed session does not clear'); assert.equal(r.messageCreates().length, 3, 'and does not create');
  await unreadStep(r, 0, true); assert.equal(r.messageClears().length, 2, 'the first caught-up zero after reopening clears once');
  await unreadStep(r, 0, false); await unreadStep(r, 2, false); await unreadStep(r, 2, true, 5000);
  assert.equal(r.messageCreates().length, 3, 'the catch-up after reopening is not announced'); assert.equal(r.messageClears().length, 2);
});

// T5 (approval). Proves the approval notification click: with two origins waiting it opens or focuses exactly one window,
// clears the notification once and creates nothing; an approval arriving after the click creates nothing (the click does not
// end the spell); in a new spell with two origins, resolving one then clicking first changes nothing and the click then
// opens the window and clears once; with nothing waiting the click only clears. Can falsely pass if the listener were
// never registered: the test calls the listener captured from onClicked.addListener.
test('approval notification click shows the window without ending the spell', async t => {
  const r = rig(t); await settle();
  const startClears = r.clears().length, shown = () => r.created.length + r.focused.length;
  r.add('a', 'wallet_requestPermissions', 'https://a.example'); r.add('b', 'wallet_requestPermissions', 'https://b.example'); await settle();
  assert.equal(r.creates().length, 1); assert.equal(shown(), 0);
  await r.click(APPROVAL_ID);
  assert.equal(shown(), 1, 'one window'); assert.equal(r.clears().length, startClears + 1); assert.equal(r.creates().length, 1);
  r.add('c', 'personal_sign', 'https://a.example'); await settle(); assert.equal(r.creates().length, 1, 'no new notification after the click');
  for (const id of ['a', 'b', 'c']) r.accept(id);
  await settle(); assert.equal(r.clears().length, startClears + 2, 'the end of the spell clears once more');
  r.add('d', 'wallet_requestPermissions', 'https://a.example'); r.add('e', 'wallet_requestPermissions', 'https://b.example'); await settle();
  assert.equal(r.creates().length, 2); r.accept('d'); await settle();
  assert.equal(r.creates().length, 2); assert.equal(r.clears().length, startClears + 2); const before = shown();
  await r.click(APPROVAL_ID); assert.equal(shown(), before + 1); assert.equal(r.clears().length, startClears + 3);
  r.accept('e'); await Promise.all(r.outcomes);
  const idle = rig(t); await settle(); const base = idle.clears().length;
  await idle.click(APPROVAL_ID); assert.equal(idle.clears().length, base + 1, 'nothing waits: clear only'); assert.equal(idle.created.length + idle.focused.length, 0);
});

// T5 (message). Proves the message notification click: with a full-page tab, the controller notification showConnect goes to
// that tab first, then the tab is activated, its window focused, and the notification cleared; without one a new tab opens
// on home.html?view=connect; when that rejects a focused window with the same address opens; an id of another module does
// nothing. The order is read from one trace list, so a different order fails.
test('message notification click lands on Connect in an existing or a new tab', async t => {
  const r = rig(t); await settle();
  r.ui.tabIds = new Set([7, 8]);
  await r.click(MESSAGE_ID);
  assert.deepEqual(r.showConnectCalls, [7]);
  assert.deepEqual(r.trace.filter(entry => entry[0] !== 'clear' || entry[1] === MESSAGE_ID),
    [['showConnect', 7], ['tabs.update', 7, { active: true }], ['windows.update', 5, { focused: true }], ['clear', MESSAGE_ID]]);
  const fresh = rig(t); await settle(); fresh.trace.length = 0;
  await fresh.click(MESSAGE_ID);
  assert.deepEqual(fresh.trace, [['tabs.create', { url: CONNECT_URL }], ['clear', MESSAGE_ID]]);
  const failing = rig(t, { tabsCreateFails: true }); await settle(); failing.trace.length = 0;
  await failing.click(MESSAGE_ID);
  assert.deepEqual(failing.trace, [['tabs.create', { url: CONNECT_URL }], ['windows.create', { url: CONNECT_URL, focused: true }], ['clear', MESSAGE_ID]]);
  const foreign = rig(t); await settle(); foreign.trace.length = 0; const logged = foreign.log.length;
  await foreign.click('nodus-transaction:abc'); await foreign.click('something-else');
  assert.deepEqual(foreign.trace, []); assert.equal(foreign.log.length, logged); assert.equal(foreign.created.length + foreign.focused.length, 0);
});

// T5 (waking click). Proves the click listener is registered through the worker's lazy listener when chrome.notifications
// is the notifications object in use, so a click that woke a stopped worker (buffered before the background attached) is
// delivered: a buffered message click with no interface port and a locked session opens the Connect address once and clears
// once; a buffered approval click with nothing waiting only clears. It asserts the lazy listener was asked for
// ('notifications', 'onClicked') and that onClicked.addListener was NOT used, so a direct registration (which would miss
// the buffered click) cannot pass.
test('a notification click that woke a stopped worker is delivered through the lazy listener', async t => {
  const lazy = { buffered: [[MESSAGE_ID]] };
  const r = rig(t, { lazy }); await settle();
  assert.deepEqual(lazy.calls, [['notifications', 'onClicked']]); assert.equal(r.clickListeners.length, 0);
  assert.deepEqual(r.trace.filter(entry => !(entry[0] === 'clear' && entry[1] === APPROVAL_ID)), [['tabs.create', { url: CONNECT_URL }], ['clear', MESSAGE_ID]]);
  const other = { buffered: [[APPROVAL_ID]] };
  const q = rig(t, { lazy: other }); await settle();
  assert.deepEqual(other.calls, [['notifications', 'onClicked']]);
  assert.equal(q.created.length + q.focused.length, 0, 'nothing waits: no window');
  assert.equal(q.clears().length, 2, 'the start clear and the click clear');
});

// T6. Proves the start clears the approval notification (no approval survives a restart) and never the message one (its
// message survives in the saved history), also after the first locked computation { 0, false }; a badge API that throws
// affects no approval and nothing else in the module; destroy() clears the badge, removes the click listener and stops
// updating; and a notifications object with only `create`, no action and no click event still constructs (the shape of
// the existing background fixtures).
test('start clears only the approval notification, a broken badge harms nothing, destroy cleans up', async t => {
  const r = rig(t); await settle(); r.attention.messagesChanged(); await settle();
  assert.equal(r.clears().length, 1); assert.equal(r.messageClears().length, 0);
  assert.equal(r.clickListeners.length, 1);
  const broken = rig(t, { badgeThrows: true }); await settle();
  broken.add('b', 'personal_sign'); await settle(); broken.accept('b'); assert.deepEqual(await Promise.all(broken.outcomes), ['accepted']);
  const d = rig(t); await settle(); d.add('c', 'personal_sign'); await settle(); assert.equal(d.text(), '!');
  d.destroyAttention(); assert.equal(d.text(), ''); assert.equal(d.clickListeners.length, 0);
  d.add('c2', 'wallet_requestPermissions'); await settle(); assert.equal(d.text(), '', 'a destroyed module no longer updates');
  const m = rig(t, { minimalNotifications: true, noAction: true }); await settle(); m.add('x', 'personal_sign'); await settle();
  assert.equal(m.log.length, 1, 'only create exists on this notifications object');
  m.accept('x'); await Promise.all(m.outcomes);
});

// T6 (listener failures). Proves the click listener's registration (direct and through the lazy listener) and its removal are
// guarded like every other notification call: each refusal is written as exactly one `attention notification-failed` line and
// neither createAttention nor destroy throws; the rest of the module still works (the badge shows the approval). Can falsely
// pass if the line came from another call: each case counts the lines of its own step only, with the others at zero.
test('a refused click-listener registration or removal is logged once and never thrown', async t => {
  const lines = [], stop = onDebugLine(line => lines.push(`${line.area} ${line.event}`)); t.after(stop);
  const failed = () => lines.filter(line => line === 'attention notification-failed').length;
  const direct = rig(t, { addListenerThrows: true }); await settle();
  assert.equal(failed(), 1, 'direct registration');
  direct.add('a', 'personal_sign'); await settle(); assert.equal(direct.text(), '!'); direct.accept('a'); await Promise.all(direct.outcomes);
  rig(t, { lazy: { buffered: [], throws: true } }); await settle();
  assert.equal(failed(), 2, 'lazy registration');
  const removal = rig(t, { removeListenerThrows: true }); await settle();
  assert.equal(failed(), 2, 'a working registration logs nothing');
  removal.destroyAttention(); assert.equal(failed(), 3, 'removal');
});
