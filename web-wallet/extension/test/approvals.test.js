import test from 'node:test';
import assert from 'node:assert/strict';
import { Messenger } from '@metamask/messenger';
import { JsonRpcEngine } from '@metamask/json-rpc-engine';
import { providerErrors } from '@metamask/rpc-errors';
import { ApprovalType } from '@metamask/controller-utils';
import { createApprovals } from '../src/background/approvals.js';

// Node >=22.14; no flags/network/disk output. Window calls and time are explicit fakes.
export function approvalFixture() {
  const created = [], focused = [], positioned = [], removed = new Set(), open = [];
  const windows = {
    onRemoved: { addListener(fn) { removed.add(fn); }, removeListener(fn) { removed.delete(fn); } },
    async getAll() { return open; }, async getLastFocused() { return { left: 20, top: 30, width: 1000 }; },
    async create(options) { created.push(options); const win = { ...options, id: created.length }; open.push(win); return win; },
    async update(id, options) { (options.focused ? focused : positioned).push({ id, ...options }); },
  };
  return { windows, created, focused, positioned, removed, open, runtime: { id: 'test-extension', getURL: path => `chrome-extension://test-extension/${path}` } };
}

// Proves the real controller's pending request opens a 400x620 notification and reuses it; a mocked approval controller could hide a missing show hook.
test('addAndShowApprovalRequest calls triggerUi and focuses the existing window', async () => {
  const fixture = approvalFixture(), messenger = new Messenger({ namespace: 'Background' });
  const approvals = createApprovals({ ...fixture, messenger });
  const pending = approvals.controller.addAndShowApprovalRequest({ id: 'first', origin: 'https://site.example', type: 'wallet_requestPermissions' });
  await approvals.whenUiSettled();
  assert.deepEqual(fixture.created, [{ url: 'chrome-extension://test-extension/notification.html', type: 'popup', width: 400, height: 620, left: 620, top: 30 }]);
  assert.equal(approvals.controller.get('first').origin, 'https://site.example');
  approvals.controller.acceptRequest('first', { approved: true }); assert.deepEqual(await pending, { approved: true });
  const rejected = approvals.controller.addAndShowApprovalRequest({ id: 'second', origin: 'https://site.example', type: 'personal_sign' });
  const check = assert.rejects(rejected, { code: 4001 });
  await approvals.whenUiSettled(); assert.equal(fixture.created.length, 1); assert.equal(fixture.focused[0].id, 1);
  approvals.reject('second'); await check; approvals.destroy();
});

// Proves all retained reference approval types queue per origin and permissions remain limited; testing one signing type could miss an incomplete exclusion list.
test('reference signing and transaction approval types bypass the per-origin pending limit', async () => {
  const approvals = createApprovals({ ...approvalFixture(), messenger: new Messenger({ namespace: 'Background' }) });
  const pending = [];
  try {
    for (const type of [ApprovalType.PersonalSign, ApprovalType.EthSignTypedData, ApprovalType.Transaction]) {
      for (const suffix of ['first', 'second']) {
        const id = `${type}-${suffix}`;
        pending.push({ id, promise: approvals.controller.add({ id, origin: 'https://site.example', type }) });
      }
    }
    pending.push({ id: 'permission', promise: approvals.controller.add({ id: 'permission', origin: 'https://site.example', type: 'wallet_requestPermissions' }) });
    assert.throws(() => approvals.controller.add({ id: 'duplicate', origin: 'https://site.example', type: 'wallet_requestPermissions' }), { code: -32002 });
    assert.equal(approvals.controller.state.pendingApprovalCount, 7);
  } finally {
    for (const { id } of pending) approvals.controller.acceptRequest(id, true);
    assert.deepEqual(await Promise.all(pending.map(({ promise }) => promise)), pending.map(() => true));
    approvals.destroy();
  }
});

// Proves a failed notification open preserves all queued approvals and surfaces the UI failure; a single settled request could miss a global clearRequests side effect.
test('triggerUi failure leaves pending approvals for the user to answer', async t => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  t.mock.method(fixture.windows, 'create', async () => { throw new Error('fixture window failure'); });
  const requests = ['https://first.example', 'https://second.example'].map((origin, index) => ({
    id: `pending-${index}`, promise: approvals.controller.addAndShowApprovalRequest({ id: `pending-${index}`, origin, type: 'wallet_requestPermissions' }),
  }));
  const outcomes = requests.map(({ promise }) => promise.then(value => value, error => error.code));
  await assert.rejects(approvals.whenUiSettled(), /fixture window failure/u);
  assert.equal(approvals.controller.state.pendingApprovalCount, 2);
  for (const { id } of requests) approvals.controller.acceptRequest(id, true);
  assert.deepEqual(await Promise.all(outcomes), [true, true]);
  approvals.destroy();
});

// Proves the reference corrects left bounds only for a numeric non-fullscreen popup id; always-correct positioning fakes would never exercise the update branch.
test('notification creation corrects ignored bounds using updateWindowPosition', async t => {
  for (const [id, state, returnedLeft, shouldUpdate] of [[1, 'normal', 0, true], [2, 'fullscreen', 0, false], [3, 'normal', 620, false], [undefined, 'normal', 0, false]]) {
    const fixture = approvalFixture();
    t.mock.method(fixture.windows, 'create', async options => ({ ...options, id, state, left: returnedLeft }));
    const approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
    await approvals.triggerUi();
    assert.deepEqual(fixture.positioned, shouldUpdate ? [{ id, left: 620, top: 30 }] : []);
    approvals.destroy();
  }
});

// Proves a refused position (the browser's "Bounds must be at least 50% within visible screen space") does not leave the approval
// without a window: the create is retried once without left and top, the window is remembered and reused, and no position
// correction is asked for the browser-placed window. A second refusal still reaches the caller, so the failure is not hidden.
test('a refused window position is retried once without left and top', async t => {
  const fixture = approvalFixture(), attempts = [];
  t.mock.method(fixture.windows, 'create', async options => {
    attempts.push(options);
    if ('left' in options) throw new Error('Invalid value for bounds. Bounds must be at least 50% within visible screen space.');
    const win = { ...options, id: 9, left: 5 }; fixture.windows.getAll = async () => [win]; return win;
  });
  const approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  await approvals.triggerUi();
  assert.equal(attempts.length, 2); assert.ok('left' in attempts[0] && 'top' in attempts[0]);
  assert.deepEqual(attempts[1], { url: 'chrome-extension://test-extension/notification.html', type: 'popup', width: 400, height: 620 });
  assert.deepEqual(fixture.positioned, []);
  await approvals.triggerUi(); assert.equal(attempts.length, 2); assert.equal(fixture.focused[0].id, 9);
  approvals.destroy();
  const failing = approvalFixture(); t.mock.method(failing.windows, 'create', async () => { throw new Error('no window possible'); });
  const second = createApprovals({ ...failing, messenger: new Messenger({ namespace: 'Background' }) });
  await assert.rejects(second.triggerUi(), /no window possible/u); second.destroy();
});

// Proves the pinned screen-coordinate fallback is retained when window lookup fails; successful lookup fixtures cannot detect an invented zero-position fallback.
test('notification positioning uses the reference screen fallback on lookup failure', async t => {
  const fixture = approvalFixture(), saved = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  t.mock.method(fixture.windows, 'getLastFocused', async () => { throw new Error('fixture lookup failure'); });
  globalThis.window = { screenX: 20, screenY: -10, outerWidth: 800 };
  try {
    await approvals.triggerUi();
    assert.equal(fixture.created[0].left, 420); assert.equal(fixture.created[0].top, 0);
  } finally {
    if (saved) Object.defineProperty(globalThis, 'window', saved); else delete globalThis.window;
    approvals.destroy();
  }
});

// Proves reference rejection thresholds and origin/method isolation; testing only three rejections would miss whether the fourth request was actually blocked.
test('three prompt rejections throttle the same origin for one minute', async t => {
  t.mock.method(Date, 'now', () => 1_000_000);
  const approvals = createApprovals({ ...approvalFixture(), messenger: new Messenger({ namespace: 'Background' }) });
  const engine = new JsonRpcEngine(); engine.push(approvals.createOriginThrottlingMiddleware());
  let reached = 0;
  engine.push((_req, _res, _next, end) => { reached++; end(providerErrors.userRejectedRequest()); });
  for (let id = 0; id < 3; id++) assert.equal((await engine.handle({ id, jsonrpc: '2.0', origin: 'https://site.example', method: 'personal_sign' })).error.code, 4001);
  assert.equal((await engine.handle({ id: 4, jsonrpc: '2.0', origin: 'https://site.example', method: 'personal_sign' })).error.code, 4100);
  assert.equal(reached, 3);
  assert.equal((await engine.handle({ id: 5, jsonrpc: '2.0', origin: 'https://other.example', method: 'personal_sign' })).error.code, 4001);
  assert.equal((await engine.handle({ id: 6, jsonrpc: '2.0', origin: 'https://site.example', method: 'eth_requestAccounts' })).error.code, 4001);
  t.mock.method(Date, 'now', () => 1_060_001);
  assert.equal((await engine.handle({ id: 7, jsonrpc: '2.0', origin: 'https://site.example', method: 'personal_sign' })).error.code, 4001);
  engine.destroy(); approvals.destroy();
});

// Proves the toolbar badge follows the real controller's pending approvals: cleared at start and with none pending,
// the count while approvals wait, "<max>+" past the maximum (9), always with the approval colour. Can falsely pass
// if the fake action recorded calls but the assertions read a stale entry; each check reads the latest call.
test('toolbar badge shows the number of pending approvals and clears with none', async () => {
  const texts = [], colors = [], action = { setBadgeText: ({ text }) => texts.push(text), setBadgeBackgroundColor: ({ color }) => colors.push(color) };
  const approvals = createApprovals({ ...approvalFixture(), action, messenger: new Messenger({ namespace: 'Background' }) });
  assert.equal(texts.at(-1), '');
  const waiting = [];
  for (let n = 1; n <= 11; n++) {
    const pending = approvals.controller.addAndShowApprovalRequest({ id: `a${n}`, origin: `https://site${n}.example`, type: 'personal_sign' });
    pending.catch(() => {}); waiting.push(pending);
    assert.equal(texts.at(-1), n > 9 ? '9+' : String(n));
  }
  assert.equal(colors.at(-1), '#0376C9');
  approvals.reject('a11'); assert.equal(texts.at(-1), '9+');
  for (let n = 10; n >= 1; n--) approvals.reject(`a${n}`);
  assert.equal(texts.at(-1), '');
  await Promise.allSettled(waiting); await approvals.whenUiSettled(); approvals.destroy();
});

// Proves a failing badge API cannot break an approval, and that destroy() clears the badge and stops updating.
test('toolbar badge failures do not affect approvals and destroy clears the badge', async () => {
  const texts = [];
  const broken = createApprovals({ ...approvalFixture(), action: { setBadgeText() { throw new Error('no badge'); }, setBadgeBackgroundColor() {} }, messenger: new Messenger({ namespace: 'Background' }) });
  const pending = broken.controller.addAndShowApprovalRequest({ id: 'b', origin: 'https://site.example', type: 'personal_sign' });
  await broken.whenUiSettled(); broken.controller.acceptRequest('b', true); assert.equal(await pending, true); broken.destroy();
  const approvals = createApprovals({ ...approvalFixture(), action: { setBadgeText: ({ text }) => texts.push(text), setBadgeBackgroundColor() {} }, messenger: new Messenger({ namespace: 'Background' }) });
  const waiting = approvals.controller.addAndShowApprovalRequest({ id: 'c', origin: 'https://site.example', type: 'personal_sign' }); waiting.catch(() => {});
  await approvals.whenUiSettled(); assert.equal(texts.at(-1), '1');
  approvals.destroy(); assert.equal(texts.at(-1), '');
});

// Window removal as the browser reports it: the window leaves the list, then every onRemoved listener hears its id.
const closeWindow = (fixture, id) => {
  fixture.open.splice(fixture.open.findIndex(win => win.id === id), 1);
  for (const listener of [...fixture.removed]) listener(id);
};
const idle = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
// An approval window already open with approval 'first' answered and approval 'second' waiting: 'second' arrived while the
// window was closing, so it only focused the window (no new one). The outcome of 'second' is read from its promise.
async function windowWithSecondWaiting() {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  const first = approvals.controller.addAndShowApprovalRequest({ id: 'first', origin: 'https://site.example', type: 'wallet_requestPermissions' });
  await approvals.whenUiSettled(); approvals.controller.acceptRequest('first', true); await first;
  const second = approvals.controller.addAndShowApprovalRequest({ id: 'second', origin: 'https://site.example', type: 'personal_sign' });
  const outcome = second.then(() => 'accepted', error => error.code);
  await approvals.whenUiSettled();
  assert.equal(fixture.created.length, 1, 'the second approval only focused the window that is closing');
  return { fixture, approvals, outcome };
}

// Proves an approval that arrived while the window was closing itself gets a new window: the mark is set, the window
// removed, and a second window is created with the same options. Could falsely pass if the fixture created a second
// window for the first approval too; the setup asserts a single window before the removal.
test('an automatic close with an approval still pending opens a new window', async () => {
  const { fixture, approvals, outcome } = await windowWithSecondWaiting();
  approvals.setAutomaticClose(true); closeWindow(fixture, 1); await idle();
  assert.equal(fixture.created.length, 2); assert.deepEqual(fixture.created[1], fixture.created[0]);
  assert.equal(approvals.controller.state.pendingApprovalCount, 1, 'the approval is still waiting, not rejected');
  approvals.reject('second'); assert.equal(await outcome, 4001); approvals.destroy();
});

// Proves an automatic close with nothing pending opens no window and rejects nothing. Could falsely pass if the removal
// listener were never called; the later user-close test and the other-window test pin that the listener is live.
test('an automatic close with no approval pending opens no window and rejects nothing', async () => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  const only = approvals.controller.addAndShowApprovalRequest({ id: 'only', origin: 'https://site.example', type: 'wallet_requestPermissions' });
  await approvals.whenUiSettled(); approvals.controller.acceptRequest('only', 'answered'); assert.equal(await only, 'answered');
  approvals.setAutomaticClose(true); closeWindow(fixture, 1); await idle();
  assert.equal(fixture.created.length, 1); assert.equal(approvals.controller.state.pendingApprovalCount, 0);
  approvals.destroy();
});

// Proves a window the user closes rejects every pending approval with the user-rejection code 4001 and opens no new
// window. Two approvals from different origins show that all are rejected, not only the first. Could falsely pass if
// the approvals were rejected by something else; the setup shows both pending until the removal.
test('closing the approval window by hand rejects every pending approval and opens no window', async () => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  const outcomes = ['https://a.example', 'https://b.example'].map((origin, n) => approvals.controller
    .addAndShowApprovalRequest({ id: `p${n}`, origin, type: 'personal_sign' }).then(() => 'accepted', error => error.code));
  await approvals.whenUiSettled(); assert.equal(approvals.controller.state.pendingApprovalCount, 2);
  closeWindow(fixture, 1);
  assert.deepEqual(await Promise.all(outcomes), [4001, 4001]);
  await idle(); assert.equal(fixture.created.length, 1); assert.equal(approvals.controller.state.pendingApprovalCount, 0);
  approvals.destroy();
});

// Proves the mark is read and reset by one removal: after an automatic close, the next window's close by the user rejects.
// Could falsely pass if the second window's removal were not heard; the first removal reopens, so window 2 exists.
test('the automatic-close mark applies to one removal only', async () => {
  const { fixture, approvals, outcome } = await windowWithSecondWaiting();
  approvals.setAutomaticClose(true); closeWindow(fixture, 1); await idle(); assert.equal(fixture.created.length, 2);
  closeWindow(fixture, 2); assert.equal(await outcome, 4001); await idle(); assert.equal(fixture.created.length, 2);
  approvals.destroy();
});

// Proves a removal while an opening is in flight (the opening found the closing window and is focusing it) is followed by a
// new opening that creates a window, not by joining the one that focused the closing window. The focus call is held open
// by hand so the removal lands inside it. Could falsely pass if the hold were released before the removal; the test
// removes the window first and counts created windows only after the release.
test('a removal while an opening is in flight is followed by a new window', async () => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  const first = approvals.controller.addAndShowApprovalRequest({ id: 'first', origin: 'https://site.example', type: 'wallet_requestPermissions' });
  await approvals.whenUiSettled(); approvals.controller.acceptRequest('first', true); await first;
  let release; const held = new Promise(resolve => { release = resolve; });
  fixture.windows.update = async (id, options) => { fixture.focused.push({ id, ...options }); await held; };
  const second = approvals.controller.addAndShowApprovalRequest({ id: 'second', origin: 'https://site.example', type: 'personal_sign' });
  const outcome = second.then(() => 'accepted', error => error.code);
  await idle(); assert.equal(fixture.focused.length, 1, 'the opening is focusing the closing window');
  approvals.setAutomaticClose(true); closeWindow(fixture, 1); await idle();
  assert.equal(fixture.created.length, 1, 'recovery waits for the opening in flight');
  release(); await idle();
  assert.equal(fixture.created.length, 2); assert.equal(approvals.controller.state.pendingApprovalCount, 1);
  approvals.reject('second'); assert.equal(await outcome, 4001); approvals.destroy();
});

// Proves a withdrawn mark (the page could not close) makes the next removal a user close: approvals are rejected and no
// window opens. Could falsely pass if the mark were never set; the same removal with the mark kept is the first test above.
test('a withdrawn automatic-close mark leaves a later close to count as the user close', async () => {
  const { fixture, approvals, outcome } = await windowWithSecondWaiting();
  approvals.setAutomaticClose(true); approvals.setAutomaticClose(false); closeWindow(fixture, 1);
  assert.equal(await outcome, 4001); await idle(); assert.equal(fixture.created.length, 1); approvals.destroy();
});

// Proves the removal of any other window (toolbar popup, a tab) changes nothing and keeps the mark: no rejection, no
// window, and the mark still applies to the approval window's own removal afterwards. Could falsely pass if the other id
// coincided with the approval window's; id 99 is not any created window.
test('the removal of another window changes nothing', async () => {
  const { fixture, approvals, outcome } = await windowWithSecondWaiting();
  approvals.setAutomaticClose(true); for (const listener of [...fixture.removed]) listener(99); await idle();
  assert.equal(fixture.created.length, 1); assert.equal(approvals.controller.state.pendingApprovalCount, 1);
  closeWindow(fixture, 1); await idle(); assert.equal(fixture.created.length, 2, 'the mark survived the other removal');
  approvals.reject('second'); assert.equal(await outcome, 4001); approvals.destroy();
});
