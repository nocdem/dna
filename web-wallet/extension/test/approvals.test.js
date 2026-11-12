import test from 'node:test';
import assert from 'node:assert/strict';
import { Messenger } from '@metamask/messenger';
import { JsonRpcEngine } from '@metamask/json-rpc-engine';
import { providerErrors } from '@metamask/rpc-errors';
import { ApprovalType } from '@metamask/controller-utils';
import { createApprovals } from '../src/background/approvals.js';
import { onDebugLine } from '../../src/debug-log.js';

// Node >=22.14; no flags/network/disk output. Window calls and time are explicit fakes.
export function approvalFixture() {
  // Every window call is also written to `order` ('create', 'focus:<id>', 'state:<id>', 'draw:<id>', 'position:<id>').
  // `update` records a drawAttention call, a state change (un-minimise) and a plain focus or position call separately,
  // so the exact `positioned` assertions below stay exact when the attention calls are added.
  const created = [], focused = [], positioned = [], attention = [], states = [], order = [], removed = new Set(), open = [];
  const windows = {
    onRemoved: { addListener(fn) { removed.add(fn); }, removeListener(fn) { removed.delete(fn); } },
    async getAll() { return open; }, async getLastFocused() { return { left: 20, top: 30, width: 1000 }; },
    async create(options) { order.push('create'); created.push(options); const win = { ...options, id: created.length }; open.push(win); return win; },
    async update(id, options) {
      if (options.drawAttention) { order.push(`draw:${id}`); attention.push({ id, ...options }); }
      else if ('state' in options) { order.push(`state:${id}`); states.push({ id, ...options }); }
      else if (options.focused) { order.push(`focus:${id}`); focused.push({ id, ...options }); }
      else { order.push(`position:${id}`); positioned.push({ id, ...options }); }
    },
  };
  return { windows, created, focused, positioned, attention, states, order, removed, open, runtime: { id: 'test-extension', getURL: path => `chrome-extension://test-extension/${path}` } };
}

// Proves the real controller's pending request opens a 400x620 notification explicitly focused (`focused: true`),
// asks the system to draw attention to it once the window id is recorded, and reuses it: a second approval focuses
// the same window and asks for attention again, in that order. A mocked approval controller could hide a missing
// show hook; the order log would falsely pass only if the fixture recorded calls in another order than they happened.
test('addAndShowApprovalRequest calls triggerUi and focuses the existing window', async () => {
  const fixture = approvalFixture(), messenger = new Messenger({ namespace: 'Background' });
  const approvals = createApprovals({ ...fixture, messenger });
  const pending = approvals.controller.addAndShowApprovalRequest({ id: 'first', origin: 'https://site.example', type: 'wallet_requestPermissions' });
  await approvals.whenUiSettled();
  assert.deepEqual(fixture.created, [{ url: 'chrome-extension://test-extension/notification.html', type: 'popup', width: 400, height: 620, left: 620, top: 30, focused: true }]);
  assert.deepEqual(fixture.attention, [{ id: 1, drawAttention: true }]);
  assert.deepEqual(fixture.order, ['create', 'draw:1']);
  assert.equal(approvals.controller.get('first').origin, 'https://site.example');
  approvals.controller.acceptRequest('first', { approved: true }); assert.deepEqual(await pending, { approved: true });
  const rejected = approvals.controller.addAndShowApprovalRequest({ id: 'second', origin: 'https://site.example', type: 'personal_sign' });
  const check = assert.rejects(rejected, { code: 4001 });
  await approvals.whenUiSettled(); assert.equal(fixture.created.length, 1); assert.equal(fixture.focused[0].id, 1);
  assert.deepEqual(fixture.focused, [{ id: 1, focused: true }]);
  assert.deepEqual(fixture.order, ['create', 'draw:1', 'focus:1', 'draw:1']);
  approvals.reject('second'); await check; approvals.destroy();
});

// Proves an existing window that the user minimised is brought back (`state: 'normal'` together with `focused: true`,
// never `focused` alone: Chrome refuses focus with the minimised state) and then asks for attention; a window that is
// not minimised gets only `{ focused: true }`. A fixture window without a state would hide the minimised branch; the
// test sets `state: 'minimized'` on the open window and asserts the plain focus call is absent.
test('a minimised approval window is restored, focused and drawn to attention', async () => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  const first = approvals.controller.addAndShowApprovalRequest({ id: 'first', origin: 'https://site.example', type: 'wallet_requestPermissions' });
  await approvals.whenUiSettled(); approvals.controller.acceptRequest('first', true); await first;
  fixture.open[0].state = 'minimized';
  const second = approvals.controller.addAndShowApprovalRequest({ id: 'second', origin: 'https://site.example', type: 'personal_sign' });
  const check = assert.rejects(second, { code: 4001 });
  await approvals.whenUiSettled();
  assert.equal(fixture.created.length, 1);
  assert.deepEqual(fixture.states, [{ id: 1, state: 'normal', focused: true }]);
  assert.deepEqual(fixture.focused, [], 'the restore call carries the focus, no separate plain focus call');
  assert.deepEqual(fixture.order, ['create', 'draw:1', 'state:1', 'draw:1']);
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
  assert.deepEqual(attempts[1], { url: 'chrome-extension://test-extension/notification.html', type: 'popup', width: 400, height: 620, focused: true });
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

// Proves the lookup-failure branch runs in a worker, which has no `window`: with the last-focused lookup rejecting and
// `globalThis.window` asserted absent, the window is still created, without left and top (the browser places it), and
// nothing rejects. The test above defines `window` and so covers the retained reference fallback only where it can
// run; a test that defined `window` here would falsely pass the defect (a ReferenceError in the catch block).
test('lookup failure without a window global opens the window without left and top', async t => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  assert.equal(typeof globalThis.window, 'undefined', 'this test needs a worker-like global scope');
  t.mock.method(fixture.windows, 'getLastFocused', async () => { throw new Error('fixture lookup failure'); });
  await approvals.triggerUi();
  assert.deepEqual(fixture.created, [{ url: 'chrome-extension://test-extension/notification.html', type: 'popup', width: 400, height: 620, focused: true }]);
  assert.deepEqual(fixture.positioned, [], 'a browser-placed window is not moved');
  approvals.destroy();
});

// Proves the attention request cannot undo the window record: `update` rejects only a call with `drawAttention` (a
// reject-everything fake would also fail the position correction and prove less). showPopup still resolves, the window
// id was recorded before the call so the next approval focuses window 1 instead of opening a second one, and a removal
// of window 1 rejects the waiting approvals as before. The debug line `approvals draw-attention-failed` names the
// failure. It could falsely pass if the id were recorded after the call: then the second approval would create window 2.
test('a failing drawAttention call leaves the window recorded and never rejects showPopup', async () => {
  const fixture = approvalFixture(), lines = [], stop = onDebugLine(line => lines.push(`${line.area} ${line.event}`));
  const plainUpdate = fixture.windows.update;
  fixture.windows.update = async (id, options) => { if (options.drawAttention) throw new Error('fixture attention refusal'); return plainUpdate(id, options); };
  const approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  try {
    const outcomes = [];
    for (const [n, id] of ['first', 'second'].entries()) {
      outcomes.push(approvals.controller.addAndShowApprovalRequest({ id, origin: `https://site${n}.example`, type: 'personal_sign' })
        .then(() => 'accepted', error => error.code));
      await approvals.whenUiSettled();
    }
    await idle();
    assert.equal(fixture.created.length, 1, 'the second approval focused window 1 and did not open a second window');
    assert.equal(fixture.focused[0]?.id, 1);
    assert.ok(lines.includes('approvals draw-attention-failed'), lines.join(', '));
    assert.equal(lines.includes('approvals window-open-failed'), false, 'showPopup did not reject');
    closeWindow(fixture, 1);
    assert.deepEqual(await Promise.all(outcomes), [4001, 4001]);
  } finally { stop(); approvals.destroy(); }
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

// The toolbar badge tests moved to attention.test.js: the badge is no longer written by this module.
// Proves the module exposes what the attention module needs: the number of waiting approvals, and showWindow, which
// opens (or focuses) the approval window for a waiting approval WITHOUT triggerUi's skips for an open toolbar popup
// or an active wallet tab (the user asked to see it), and does nothing when no approval waits. Could falsely pass if
// the skip fixture were not active; the same state is first shown to make triggerUi skip (no window), then showWindow
// is shown to open one.
test('pendingCount and showWindow serve the approval notification click', async () => {
  const fixture = approvalFixture(), ui = { popupCount: 1, tabIds: new Set() };
  const approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }), getUiState: () => ui });
  assert.equal(approvals.pendingCount(), 0);
  await approvals.showWindow(); assert.equal(fixture.created.length, 0, 'nothing waits: no window');
  const pending = approvals.controller.add({ id: 'first', origin: 'https://site.example', type: 'personal_sign' }); pending.catch(() => {});
  assert.equal(approvals.pendingCount(), 1);
  await approvals.triggerUi(); assert.equal(fixture.created.length, 0, 'triggerUi skips while a toolbar popup is open');
  await approvals.showWindow(); assert.equal(fixture.created.length, 1, 'showWindow does not skip');
  await approvals.showWindow(); assert.equal(fixture.created.length, 1, 'a second click focuses the same window');
  assert.equal(fixture.focused.at(-1).id, 1);
  approvals.reject('first'); await pending.catch(() => {}); approvals.destroy();
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
  approvals.markAutomaticClose(); closeWindow(fixture, 1); await idle();
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
  approvals.markAutomaticClose(); closeWindow(fixture, 1); await idle();
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
  approvals.markAutomaticClose(); closeWindow(fixture, 1); await idle(); assert.equal(fixture.created.length, 2);
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
  approvals.markAutomaticClose(); closeWindow(fixture, 1); await idle();
  assert.equal(fixture.created.length, 1, 'recovery waits for the opening in flight');
  release(); await idle();
  assert.equal(fixture.created.length, 2); assert.equal(approvals.controller.state.pendingApprovalCount, 1);
  approvals.reject('second'); assert.equal(await outcome, 4001); approvals.destroy();
});

// Proves a close by the user that rejects three pending approvals of one origin does not count toward that origin's spam
// block: after it, the origin's next request is let through to the approval (pending, then rejected by the user with 4001),
// not answered with the block error 4100. Could falsely pass if the three approvals were answered one at a time; the
// three are pending together before the removal.
test('a user close with three pending approvals of one origin does not block that origin', async () => {
  const fixture = approvalFixture(), approvals = createApprovals({ ...fixture, messenger: new Messenger({ namespace: 'Background' }) });
  const engine = new JsonRpcEngine(); engine.push(approvals.createOriginThrottlingMiddleware());
  engine.push((req, res, _next, end) => {
    approvals.controller.addAndShowApprovalRequest({ id: `r${req.id}`, origin: req.origin, type: 'personal_sign' }).then(value => { res.result = value; end(); }, end);
  });
  const ask = id => engine.handle({ id, jsonrpc: '2.0', origin: 'https://site.example', method: 'personal_sign' });
  const first = [1, 2, 3].map(ask);
  await idle(); assert.equal(approvals.controller.state.pendingApprovalCount, 3);
  closeWindow(fixture, 1);
  assert.deepEqual((await Promise.all(first)).map(response => response.error.code), [4001, 4001, 4001]);
  const next = ask(4); await idle();
  assert.equal(approvals.controller.state.pendingApprovalCount, 1, 'the next request reached its approval, it was not blocked');
  approvals.reject('r4'); assert.equal((await next).error.code, 4001);
  engine.destroy(); approvals.destroy();
});

// Proves the mark is kept until that window's removal: another window's removal and the passing of time between the mark
// and the removal leave it set, so the removal still reopens and rejects nothing. Could falsely pass if the removal were
// delivered before the mark; the mark is set first and the approval is shown pending afterwards.
test('the automatic-close mark survives until the approval window is removed', async () => {
  const { fixture, approvals, outcome } = await windowWithSecondWaiting();
  approvals.markAutomaticClose(); await idle(); await idle();
  assert.equal(approvals.controller.state.pendingApprovalCount, 1);
  closeWindow(fixture, 1); await idle();
  assert.equal(fixture.created.length, 2); assert.equal(approvals.controller.state.pendingApprovalCount, 1);
  approvals.reject('second'); assert.equal(await outcome, 4001); approvals.destroy();
});

// Proves the removal of any other window (toolbar popup, a tab) changes nothing and keeps the mark: no rejection, no
// window, and the mark still applies to the approval window's own removal afterwards. Could falsely pass if the other id
// coincided with the approval window's; id 99 is not any created window.
test('the removal of another window changes nothing', async () => {
  const { fixture, approvals, outcome } = await windowWithSecondWaiting();
  approvals.markAutomaticClose(); for (const listener of [...fixture.removed]) listener(99); await idle();
  assert.equal(fixture.created.length, 1); assert.equal(approvals.controller.state.pendingApprovalCount, 1);
  closeWindow(fixture, 1); await idle(); assert.equal(fixture.created.length, 2, 'the mark survived the other removal');
  approvals.reject('second'); assert.equal(await outcome, 4001); approvals.destroy();
});
