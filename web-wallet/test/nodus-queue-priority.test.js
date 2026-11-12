// The Nodus module queue with two classes (src/nodus/client.js): a step that the user started goes ahead of waiting
// background work, and while a user flow is open no background call starts. Against the TEST-ONLY mock module
// (test/nodus-mock-module.js): proves the wallet-side ordering rules, the lease, the class rule and the runner's debug
// lines; says nothing about the real module, the chain or the browser wiring.
// Environment: Node >= 22.14, the committed WASM is not used, no network, no flags. Leftovers: none (every client is
// locked at the end of its test; the debug sink of Q13 is restored in `finally`).
// How these tests could falsely pass: a gate that does not hold its call (each test asserts which call is the last
// log entry before the gate opens), a `settle()` too short to let the runner act (it drains all microtasks and one
// macrotask, and the runner needs microtasks only), an order that holds only because an entry was enqueued late (each
// test states the enqueue order it relies on). Every test sets a timeout: a deadlock fails instead of hanging, which is
// a failure bound and not a retry. The bounded waits (`until`) are assertions on an expected asynchronous condition.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusClient, NODUS_SESSION_LOST_TEXT } from '../src/nodus/client.js';
import { prepareTransfer } from '../src/wallet.js';
import { setDebugLogSink } from '../src/debug-log.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, INTENT_ID, NODUS_NATIVE, TUSDT, TUSDT_ID, tokenCoin } from './nodus-mock-module.js';

const settle = () => new Promise(resolve => setImmediate(resolve));
// At most 200 turns, then an assertion: never a retry of the test.
async function until(condition, what) {
  for (let turn = 0; turn < 200 && !condition(); turn++) await settle();
  assert.ok(condition(), what);
}
async function readyClient(setup = () => {}) {
  const mock = createMockNodusModule(), timers = { cleared: [] };
  setup(mock.state);
  const client = createNodusClient({
    factory: mock.factory,
    setInterval: (fn, ms) => { timers.fn = fn; timers.ms = ms; return 7; }, clearInterval: id => timers.cleared.push(id)
  });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client, timers };
}
const walletFor = client => ({ addresses: { nodus: FINGERPRINT }, nodusClient: client });
// A view of the client whose flow has already ended: its calls still run in the user class.
async function closedView(client) { let view; await client.userFlow(opened => { view = opened; }); return view; }
const starts = (mock, from = 0) => mock.log.slice(from).filter(entry => entry.endsWith(':start')).map(entry => entry.slice(0, -6));
const OPTIONS = { timeout: 20000 };

// Proves: a user-class entry runs right after the call in flight, before a background entry that was waiting longer,
// and no options object can claim the user class. Falsely passes if the gate did not hold balance (guarded: only
// `balance:start` is in the log before the gate opens). Base: userFlow is missing.
test('Q1: a user entry passes a waiting background entry; options cannot set the class', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  const closed = await closedView(client);
  const base = mock.log.length, open = mock.gate('balance');
  const inFlight = client.balance();
  // balance is in flight before the two other entries are queued
  await until(() => mock.log.slice(base).includes('balance:start'), 'balance entered the gated call');
  const background = client.list({ flow: {}, class: 'user' }); // other class whatever the options say
  const user = closed.rulesetInfo();
  await settle();
  assert.deepEqual(mock.log.slice(base), ['balance:start'], 'only the gated call has started');
  open();
  await Promise.all([inFlight, background, user]);
  assert.deepEqual(starts(mock, base), ['balance', 'rulesetInfo', 'list']);
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// Proves: selection at an idle queue follows the rule too: a background call and then an ended view's call (user class)
// are queued in one synchronous block with nothing running; the user call starts first, then the background one.
// Falsely passes if the queue was not idle (guarded: the log holds no entry of the block before they are queued, and
// the starts are read from the module log) or if the background call never ran (it is awaited and listed).
// Base: userFlow is missing.
test('Q1b: at an idle queue a user entry starts before a background entry queued earlier in the same tick', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  const closed = await closedView(client);
  await settle();
  const base = mock.log.length;
  const background = client.list();
  const user = closed.balance();
  await Promise.all([background, user]);
  assert.deepEqual(starts(mock, base), ['balance', 'list']);
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// Proves: the user class keeps enqueue order, between two flows and inside one flow that makes two calls at once.
// Flow A enqueues list and rulesetInfo together; flow B enqueues balance and, once it returned, rulesetInfo again; a
// background marker waits from the start and must come last. Falsely passes if the order is a coincidence of one
// flow: two flows and the background marker are all in the expected order. Base: userFlow is missing.
test('Q2: user entries run in enqueue order across and inside flows; the background entry runs last', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  const base = mock.log.length, open = mock.gate('balance');
  const inFlight = client.balance();
  await settle();
  const background = client.connect(async () => { mock.log.push('background:run'); return {}; });
  const flowA = client.userFlow(view => Promise.all([view.list(), view.rulesetInfo()]));
  const flowB = client.userFlow(async view => { await view.balance(); await view.rulesetInfo(); });
  await settle();
  assert.deepEqual(mock.log.slice(base), ['balance:start'], 'only the gated call has started');
  open();
  await Promise.all([inFlight, background, flowA, flowB]);
  assert.deepEqual(starts(mock, base).filter(name => name !== 'connect'), ['balance', 'list', 'rulesetInfo', 'balance', 'rulesetInfo']);
  assert.ok(mock.log.indexOf('background:run') > mock.log.lastIndexOf('rulesetInfo:end'), 'the background entry ran after both flows');
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// Proves: inside an open flow, a background call enqueued during the flow does not start between two of the flow's
// steps, and starts as soon as the flow ends. Falsely passes if `settle()` were too short; it drains every microtask
// and a macrotask, and the runner needs only microtasks. Base: userFlow is missing.
test('Q3: the lease keeps background work out between two steps of a flow and lets it run at the end', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  const base = mock.log.length;
  let background;
  await client.userFlow(async view => {
    await view.balance();
    background = client.list();
    await settle();
    assert.ok(!mock.log.slice(base).includes('list:start'), 'no background call starts between two steps');
    await view.rulesetInfo();
    await settle();
    assert.ok(!mock.log.slice(base).includes('list:start'), 'nor while the flow is still open');
  });
  await background;
  assert.deepEqual(starts(mock, base), ['balance', 'rulesetInfo', 'list']);
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// Proves: the lease closes on every outcome of the work (value, rejection, synchronous throw), userFlow resolves with
// the work's value or rejects with the work's own error, and a work that is not a function is refused. A background
// call enqueued during each flow must run afterwards: a leaked lease would never start it (the test timeout fails it).
// Falsely passes if the background call ran for another reason: each one is awaited, and `list` is other class.
// Base: userFlow is missing.
test('Q4: the lease closes when the work resolves, rejects or throws; the work\'s own value and error come back', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  // resolves
  let background;
  assert.equal(await client.userFlow(async view => { background = client.list(); await view.balance(); return 'value'; }), 'value');
  await background;
  // rejects: the module answers busy for list
  mock.state.busy.add('list');
  await assert.rejects(client.userFlow(async view => { background = client.balance(); await view.list(); }), error => error.busy === true);
  await background;
  mock.state.busy.delete('list');
  // throws synchronously
  await assert.rejects(client.userFlow(() => { background = client.list(); throw new Error('work threw'); }), /work threw/);
  await background;
  // a work that is not a function
  await assert.rejects(async () => client.userFlow(42), /Invalid Nodus operation/);
  assert.equal(await client.list().then(() => 'ran'), 'ran', 'the queue is free for background work afterwards');
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// Proves with the real prepare(): between the first and the last of a send preparation's own calls no background call
// starts, and the background call that waited runs after the last one. The first call is gated, a Messages-style
// background entry is enqueued while it runs, then the gate opens. Three variants: a NODUS send, a send to a chain name
// (the lookup is the first call) and a token send. Falsely passes if the background entry never ran: its marker must be
// present, after the end marker. Base: FIFO runs the background entry right after the first call.
async function prepareOrdering({ setup, gated, end, to, symbol, asset, amount }) {
  const { mock, client } = await readyClient(setup);
  const open = mock.gate(gated);
  const preparing = prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol, asset, to, amount });
  await until(() => mock.log.includes(`${gated}:start`), `${gated} started`);
  assert.equal(mock.log.at(-1), `${gated}:start`, 'only the gated call is running');
  const background = client.connect(async () => { mock.log.push('background:run'); return {}; });
  open();
  const transfer = await preparing; await background;
  const from = mock.log.indexOf(`${gated}:end`), to2 = mock.log.indexOf(end);
  assert.ok(from >= 0 && to2 > from, 'the first and the last call of the preparation are in the log');
  assert.ok(!mock.log.slice(from, to2).includes('connect:start'), 'no background call between the first and the last call');
  assert.ok(mock.log.indexOf('background:run') > to2, 'the background call ran after the last call');
  assert.equal(mock.state.overlap, false);
  transfer.cancel(); client.lock();
}
test('Q5a: a NODUS send preparation runs its calls back to back, a waiting background call after them', OPTIONS, () =>
  prepareOrdering({ gated: 'balance', end: 'buildAndSign:end', symbol: 'NODUS', asset: NODUS_NATIVE, to: RECIPIENT, amount: '1' }));
test('Q5b: a send to a chain name runs the lookup and the rest back to back', OPTIONS, () =>
  prepareOrdering({ setup: state => { state.names = { alice: RECIPIENT }; }, gated: 'nameLookup', end: 'buildAndSign:end', symbol: 'NODUS', asset: NODUS_NATIVE, to: 'alice', amount: '1' }));
test('Q5c: a token send preparation runs its calls back to back', OPTIONS, () =>
  prepareOrdering({
    setup: state => {
      state.pins = [TUSDT];
      state.tokenBalances = [{ tokenId: TUSDT_ID, total: '5000000', spendable: '5000000' }];
      state.tokenCoins = [tokenCoin(7, '3000000'), tokenCoin(8, '2000000')];
      state.tokenListing = [{ tokenId: TUSDT_ID, listed: true, truncated: false }];
    },
    gated: 'balance', end: 'tokenBuildAndSign:end', symbol: 'tUSDT', asset: { chain: 'nodus', tokenId: TUSDT_ID }, to: RECIPIENT, amount: '2.5'
  }));

// Proves: the review's submit goes through the ended view, so it is user class: with a background entry (addrHistory)
// waiting ahead of it and a background call (scanConfirm) in flight, the submit runs first. The submit is enqueued
// before the gate opens (asserted by the log: nothing but the gated call has started). Falsely passes if the submit
// was enqueued only after the gate opened: guarded by the settle before open() and the single-entry log check.
// Base: FIFO runs addrHistory before the submit.
test('Q6: a prepared review\'s submit is user class even after its flow ended', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  const transfer = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', asset: NODUS_NATIVE, to: RECIPIENT, amount: '1' });
  const base = mock.log.length, open = mock.gate('scanConfirm');
  const scanning = client.scanConfirm({ intentId: INTENT_ID, fromHeight: '1001', toHeight: '1090' });
  await settle();
  assert.deepEqual(mock.log.slice(base), ['scanConfirm:start'], 'only the gated call is running');
  const history = client.addrHistory();
  const confirming = transfer.confirm(async () => {});
  await settle();
  assert.deepEqual(mock.log.slice(base), ['scanConfirm:start'], 'the submit and addrHistory are waiting');
  open();
  await Promise.all([scanning, history, confirming]);
  assert.deepEqual(starts(mock, base), ['scanConfirm', 'submit', 'addrHistory']);
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// Proves: lock() during a flow rejects the call in flight, a waiting user entry and a waiting background entry with
// "locked", starts none of the queued ones, keeps the lock order (cancel, lock, release) and the memory wipe, and the
// flow rejects; afterwards userFlow still calls its work, inside which view calls refuse exactly as the client's own
// calls do and the site signature refuses "locked". Falsely passes if lock() rejected only some entries: every one is
// asserted. Base: userFlow is missing.
test('Q7: lock during a flow rejects everything in the queue in today\'s order; userFlow after lock calls its work', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  mock.gate('balance'); // never opened: the call stays suspended
  let inFlight, userWaiting;
  const flow = client.userFlow(async view => { inFlight = view.balance(); userWaiting = view.rulesetInfo(); await inFlight; });
  const backgroundWaiting = client.list();
  await settle();
  const before = mock.log.length;
  client.lock();
  await Promise.all([assert.rejects(inFlight, /locked/), assert.rejects(userWaiting, /locked/), assert.rejects(backgroundWaiting, /locked/), assert.rejects(flow, /locked/)]);
  assert.deepEqual(mock.log.slice(before), ['cancel', 'lock', 'release']);
  assert.equal(mock.state.zeroAtRelease, true);
  assert.ok(!mock.log.includes('rulesetInfo:start') && !mock.log.includes('list:start'), 'a queued call never reaches the module');
  let seen = false;
  await assert.rejects(client.userFlow(async view => {
    seen = true;
    const viewError = await view.list().then(() => undefined, error => error), clientError = await client.list().then(() => undefined, error => error);
    assert.match(viewError?.message ?? '', /not ready/);
    assert.equal(viewError.message, clientError.message, 'the view refuses with the client\'s own text');
    await assert.rejects(view.siteSignMessage({ origin: 'https://site.example', message: new Uint8Array([1]) }), /locked/i);
    throw new Error('work error');
  }), /work error/);
  assert.ok(seen, 'userFlow called its work on a locked client');
  assert.deepEqual(mock.log.slice(before), ['cancel', 'lock', 'release'], 'no further module call');
});

// Proves: a user entry aborted while waiting never enters the module; an entry aborted after it started finishes and
// resolves; and after an abort the runner never stops while a live entry that may start is waiting: (a) an aborted user
// head with a live user entry behind it, (b) an aborted background head with a live background entry behind it, (c) an
// aborted user head with a live background entry waiting, no lease open. After the abort nothing is enqueued, no timer
// is called and no lease opens or closes: only the in-flight call returns (the gate opens), so the live entry cannot
// have been started by a later trigger of the test. Falsely passes if the live entry were started by the test's own
// action: the only action after the abort is the gate opening, which is the end of the call in flight.
// Base: userFlow is missing.
test('Q8: an aborted waiting entry never runs; a started one finishes; an aborted head never stalls a live entry', OPTIONS, async () => {
  {
    const { mock, client } = await readyClient();
    const closed = await closedView(client);
    const open = mock.gate('balance'), running = client.balance();
    await settle();
    const controller = new AbortController(), aborted = closed.list({ signal: controller.signal });
    controller.abort();
    await assert.rejects(aborted, /cancelled/);
    open(); await running; await settle();
    assert.ok(!mock.log.includes('list:start'), 'an entry aborted while waiting never enters the module');
    // aborted after its start: finishes and resolves
    const open2 = mock.gate('balance'), second = new AbortController(), started = closed.balance({ signal: second.signal });
    await until(() => mock.log.filter(entry => entry === 'balance:start').length === 2, 'the second balance started');
    second.abort(); open2();
    assert.ok((await started).total, 'a started call finishes and resolves');
    assert.equal(mock.state.overlap, false);
    client.lock();
  }
  for (const [label, headUser, liveUser] of [['a', true, true], ['b', false, false], ['c', true, false]]) {
    const { mock, client } = await readyClient();
    const closed = await closedView(client), pick = user => (user ? closed : client);
    const open = mock.gate('balance'), running = client.balance();
    await settle();
    const controller = new AbortController();
    const head = pick(headUser).list({ signal: controller.signal });
    const live = pick(liveUser).rulesetInfo();
    controller.abort();
    await assert.rejects(head, /cancelled/);
    open(); await running;
    await until(() => mock.log.includes('rulesetInfo:end'), `case ${label}: the live entry started`);
    await live;
    assert.ok(!mock.log.includes('list:start'), `case ${label}: the aborted head never ran`);
    assert.equal(mock.state.overlap, false);
    client.lock();
  }
});

// Proves: the keepalive tick is user class. Inside a flow a tick that comes due between two steps runs between them,
// in enqueue order, once (two timer calls coalesce); with a gated call in flight, a waiting user entry and then a timer
// tick, the order is the enqueue order: balance, list, tick. Falsely passes if the tick ran before rulesetInfo only
// because rulesetInfo was enqueued late: the tick's position between the two step markers is asserted and the timer
// is called before rulesetInfo is enqueued. Base: userFlow is missing.
test('Q9: the keepalive tick is user class and keeps enqueue order', OPTIONS, async () => {
  {
    const { mock, client, timers } = await readyClient();
    const base = mock.log.length;
    await client.userFlow(async view => { await view.balance(); timers.fn(); timers.fn(); await view.rulesetInfo(); });
    await settle();
    assert.deepEqual(starts(mock, base), ['balance', 'tick', 'rulesetInfo']);
    assert.equal(mock.state.overlap, false);
    client.lock();
  }
  {
    const { mock, client, timers } = await readyClient();
    const closed = await closedView(client);
    const base = mock.log.length, open = mock.gate('balance');
    const inFlight = closed.balance(), waiting = closed.list();
    await settle();
    assert.deepEqual(mock.log.slice(base), ['balance:start']);
    timers.fn();
    open();
    await Promise.all([inFlight, waiting]); await settle();
    assert.deepEqual(starts(mock, base), ['balance', 'list', 'tick']);
    assert.equal(mock.state.overlap, false);
    client.lock();
  }
});

// Proves: a view is the client's full operation surface without the four connection operations, and the getters of
// both stay live. Falsely passes if the keys match while an operation is untagged: Q5 and Q6 and the extension tests
// cover every operation the flows use behaviourally. Base: userFlow is missing.
test('Q10: a view has the whole surface except the connection operations; getters stay live', OPTIONS, async () => {
  const { client } = await readyClient();
  let view;
  await client.userFlow(opened => { view = opened; });
  const absent = ['unlock', 'identify', 'connectNetwork', 'checkLiveness'];
  assert.deepEqual(Object.keys(view).sort(), Object.keys(client).filter(key => !absent.includes(key)).sort());
  for (const key of absent) assert.equal(typeof view[key], 'undefined', key);
  assert.equal(typeof view.userFlow, 'function'); assert.equal(typeof view.lock, 'function');
  assert.equal(client.state, 'ready'); assert.equal(view.state, 'ready');
  client.lock();
  assert.equal(client.state, 'locked'); assert.equal(view.state, 'locked');
});

// Proves: a flow can open a flow on its view; background work waits until the outer flow ends, not only the inner one.
// Falsely passes if the background call never started before the end for another reason: its start is asserted after
// the flow. Base: userFlow is missing.
test('Q11: nested flows: background work waits for the outer flow', OPTIONS, async () => {
  const { mock, client } = await readyClient();
  const base = mock.log.length;
  let background;
  await client.userFlow(async outer => {
    background = client.list();
    await outer.userFlow(async inner => { await inner.balance(); });
    await settle();
    assert.ok(!mock.log.slice(base).includes('list:start'), 'the inner flow ended, the outer one is still open');
    await outer.rulesetInfo();
  });
  await background;
  assert.deepEqual(starts(mock, base), ['balance', 'rulesetInfo', 'list']);
  assert.equal(mock.state.overlap, false);
  client.lock();
});

// A module whose balance refuses with the session-lost text until its tick has run, as a module that lost its session
// and reconnects only inside its tick; it records its call order. `list` can be held.
function lostSessionModule() {
  const calls = [], hold = { release: undefined };
  let ticked = false;
  const gate = new Promise(resolve => { hold.release = resolve; });
  const module = {
    async unlock() { return { fingerprint: FINGERPRINT, chainId: '56'.repeat(32) }; },
    async balance() { calls.push('balance'); if (!ticked) throw new Error(NODUS_SESSION_LOST_TEXT); return { total: '0', spendable: '0' }; },
    async list() { calls.push('list'); await gate; return { tip: '1', coins: [] }; },
    async tick() { calls.push('tick'); ticked = true; },
    async buildAndSign() {}, async submit() {}, async scanConfirm() {},
    async rulesetInfo() { return { generation: '1', tip: '1', gen2Height: '0' }; },
    cancel() {}, lock() {}, release() {}, memory: { buffer: new ArrayBuffer(64) }
  };
  return { module, calls, hold };
}
async function lostSessionClient() {
  const parts = lostSessionModule(), timers = {};
  const client = createNodusClient({ factory: async () => parts.module, setInterval: fn => { timers.fn = fn; return 1; }, clearInterval() {} });
  await client.unlock({ seed: new Uint8Array(32), fingerprint: FINGERPRINT });
  return { ...parts, client, timers };
}
// Proves the order in which a dropped session is restored: with a call in flight and a keepalive tick waiting behind
// it, a flow started meanwhile runs after the tick (user class, enqueue order), so its first network call finds the
// session the tick restored and the client stays ready. The control (no tick waiting) shows that this module's
// balance depends on the tick: the flow rejects with the session-lost text and the client goes to 'error'. A later
// change that moves the tick out of the user class makes the first part fail. Base: userFlow is missing.
test('Q12: a waiting keepalive runs before a flow started after it; without it the flow finds the lost session', OPTIONS, async () => {
  const { calls, hold, client, timers } = await lostSessionClient();
  const listing = client.list();
  await settle();
  assert.deepEqual(calls, ['list']);
  timers.fn();
  const flow = client.userFlow(view => view.balance());
  hold.release();
  await listing;
  assert.deepEqual(await flow, { total: '0', spendable: '0' });
  assert.deepEqual(calls, ['list', 'tick', 'balance']);
  assert.equal(client.state, 'ready');
  client.lock();
  const control = await lostSessionClient();
  await assert.rejects(control.client.userFlow(view => view.balance()), error => error.message === NODUS_SESSION_LOST_TEXT);
  assert.equal(control.client.state, 'error');
  assert.deepEqual(control.calls, ['balance']);
  control.client.lock();
});

// Proves: the runner writes one `nodus-queue start` and one `nodus-queue end` line per entry that runs, with the class
// word, the number of open flows (start) and the duration and outcome (end), and no argument, seed or secret reaches a
// line. The sink is installed before the client is built, so the unlock entry's line must exist; each test of this
// file restores its own sink and node:test runs the tests of one file one after another, so no foreign lines
// interleave. Falsely passes if the sink was installed late (guarded by the unlock line) or the pattern is loose (each
// line is matched whole). Base: writes no `nodus-queue` line.
test('Q13: the runner writes a start and an end line per entry, with class, flows and outcome, and no arguments', OPTIONS, async () => {
  const lines = [], restore = setDebugLogSink(line => lines.push(line));
  try {
    const { mock, client } = await readyClient();
    await client.list();
    await client.userFlow(view => view.balance());
    const queue = () => lines.filter(line => line.includes(' nodus-queue '));
    assert.ok(queue().some(line => /^nodus-debug \S+ nodus-queue start op=unlock class=other /.test(line)), 'the unlock entry wrote its line');
    const own = queue().filter(line => !line.includes(' op=unlock '));
    const number = '[0-9]+(?:\\.[0-9]+)?';
    const expected = [
      new RegExp(`^nodus-debug \\S+ nodus-queue start op=list class=other waited=${number} flows=0$`),
      new RegExp(`^nodus-debug \\S+ nodus-queue end op=list class=other ms=${number} outcome=ok$`),
      new RegExp(`^nodus-debug \\S+ nodus-queue start op=balance class=user waited=${number} flows=1$`),
      new RegExp(`^nodus-debug \\S+ nodus-queue end op=balance class=user ms=${number} outcome=ok$`)
    ];
    assert.equal(own.length, 4, own.join('\n'));
    expected.forEach((pattern, index) => assert.match(own[index], pattern));
    mock.state.busy.add('list');
    await assert.rejects(client.list());
    const failed = queue().filter(line => line.includes(' nodus-queue end op=list '));
    assert.match(failed.at(-1), /outcome=error/);
    for (const line of queue()) assert.ok(!/ args=/.test(line), line);
    assert.ok(!queue().join('\n').includes('05'.repeat(32)), 'the seed never reaches a line');
    client.lock();
  } finally { restore(); }
});

// Proves: a resume check's fresh keepalive tick and a timer tick that comes due meanwhile are one queue entry, whether
// the fresh tick is waiting (1) or running (3); the bookkeeping is released afterwards (2): a fix that left it set
// would silence every later keepalive; the resume check still resolves 'ok'. Falsely passes if the gate did not hold
// balance (guarded: balance:start is the last log entry before the check), if an earlier timer tick had set the
// bookkeeping (guarded: no tick:start and no timer call before the check), or if the timer's guard skipped because the
// state was not 'ready' (guarded: asserted before the timer call); the mock logs every tick, so a count of 1 is a count.
// The resume check's watchdog uses the client's default timer and clears it when the check settles. Base: case (1) gives
// two tick:start, the timer tick being enqueued behind the fresh one.
test('Q14: a resume check\'s fresh tick and a timer tick are one entry, waiting or running; the bookkeeping is released', OPTIONS, async () => {
  const { mock, client, timers } = await readyClient();
  const ticks = () => mock.log.filter(entry => entry === 'tick:start').length;
  try {
    // (1) the fresh tick waits behind a call in flight
    const open = mock.gate('balance'), held = client.balance();
    await settle();
    assert.equal(mock.log.at(-1), 'balance:start');
    assert.equal(ticks(), 0);
    const check = client.checkLiveness();
    await settle();
    assert.equal(client.state, 'ready');
    timers.fn();
    open(); await held;
    assert.equal(await check, 'ok');
    await settle(); await settle();
    assert.equal(ticks(), 1, 'one tick for the resume check and the timer together');
    // (2) the bookkeeping is released: the next timer tick runs
    timers.fn(); await settle();
    assert.equal(ticks(), 2);
    // (3) the fresh tick is running when the timer fires
    const openTick = mock.gate('tick'), second = client.checkLiveness();
    await settle();
    assert.equal(mock.log.at(-1), 'tick:start');
    timers.fn();
    openTick();
    assert.equal(await second, 'ok');
    await settle();
    assert.equal(ticks(), 3);
    assert.equal(mock.state.overlap, false);
  } finally { client.lock(); }
});
