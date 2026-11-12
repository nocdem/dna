// Tests of the page's diagnostic log (log.js) and of the log lines the flow and the bot client write
// (operator 2026-11-12: full diagnostic logging for debugging).
//
// PROVES:
//   - a line is "[swap-site] <ISO time> <area> <event> name=value ..." with the time and the duration injected;
//     failures go to the sink's warn, the rest to info;
//   - only named plain values are written: an absent field is skipped, an object or function is not printed, a long
//     string is cut, and a field named like a signature or key is replaced;
//   - one swap success, one delivered failure and one follow write the expected events with the expected field names
//     (a captured logger stands in for the console);
//   - a logger that throws on every call (info, warn and timer) changes no flow result and no bot client result.
// ENVIRONMENT: node >= 20, `node --test website/swap-site/test/`; no browser, no network, no environment variables.
// LEAVES BEHIND: nothing.
// FALSE PASS: the captured logger records the (area, event, fields) the modules pass, so a field name checked here is
//   proved to be passed, not that the real console prints it; the page's own lines (swap.js: clicks, busy, page load)
//   and the extension's lines (extension.js) are DOM or browser bound and are not exercised. The throwing-logger test
//   compares results of two runs on the same stubs, so a result that depends on the clock would fail it falsely.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createLogger, formatFields, errorFields, guardLog, LOG_PREFIX } from '../log.js';
import { createSwapFlow } from '../flow.js';
import { createBotClient, BOT_ORIGIN } from '../bot.js';
import { AdapterError } from '../adapter.js';

const ETH = `0x${'4b'.repeat(20)}`;
const NODUS_ADDR = 'ab'.repeat(64);
const ACCOUNTS = { nodus: { address: NODUS_ADDR, publicKey: `0x${'cd'.repeat(2592)}` }, ethereum: ETH };
const TOKEN = `0x${'a7'.repeat(20)}`;
const STATUS = {
  swapsPaused: false, liquidityPaused: false, payoutsPaused: false, stopped: false,
  reserves: { nodus: '3000000000000000', usdt: '3000000000' },
  settings: { swapMinUsdt: '1000000', swapMaxUsdt: '100000000', commission: '0', ethChainId: '11155111' },
  foundationNodus: 'fd'.repeat(64), nodusChainId: '5c'.repeat(32),
};
const QUOTE = {
  approved: true, direction: 'usdt_to_nodus', amount: '100000000', number: '124860000000', estimatedFee: '1000000',
  requestNumber: '4242', validUntil: '1700000300', payTo: `0x${'fe'.repeat(20)}`,
};

// A captured logger: every call is kept as { level, area, event, fields }; timer() always reads 7 ms.
function capture() {
  const events = [];
  const rec = level => (area, event, fields) => events.push({ level, area, event, fields });
  return { events, info: rec('info'), warn: rec('warn'), timer: () => () => 7 };
}
const thrower = { info() { throw new Error('log sink broke'); }, warn() { throw new Error('log sink broke'); }, timer() { throw new Error('log sink broke'); } };

function stubFetch(routes) {
  return async (fullUrl, init = {}) => {
    const key = `${init.method ?? 'GET'} ${fullUrl.slice(BOT_ORIGIN.length)}`;
    let hit = routes[key] ?? routes[`${init.method ?? 'GET'} ${fullUrl.slice(BOT_ORIGIN.length).replace(/\/amm\/swap\/.*/, '/amm/swap/*')}`];
    if (hit === undefined) throw new Error(`no route for ${key}`);
    return { status: hit[0], json: async () => hit[1] };
  };
}
function build({ log, adapter, routes = {}, pollMax = 2 }) {
  const fetch = stubFetch({ 'GET /amm/status': [200, STATUS], 'POST /amm/quote': [200, QUOTE], 'GET /amm/swap/*': [200, { requestNumber: '4242', state: 'approved' }], ...routes });
  const flow = createSwapFlow({ bot: createBotClient({ fetch, log }), adapter, botUrl: BOT_ORIGIN, usdtToken: TOKEN, sleep: async () => {}, pollMax, pollIntervalMs: 5000, log });
  flow.setAccounts(ACCOUNTS);
  return flow;
}
const okAdapter = { async usdtToNodus(_i, o) { o.onStep({ id: 'switch' }); o.onStep({ id: 'usdt_windows' }); return { delivered: true }; } };
const deliveredAdapter = { async usdtToNodus() { throw new AdapterError('extension_error', 'x', { delivered: true, paid: false, extensionCode: -32000 }); } };
const names = events => events.map(e => `${e.area}.${e.event}`);

test('a line is prefix, ISO time, area, event and the named fields; failures use warn', () => {
  const out = [];
  const log = createLogger({
    sink: { info: l => out.push(['info', l]), warn: l => out.push(['warn', l]) },
    now: () => new Date('2026-11-12T10:00:00.000Z'), clock: (() => { let t = 100; return () => (t += 12.4); })(),
  });
  const ms = log.timer();
  log.info('bot', 'response', { path: '/status', status: 200, ms: ms() });
  log.warn('adapter', 'call_failed', { code: 'extension_error', delivered: true });
  log.info('page', 'load', {});
  assert.deepEqual(out, [
    ['info', `${LOG_PREFIX} 2026-11-12T10:00:00.000Z bot response path="/status" status=200 ms=12`],
    ['warn', `${LOG_PREFIX} 2026-11-12T10:00:00.000Z adapter call_failed code="extension_error" delivered=true`],
    ['info', `${LOG_PREFIX} 2026-11-12T10:00:00.000Z page load`],
  ]);
});

test('only named plain values are written: absent skipped, objects and signatures never printed, long text cut', () => {
  const err = new Error('boom'); err.code = 'x';
  const text = formatFields({
    a: undefined, b: null, c: 5n, d: { nested: 'object' }, e: () => 1, f: 'y'.repeat(300), g: err,
    signature: `0x${'dead'.repeat(50)}`, publicKey: 'k', mnemonicWords: 'w',
  });
  assert.equal(text.includes('a='), false);
  assert.match(text, /b=null c=5 d="\[not-plain\]" e="\[not-plain\]"/);
  assert.match(text, /f="y{200}…"/);
  assert.match(text, /g="\[not-plain\]"/);                                   // an Error object is never printed (no stack)
  assert.match(text, /signature="\[omitted\]" publicKey="\[omitted\]" mnemonicWords="\[omitted\]"/);
  assert.equal(text.includes('dead'), false);
  assert.deepEqual(Object.keys(errorFields(err)).sort(), ['answered', 'code', 'delivered', 'extensionCode', 'message', 'nodusSent', 'openRequestNumber', 'paid', 'reason']);
});

// PROVES: a swap success writes status, bot request, press, confirm, adapter call and step lines in order, with the
// quote's request number, amount, number, fee and validUntil, the announced step ids and the durations.
test('one swap success: the expected events with their field names', async () => {
  const log = capture();
  const flow = build({ log, adapter: okAdapter });
  await flow.loadStatus();
  await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  const r = await flow.confirm({ toleranceBps: 100 });
  assert.equal(r.ok, true);
  assert.deepEqual(names(log.events), [
    'bot.response', 'status.loaded',
    'flow.press_start', 'bot.response', 'flow.press_result',
    'flow.confirm_start', 'adapter.call_start', 'adapter.step', 'adapter.step', 'adapter.call_end', 'flow.confirm_result',
  ]);
  const by = (area, event) => log.events.filter(e => e.area === area && e.event === event);
  assert.deepEqual(by('bot', 'response')[1].fields, {
    method: 'POST', path: '/quote', status: 200, json: true, approved: true, direction: 'usdt_to_nodus', requestNumber: '4242',
    amount: '100000000', number: '124860000000', estimatedFee: '1000000', validUntil: '1700000300', ms: 7,
  });
  assert.deepEqual(by('flow', 'press_start')[0].fields, { direction: 'usdt_to_nodus', amountText: '100' });
  assert.equal(by('flow', 'press_result')[0].level, 'info');
  assert.deepEqual(by('flow', 'confirm_start')[0].fields, { toleranceBps: 100, requestNumber: '4242', direction: 'usdt_to_nodus' });
  assert.deepEqual(by('adapter', 'step').map(e => e.fields.id), ['switch', 'usdt_windows']);
  assert.deepEqual(by('adapter', 'call_end')[0].fields, { name: 'usdtToNodus', requestNumber: '4242', ms: 7 });
  const result = by('flow', 'confirm_result')[0];
  assert.equal(result.level, 'info');
  assert.equal(result.fields.ok, true); assert.equal(result.fields.requestNumber, '4242');
});

test('one delivered failure: a warn line with the error\'s named fields, then the flow result as a warn', async () => {
  const log = capture();
  const flow = build({ log, adapter: deliveredAdapter });
  await flow.loadStatus(); await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  const r = await flow.confirm({ toleranceBps: 100 });
  assert.equal(r.reason, 'delivered');
  const failed = log.events.find(e => e.event === 'call_failed');
  assert.equal(failed.level, 'warn');
  assert.deepEqual(failed.fields, {
    name: 'usdtToNodus', requestNumber: '4242', code: 'extension_error', extensionCode: -32000, delivered: true, paid: false,
    nodusSent: undefined, reason: undefined, openRequestNumber: undefined, answered: undefined, message: 'x', ms: 7,
  });
  const result = log.events.find(e => e.event === 'confirm_result');
  assert.equal(result.level, 'warn');
  assert.equal(result.fields.reason, 'delivered'); assert.equal(result.fields.delivered, true); assert.equal(result.fields.paid, false);
});

test('one follow: start, each read with request number, poll and state, then the exhaustion warning', async () => {
  const log = capture();
  const flow = build({ log, adapter: okAdapter, pollMax: 2 });
  const r = await flow.follow('4242');
  assert.equal(r.exhausted, true);
  assert.deepEqual(names(log.events), ['follow.start', 'bot.response', 'follow.read', 'bot.response', 'follow.read', 'follow.exhausted']);
  assert.deepEqual(log.events[0].fields, { requestNumber: '4242', pollMax: 2, pollIntervalMs: 5000 });
  assert.deepEqual(log.events[2].fields, { requestNumber: '4242', poll: 1, readable: true, state: 'approved', kind: log.events[2].fields.kind, final: false, ms: 7 });
  assert.equal(log.events[1].fields.state, 'approved');            // the bot line carries the answer's state word
  assert.equal(log.events[5].level, 'warn');
  assert.deepEqual(log.events[5].fields, { requestNumber: '4242', polls: 2, state: 'approved' });
});

test('an unreachable bot is a warn line with no status', async () => {
  const log = capture();
  const bot = createBotClient({ fetch: async () => { throw new TypeError('fetch failed'); }, log });
  assert.deepEqual(await bot.status(), { ok: false, unreachable: true });
  assert.deepEqual(log.events, [{ level: 'warn', area: 'bot', event: 'request_failed', fields: { method: 'GET', path: '/status', unreachable: true, error: 'TypeError', ms: 7 } }]);
});

// PROVES: a logger whose info, warn and timer all throw changes no result: the success, the delivered failure and the
// follow give the same values as a run with no logger, and the bot client still answers.
test('a logger that throws changes no flow or bot result', async () => {
  const run = async (log, adapter) => {
    const flow = build({ log, adapter });
    const status = await flow.loadStatus();
    const pressed = await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
    const confirmed = await flow.confirm({ toleranceBps: 100 });
    const followed = await flow.follow('4242');
    return { status, pressed, confirmed, followed, quote: flow.state.quote };
  };
  for (const adapter of [okAdapter, deliveredAdapter]) {
    const plain = await run(undefined, adapter);
    const noisy = await run(thrower, adapter);
    assert.deepEqual(noisy, plain);
  }
  assert.deepEqual(await createBotClient({ fetch: async () => { throw new Error('x'); }, log: thrower }).status(), { ok: false, unreachable: true });
  assert.doesNotThrow(() => guardLog(thrower).info('a', 'b', {}));
  assert.equal(guardLog(thrower).timer()(), 0);
});

// PROVES: an error whose `answered` and `message` getters throw does not change a flow result: the withdraw signing
// failure, the confirm delivered failure and the adapter failure path return what they return for a plain error of the
// same shape, and the logger still writes its warn line, with "[unreadable]" for the two fields (and the readable ones kept).
// FALSE PASS: the two getters are read only by errorFields on these paths (describeAdapterError reads neither for a
//   delivered:true error); if the flow code started to read them itself, the plain-error comparison would throw in both
//   runs and the test would fail rather than pass. Other properties with throwing getters are not tried.
test('an error with throwing getters changes no flow result and is still logged', async () => {
  const plainErr = () => new AdapterError('extension_error', 'x', { delivered: true, paid: false, extensionCode: 4001, answered: false });
  const hostile = () => {
    const e = plainErr();
    Object.defineProperty(e, 'answered', { get() { throw new Error('getter broke'); } });
    Object.defineProperty(e, 'message', { get() { throw new Error('getter broke'); } });
    return e;
  };
  const confirmRun = async (log, mk) => {
    const flow = build({ log, adapter: { async usdtToNodus() { throw mk(); } } });
    await flow.loadStatus(); await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
    return flow.confirm({ toleranceBps: 100 });
  };
  const withdrawRun = async (log, mk) => {
    const f = createSwapFlow({ bot: createBotClient({ fetch: stubFetch({ 'GET /amm/status': [200, STATUS] }), log }), adapter: okAdapter, botUrl: BOT_ORIGIN, signText: async () => { throw mk(); }, log, random: () => '777' });
    f.setAccounts(ACCOUNTS); await f.loadStatus();
    return f.withdraw({ basisPoints: 100 });
  };
  for (const run of [confirmRun, withdrawRun]) {
    const expected = await run(undefined, plainErr);
    const log = capture();
    const got = await run(log, hostile);
    assert.deepEqual(got, expected);
    const warn = log.events.find(e => e.level === 'warn' && /call_failed|sign_failed/.test(e.event));
    assert.ok(warn, run.name);
    assert.equal(warn.fields.answered, '[unreadable]');
    assert.equal(warn.fields.message, '[unreadable]');
    assert.equal(warn.fields.delivered, true);
    assert.equal(warn.fields.extensionCode, 4001);
  }
  assert.deepEqual(errorFields(null), Object.fromEntries(Object.keys(errorFields({})).map(k => [k, undefined])));
});
