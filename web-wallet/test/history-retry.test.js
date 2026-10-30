// Node >=22.14, no flags/network/artifacts. Mock fetch responses and timers
// exercise the real request/transport/history path. These checks do not prove
// live CORS/header exposure or browser rendering; every held read is released.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readHistory, HistoryUnavailable } from '../src/history.js';
import { request } from '../src/core.js';
import { CHAINS } from '../src/config.js';

const address = '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb';
const limited = 'The history provider is limiting requests right now. Try again in a few minutes.';
const ok = () => Response.json({ status: '1', result: [] });
const refusal = reset => new Response('Too many requests', { status: 429,
  headers: reset === null ? {} : { 'x-ratelimit-reset': reset } });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('request preserves the HTTP status and provider reset without retrying itself', async () => {
  let calls = 0;
  await assert.rejects(request('https://eth.blockscout.com/api', undefined, { fetcher: async () => { calls++; return refusal('42766'); } }),
    error => error.status === 429 && error.rateLimitReset === '42766' && /HTTP 429/.test(error.message));
  assert.equal(calls, 1);
});

test('429 waits the reset milliseconds, counts down, and resumes only the failed token request', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  const urls = [], statuses = [], waiting = deferred();
  t.mock.method(globalThis, 'fetch', async url => {
    urls.push(url);
    if (urls.length === 2) return refusal('2500');
    if (urls.length === 1) return Response.json({ status: '1', result: [{
      hash: '0x' + 'ab'.repeat(32), timeStamp: '1790000000', from: '0x' + '12'.repeat(20),
      to: address.toLowerCase(), value: '1000000000000000000', isError: '0',
    }] });
    return ok();
  });
  const reading = readHistory('ethereum', address, { onStatus: text => { statuses.push(text); if (text) waiting.resolve(); } });
  await waiting.promise;
  assert.equal(urls.length, 2);
  assert.equal(statuses.at(-1), 'Waiting for the provider, retrying in 3 seconds.');
  t.mock.timers.tick(1000);
  assert.equal(statuses.at(-1), 'Waiting for the provider, retrying in 2 seconds.');
  t.mock.timers.tick(1499);
  assert.equal(urls.length, 2, 'no request before the provider reset');
  assert.equal(statuses.at(-1), 'Waiting for the provider, retrying in 1 second.');
  t.mock.timers.tick(1);
  const rows = await reading;
  assert.equal(rows.length, 1, 'native result survives a later token refusal');
  assert.equal(rows[0].amount, '1.0');
  assert.equal(urls.length, 2 + CHAINS.ethereum.tokens.length);
  assert.equal(urls[1], urls[2], 'retry the same token URL');
  assert.equal(urls.filter(url => new URL(url).searchParams.get('action') === 'txlist').length, 1);
  assert.equal(statuses.at(-1), '');
});

test('persistent refusals stop after three retries with the existing message', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  let calls = 0, waiting = deferred();
  t.mock.method(globalThis, 'fetch', async () => { calls++; return refusal('1000'); });
  const reading = readHistory('ethereum', address, { onStatus: text => { if (text) waiting.resolve(); } });
  const rejected = assert.rejects(reading, error => error instanceof HistoryUnavailable && error.message === limited);
  for (let retry = 0; retry < 3; retry++) {
    await waiting.promise;
    assert.equal(calls, retry + 1);
    waiting = deferred();
    t.mock.timers.tick(1000);
  }
  await rejected;
  assert.equal(calls, 4);
});

test('a reset beyond the two-minute read deadline is refused without an early retry', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; return refusal('120001'); });
  await assert.rejects(readHistory('ethereum', address), { message: limited });
  assert.equal(calls, 1);
});

test('the two-minute deadline ends a stalled read without inventing a rate-limit response', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  const started = deferred();
  t.mock.method(globalThis, 'fetch', async (_url, { signal }) => {
    started.resolve();
    return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
  });
  const rejected = assert.rejects(readHistory('ethereum', address), { message: 'History could not be read right now. Try again later.' });
  await started.promise;
  t.mock.timers.tick(120000);
  await rejected;
});

test('the deadline is shared across reset waits, not restarted for each refusal', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  const waiting = deferred();
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; return refusal('70000'); });
  const rejected = assert.rejects(readHistory('ethereum', address, { onStatus: text => { if (text) waiting.resolve(); } }), { message: limited });
  await waiting.promise;
  t.mock.timers.tick(70000);
  await rejected;
  assert.equal(calls, 2, 'a second 70-second wait would exceed the whole-read bound');
});

test('successful token requests do not reset the whole-read retry count', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  const perUrl = new Map();
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async url => {
    calls++;
    const attempt = (perUrl.get(url) ?? 0) + 1; perUrl.set(url, attempt);
    return attempt === 1 ? refusal('0') : ok();
  });
  await assert.rejects(readHistory('ethereum', address), { message: limited });
  assert.equal(calls, 7);
  assert.deepEqual([...perUrl.values()], [2, 2, 2, 1]);
});

test('missing or invalid resets do not invent a delay or retry; zero resets remain bounded', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  for (const reset of [null, '', '-1', 'later', '1.5', 'Infinity', '9007199254740992', '0']) {
    let calls = 0;
    const fetchMock = t.mock.method(globalThis, 'fetch', async () => { calls++; return refusal(reset); });
    await assert.rejects(readHistory('ethereum', address), { message: limited });
    assert.equal(calls, reset === '0' ? 4 : 1, `reset ${reset}`);
    fetchMock.mock.restore();
  }
});

test('cancelling a countdown clears the wait and releases the provider queue', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  const waiting = deferred(), controller = new AbortController(), statuses = [];
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; return calls === 1 ? refusal('42766') : ok(); });
  const reading = readHistory('ethereum', address, { signal: controller.signal,
    onStatus: text => { statuses.push(text); if (text) waiting.resolve(); } });
  const rejected = assert.rejects(reading, { message: 'History read cancelled.' });
  await waiting.promise;
  controller.abort();
  await rejected;
  const count = statuses.length;
  t.mock.timers.tick(42766);
  assert.equal(calls, 1);
  assert.equal(statuses.length, count, 'cancelled countdown emits nothing later');
  assert.deepEqual(await readHistory('ethereum', address), []);
});

test('concurrent Ethereum reads keep one Blockscout request in flight', async t => {
  const started = deferred(), release = deferred();
  let calls = 0, active = 0, maximum = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    calls++; active++; maximum = Math.max(maximum, active);
    try { if (calls === 1) { started.resolve(); await release.promise; } return ok(); }
    finally { active--; }
  });
  const first = readHistory('ethereum', address);
  await started.promise;
  const second = readHistory('ethereum', address);
  release.resolve();
  await Promise.all([first, second]);
  assert.equal(maximum, 1);
  assert.equal(calls, 2 * (1 + CHAINS.ethereum.tokens.length));
});

test('another Ethereum read cannot bypass an active provider countdown', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100_000 });
  const waiting = deferred(), secondStarted = deferred();
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async url => {
    calls++;
    if (new URL(url).searchParams.get('address') !== address.toLowerCase()) secondStarted.resolve();
    return calls === 1 ? refusal('1000') : ok();
  });
  const first = readHistory('ethereum', address, { onStatus: text => { if (text) waiting.resolve(); } });
  await waiting.promise;
  const second = readHistory('ethereum', '0x' + '12'.repeat(20));
  // Drain the already queued microtasks without advancing the fake clock.
  await Promise.resolve(); await Promise.resolve();
  assert.equal(calls, 1);
  t.mock.timers.tick(1000);
  await Promise.all([first, second, secondStarted.promise]);
  assert.equal(calls, 3 + 2 * CHAINS.ethereum.tokens.length);
});

test('429 from another history provider is not retried', async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; return refusal('1000'); });
  await assert.rejects(readHistory('tron', 'TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7'), { message: limited });
  assert.equal(calls, 1);
});
