import test from 'node:test';
import assert from 'node:assert/strict';
import { createGateway, UPSTREAM } from '../server/cpunk-gateway.js';
import { readCpunk } from '../src/adapters/cpunk.js';
import { boundedJson, cpunkQuery, CPUNK_PATH } from '../src/cpunk-protocol.js';
const address = 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps';
async function gateway(t, options) {
  const server = createGateway(options);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, send: (body, extra = {}) => fetch(origin + CPUNK_PATH, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), ...extra }) };
}
test('browser default route traverses gateway and fixed upstream', async t => {
  let calls = 0;
  const { origin } = await gateway(t, { fetcher: async (url, options) => {
    calls++; assert.equal(url, UPSTREAM); assert.equal(options.redirect, 'error');
    assert.deepEqual(JSON.parse(options.body), cpunkQuery(address));
    assert.equal(options.headers.Authorization, undefined);
    return Response.json({ result: [[{ token: 'CPUNK', balance: '0.000000000000000001' }]] });
  } });
  const result = await readCpunk({ address, endpoint: CPUNK_PATH, fetcher: (path, options) => fetch(origin + path, options) });
  assert.equal(result.balance, '0.000000000000000001'); assert.equal(calls, 1);
});
test('gateway rejects arbitrary methods, URLs, fields, addresses and oversized input', async t => {
  let calls = 0;
  const { send, origin } = await gateway(t, { fetcher: async () => { calls++; throw Error('unexpected'); } });
  for (const body of [{ address, upstream: 'http://localhost/' }, { method: 'tx_create' }, { address: 123 }, { address: 'a'.repeat(99) }, [address], null]) assert.equal((await send(body)).status, 400);
  assert.equal((await send({ address: 'a'.repeat(600) })).status, 413);
  assert.equal((await send({ address }, { headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await send({ address }, { headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await fetch(origin + CPUNK_PATH)).status, 405);
  assert.equal((await fetch(origin + CPUNK_PATH + '?upstream=other')).status, 404);
  assert.equal(calls, 0);
});
test('upstream errors and invalid replies never become balances', async t => {
  let response;
  const { send } = await gateway(t, { fetcher: async () => response.clone() });
  for (const body of [{}, { result: [] }, { result: [[{ token: 'CELL', balance: '0' }]] }, { id: 99, result: [[{ balance: '0' }]] }, { error: {}, result: [[{ balance: '0' }]] }]) {
    response = Response.json(body); assert.equal((await send({ address })).status, 502);
  }
  for (const item of [new Response('bad', { status: 503 }), new Response('<html>Oops</html>'), new Response('{', { headers: { 'Content-Type': 'application/json' } }), Response.json({ result: [[{ balance: '0' }]], padding: 'x'.repeat(70000) }), new Response('', { status: 302, headers: { Location: 'http://localhost' } })]) {
    response = item; const result = await send({ address }); assert.equal(result.status, 502); assert.equal((await result.json()).result, undefined);
  }
  response = Response.json({ result: [[{ balance: '0' }]] });
  const result = await send({ address }); assert.equal(result.status, 200); assert.equal(result.headers.get('cache-control'), 'no-store'); assert.equal(result.headers.get('access-control-allow-origin'), null);
});
test('timeout covers upstream body; browser cancellation propagates', async t => {
  const { send } = await gateway(t, { timeoutMs: 20, fetcher: async (_, { signal }) => new Response(new ReadableStream({ start(controller) { signal.addEventListener('abort', () => controller.error(new Error('timeout')), { once: true }); } }), { headers: { 'Content-Type': 'application/json' } }) });
  assert.equal((await send({ address })).status, 504);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(readCpunk({ address, signal: controller.signal, fetcher: async (_, options) => { options.signal.throwIfAborted(); } }), /cancelled/);
});
test('stream cap works without Content-Length and cancels the stream', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(40000)); }, cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } });
  await assert.rejects(boundedJson(response), /too large/); assert.equal(cancelled, true);
});

test('observed live token schema selects CPUNK only and checks exact unit consistency', async () => {
  const live = { id: 1, result: [[{ addr: address, network: 'Backbone', tokens: [{ token: { ticker: 'CELL' }, coins: '0.015', datoshi: '15000000000000000' }, { token: { ticker: 'CPUNK' }, coins: '0.00000000000000001', datoshi: '10' }] }]] };
  const read = body => readCpunk({ address, fetcher: async url => { assert.equal(url, 'https://rpc.cellframe.net/connect'); return Response.json(body); } });
  assert.equal((await read(live)).balance, '0.00000000000000001');
  for (const change of [x => x.result[0][0].addr = 'other', x => x.result[0][0].network = 'other', x => x.result[0][0].tokens.pop(), x => x.result[0][0].tokens[1].datoshi = '11', x => x.result[0][0].tokens.push(x.result[0][0].tokens[1])]) {
    const changed = structuredClone(live); change(changed); await assert.rejects(read(changed));
  }
});
