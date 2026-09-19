import test from 'node:test';
import assert from 'node:assert/strict';
import { readCpunk } from '../src/adapters/cpunk.js';
import { boundedJson, cpunkQuery, CPUNK_ENDPOINT } from '../src/cpunk-protocol.js';
const address = 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps';
test('default and custom HTTPS reads query Cellframe directly with only public data', async () => {
  let calls = 0;
  for (const endpoint of ['', 'https://rpc.example/connect']) {
    const result = await readCpunk({ address, endpoint, fetcher: async (url, options) => {
      calls++; assert.equal(url, endpoint || CPUNK_ENDPOINT); assert.equal(options.redirect, 'error');
      assert.equal(options.credentials, 'omit'); assert.equal(options.referrerPolicy, 'no-referrer'); assert.equal(options.cache, 'no-store');
      assert.deepEqual(JSON.parse(options.body), cpunkQuery(address));
      assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
      return Response.json({ result: [[{ token: 'CPUNK', balance: '0.000000000000000001' }]] });
    } });
    assert.equal(result.balance, '0.000000000000000001');
  }
  assert.equal(calls, 2);
});
test('invalid addresses and non-HTTPS or credential-bearing endpoints fail before fetch', async () => {
  let calls = 0;
  const fetcher = async () => { calls++; throw Error('unexpected'); };
  for (const badAddress of [123, 'a'.repeat(99), 'a'.repeat(600), [address], null]) await assert.rejects(readCpunk({ address: badAddress, fetcher }), /public address/);
  for (const endpoint of ['/api/cpunk/balance', 'http://localhost/', 'https://user:password@rpc.example/', 'https://rpc.example/#fragment']) await assert.rejects(readCpunk({ address, endpoint, fetcher }), /HTTPS/);
  assert.equal(calls, 0);
});
test('direct RPC errors and invalid replies never become balances', async () => {
  const read = response => readCpunk({ address, fetcher: async () => response });
  for (const body of [{}, { result: [] }, { result: [[{ token: 'CELL', balance: '0' }]] }, { id: 99, result: [[{ balance: '0' }]] }, { error: {}, result: [[{ balance: '0' }]] }]) {
    await assert.rejects(read(Response.json(body)));
  }
  for (const item of [new Response('bad', { status: 503 }), new Response('<html>Oops</html>'), new Response('{', { headers: { 'Content-Type': 'application/json' } }), Response.json({ result: [[{ balance: '0' }]], padding: 'x'.repeat(70000) }), new Response('', { status: 302, headers: { Location: 'http://localhost' } })]) {
    await assert.rejects(read(item));
  }
  assert.equal((await read(Response.json({ result: [[{ balance: '0' }]] }))).balance, '0');
});
test('browser cancellation propagates before fetch and while reading the RPC body', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(readCpunk({ address, signal: controller.signal, fetcher: async (_, options) => { options.signal.throwIfAborted(); } }), /cancelled/);
  const pending = new AbortController();
  await assert.rejects(readCpunk({ address, signal: pending.signal, fetcher: async (_, { signal }) => {
    const response = new Response(new ReadableStream({ start(stream) { signal.addEventListener('abort', () => stream.error(new Error('aborted')), { once: true }); } }), { headers: { 'Content-Type': 'application/json' } });
    setTimeout(() => pending.abort(), 20);
    return response;
  } }), /cancelled/);
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
