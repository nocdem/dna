import test from 'node:test';
import assert from 'node:assert/strict';
import { rpcFetch } from '../src/rpc-transport.js';

test('public RPC reads are spaced; cancellation makes no request; other RPCs and broadcasts are not queued or retried', async () => {
  const endpoint = 'https://public.rpc.solanavibestation.com';
  const reads = [], calls = [];
  const fetcher = async (url, options) => {
    const method = JSON.parse(options.body).method;
    calls.push({ url, method });
    if (url.startsWith(endpoint) && method.startsWith('get')) reads.push(Date.now());
    return Response.json({ jsonrpc: '2.0', id: 1, result: null }, { status: method === 'sendTransaction' ? 429 : 200 });
  };
  const call = (url, method, signal) => rpcFetch(url, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }), signal }, { fetcher });
  await call(endpoint, 'getGenesisHash');
  const cancel = new AbortController();
  const cancelled = call(endpoint, 'getBalance', cancel.signal);
  const rejected = assert.rejects(cancelled, { name: 'AbortError' });
  cancel.abort(); await rejected;
  const queued = call(endpoint, 'getTokenAccountsByOwner');
  await call('https://rpc.example', 'getBalance');
  const broadcast = await call(endpoint, 'sendTransaction');
  assert.equal(broadcast.status, 429);
  assert.equal(reads.length, 1);
  await queued;
  assert.ok(reads[1] - reads[0] >= 1150, 'public reads must not burst');
  assert.equal(calls.length, 4);
  assert.equal(calls.filter(c => c.method === 'sendTransaction').length, 1);
  assert.equal(calls.filter(c => c.url.startsWith(endpoint) && c.method === 'getBalance').length, 0);
});
