// Nodus endpoint order — a random start, then round-robin (web 0.1.79).
// What it proves:
//   - rotateNodusEndpoints(list, s) is the cyclic shift starting at s: same
//     length, same members, list[s] first, wrapping around; a bad start is
//     refused;
//   - randomNodusEndpointStart(n, random) maps [0, 1) onto 0..n-1 (also the
//     edge random() values 0 and just below 1);
//   - createNodusSendModule hands the C client (nsw_net_add_endpoint) the
//     configured endpoints as such a rotation — every start index gives a
//     rotation of NODUS_SEND_NETWORK.endpoints, and the default (random)
//     start does too; the chain id and the pins it hands over are unchanged.
// Requires nothing beyond `npm test` (a stub glue, no WASM build).
// How it can lie: the stub glue answers 0 to every export, so it shows what
// the page hands to the module, not which node the C client then reaches.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusSendModule, NODUS_SEND_NETWORK, rotateNodusEndpoints, randomNodusEndpointStart } from '../src/nodus/send-module.js';

const E = [{ host: '10.0.0.1', port: 1 }, { host: '10.0.0.2', port: 2 }, { host: '10.0.0.3', port: 3 }];

test('rotateNodusEndpoints: the cyclic shift starting at the given index', () => {
  assert.deepEqual(rotateNodusEndpoints(E, 0), E);
  assert.deepEqual(rotateNodusEndpoints(E, 1), [E[1], E[2], E[0]]);
  assert.deepEqual(rotateNodusEndpoints(E, 2), [E[2], E[0], E[1]]);
  for (const bad of [-1, 3, 1.5, '1', null, undefined, NaN]) {
    assert.throws(() => rotateNodusEndpoints(E, bad), /start index/, String(bad));
  }
  assert.deepEqual(E.map(e => e.host), ['10.0.0.1', '10.0.0.2', '10.0.0.3'], 'the input is not modified');
});

test('randomNodusEndpointStart: [0, 1) onto 0..n-1', () => {
  assert.equal(randomNodusEndpointStart(6, () => 0), 0);
  assert.equal(randomNodusEndpointStart(6, () => 0.999999999), 5);
  assert.equal(randomNodusEndpointStart(6, () => 0.5), 3);
  assert.equal(randomNodusEndpointStart(1, () => 0.7), 0);
  for (let i = 0; i < 200; i++) {
    const s = randomNodusEndpointStart(6);
    assert.ok(Number.isInteger(s) && s >= 0 && s < 6, String(s));
  }
  assert.throws(() => randomNodusEndpointStart(0), /count/);
});

function stubGlue() {
  const calls = [];
  const M = { HEAPU8: new Uint8Array(1 << 16), ccall(name, ret, types, args) { calls.push([name, args]); return ret === 'string' ? '' : 0; } };
  return { calls, loadGlue: async () => ({ default: async () => M }) };
}

const handed = calls => calls.filter(([name]) => name === 'nsw_net_add_endpoint').map(([, [host, port]]) => ({ host, port }));
const isRotationOf = (got, list) => list.some((_, s) => JSON.stringify(got) === JSON.stringify([...list.slice(s), ...list.slice(0, s)]));

test('createNodusSendModule: the endpoints reach the module as a rotation of the configured list', async () => {
  const list = NODUS_SEND_NETWORK.endpoints.map(({ host, port }) => ({ host, port }));
  for (let s = 0; s < list.length; s++) {
    const glue = stubGlue();
    await createNodusSendModule(NODUS_SEND_NETWORK, { loadGlue: glue.loadGlue, startIndex: s });
    assert.deepEqual(handed(glue.calls), [...list.slice(s), ...list.slice(0, s)], `start ${s}`);
    // chain id and pins unchanged
    assert.deepEqual(glue.calls.filter(([n]) => n === 'nsw_net_set_chain').map(([, a]) => a[0]), [NODUS_SEND_NETWORK.chainId]);
    assert.deepEqual(glue.calls.filter(([n]) => n === 'nsw_net_add_pin').map(([, a]) => a[0]), [...NODUS_SEND_NETWORK.pins]);
  }
  for (let i = 0; i < 20; i++) {
    const glue = stubGlue();
    await createNodusSendModule(NODUS_SEND_NETWORK, { loadGlue: glue.loadGlue });
    assert.ok(isRotationOf(handed(glue.calls), list), 'default (random) start');
  }
  await assert.rejects(createNodusSendModule(NODUS_SEND_NETWORK, { loadGlue: stubGlue().loadGlue, startIndex: list.length }), /start index/);
});
