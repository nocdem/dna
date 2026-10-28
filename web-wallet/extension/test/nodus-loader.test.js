import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createNodusSendModule, NODUS_SEND_NETWORK } from '../../src/nodus/send-module.js';
import { nodusSigningSeed } from '../../src/nodus/derive.js';

const { phrase, address } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url))).vectors[0];
const wasm = readFileSync(new URL('../../src/nodus/send.wasm', import.meta.url));

// Pins the unchanged page-built glue's offline load and identity derivation without window/document; Chromium service-worker execution remains a separate gate.
test('the real send glue loads without page globals and derives the web-wallet identity offline', async t => {
  assert.equal(typeof globalThis.window, 'undefined'); assert.equal(typeof globalThis.document, 'undefined');
  const requests = [];
  t.mock.method(globalThis, 'fetch', async url => {
    requests.push(String(url)); assert.equal(new URL(url).pathname.endsWith('/nodus/send.wasm'), true);
    return new Response(wasm, { headers: { 'Content-Type': 'application/wasm' } });
  });
  const module = await createNodusSendModule(NODUS_SEND_NETWORK, { startIndex: 0 });
  const seed = nodusSigningSeed(phrase);
  try {
    const identity = await module.identify({ seed });
    assert.equal(identity.fingerprint, address); assert.equal(identity.chainId, NODUS_SEND_NETWORK.chainId);
    assert.ok(requests.length > 0);
  } finally {
    seed.fill(0); module.cancel(); module.lock(); new Uint8Array(module.memory.buffer).fill(0);
    // release's Emscripten abort diagnostic is expected; it never includes keys.
    t.mock.method(console, 'error', () => {}); module.release();
  }
});
