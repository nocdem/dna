// Test-only helper. Proves nothing by itself: it lets Soqucoin send tests reach the receive module, because
// soqucoinSigningSeed loads src/pq/receive-keygen.wasm through the global fetch (src/pq/receive.js
// loadReceiveModule) and Node's fetch cannot read a file: URL. Every other request goes to the original fetch.
// Needs the built src/pq/receive-keygen.wasm; leaves nothing (the original fetch is restored after the file's tests).
// Can falsely pass: a stale receive-keygen.wasm is served as found; the pq-receive tests check the module itself.
import { readFileSync } from 'node:fs';
import { before, after } from 'node:test';
export function serveReceiveWasmForFile() {
  const bytes = readFileSync(new URL('../../src/pq/receive-keygen.wasm', import.meta.url));
  let original;
  before(() => {
    original = globalThis.fetch;
    globalThis.fetch = async (url, options) => String(url).endsWith('/receive-keygen.wasm') ? new Response(bytes) : original(url, options);
  });
  after(() => { globalThis.fetch = original; });
}
