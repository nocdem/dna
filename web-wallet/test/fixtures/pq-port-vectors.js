// Parent-authored fixture reader. Expected keys were produced by pristine
// pinned upstream/NIST, never by the wallet bridge. All seeds are public tests.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

const root = new URL('../../../shared/crypto/tests/pq_chains/fixtures/', import.meta.url);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function portVectors(name) {
  const manifest = JSON.parse(readFileSync(new URL('manifest.json', root)));
  assert.ok(Object.hasOwn(manifest, name), 'fixture must be pinned');
  const meta = manifest[name], compressed = readFileSync(new URL(name, root));
  assert.equal(digest(compressed), meta.compressed_sha256);
  const bytes = gunzipSync(compressed);
  assert.equal(bytes.length, meta.bytes); assert.equal(digest(bytes), meta.sha256);
  let offset = 0;
  function take(n) { assert.ok(n >= 0 && offset + n <= bytes.length); const b = bytes.subarray(offset, offset + n); offset += n; return b; }
  const u32 = () => take(4).readUInt32LE();
  assert.equal(take(8).toString(), 'PQPORT01');
  const count = u32(); assert.equal(count, meta.records); assert.ok(count > 0);
  const records = Array.from({ length: count }, () => {
    const [scheme, param, id, flags] = [u32(), u32(), u32(), u32()];
    const [seed, message, context, pk, sk, signature, random, aux] = Array.from({ length: 8 }, () => take(u32()));
    return { scheme, param, id, flags, seed, message, context, pk, sk, signature, random, aux };
  });
  assert.equal(offset, bytes.length, 'trailing fixture data');
  return records;
}

export const receiveWasmBytes = () => readFileSync(new URL('../../src/pq/receive-keygen.wasm', import.meta.url));
