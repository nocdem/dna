import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { wasmUrls } from '../vite.extension.config.js';

test('extension WASM URLs resolve packaged binaries for Vite IDs on Windows and POSIX', () => {
  const plugin = wasmUrls();
  const loaders = [
    ['nodus/derive.js', 'mldsa87.wasm'], ['pq/receive.js', 'receive-keygen.wasm'],
    ['pq/xion-public-key.js', 'receive-keygen.wasm'], ['pq/xion-recovery.js', 'mldsa65-sign.wasm'],
    ['pq/tidecoin-sign.js', 'tidecoin-sign.wasm'], ['pq/tidecoin-recovery.js', 'tidecoin-sign.wasm'],
    ['pq/tidecoin-wallet-sign.js', 'receive-keygen.wasm'], ['pq/algorand-sign.js', 'algorand-sign.wasm'],
    ['pq/qtc-payment-sign.js', 'qtc-mldsa44-sign.wasm'], ['pq/ckb-signed-payload.js', 'ckb-slh-sign.wasm'],
  ];
  for (const [loader, binary] of loaders) {
    const path = fileURLToPath(new URL(`../src/${loader}`, import.meta.url));
    const code = readFileSync(path, 'utf8');
    for (const id of [path, path.replaceAll('\\', '/') + '?fixture']) {
      const result = plugin.transform.call({ error(message) { throw Error(message); } }, code, id);
      assert.ok(result, `${loader}: loader must be matched`);
      assert.ok(result.code.includes(`chrome.runtime.getURL("wasm/${binary}")`), loader);
      assert.doesNotMatch(result.code, /new\s+URL\(\s*['"][^'"]+\.wasm['"]\s*,\s*import\.meta\.url/);
    }
  }
});
