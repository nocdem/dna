// Ixios lives under src/pq/ixios and has no build switch (operator 2026-11-03: "ayni klasore topla bunlari",
// "Kalksın"; plan docs/plans/approved/2026-11-03-pq-native.md section 5).
// Proves: git tracks no file under src/ixios/ and tracks files under src/pq/ixios/; the build-switch name
// appears in none of src/, extension/src/, package.json, the vite*.js configs, test/ and extension/test/.
// Needs: git on PATH and a checkout with a work tree; node:test only. Leaves: nothing.
// Can falsely pass: it is a text search, so a renamed switch would not be seen; git ls-files lists only
// tracked files, so an untracked file left under src/ixios would not be seen; the search skips node_modules
// and build output directories.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const root = new URL('..', import.meta.url);
const tracked = prefix => execFileSync('git', ['ls-files', '--', ...prefix], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean);
// Built from parts so this file does not contain the name it searches for.
const SWITCH = ['VITE', 'ENABLE', 'IXIOS'].join('_');

test('no tracked file under src/ixios and the Ixios modules sit under src/pq/ixios', () => {
  assert.deepEqual(tracked(['src/ixios']), []);
  const moved = tracked(['src/pq/ixios']);
  assert.equal(moved.length, 14, moved.join('\n'));
  assert.ok(moved.includes('src/pq/ixios/mldsa87-verify.wasm'));
});

test('the Ixios build switch is named nowhere in the sources, scripts, configs or tests', () => {
  const files = tracked(['src', 'extension/src', 'package.json', 'vite.config.js', 'vite.connect.config.js',
    'vite.extension.config.js', 'vite.preview.config.js', 'test', 'extension/test'])
    .filter(file => /\.(js|mjs|json|html|css|sh|py)$/.test(file));
  assert.ok(files.length > 100, 'the search must cover the sources');
  const hits = files.filter(file => readFileSync(new URL(file, root), 'utf8').includes(SWITCH));
  assert.deepEqual(hits, []);
});
