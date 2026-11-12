// Tests of the deploy stamp (stamp.mjs): the page's scripts and stylesheet are asked for by the version of their
// exact content, so a browser never pairs a new page with an older cached script.
//
// PROVES:
//   - every relative import in every output module carries ?v=<first 12 hex of sha256 of the imported OUTPUT file>;
//   - index.html asks for swap.js and swap.css with the versions of the output files, and nothing else in it changes;
//   - the output holds index.html, swap.css and exactly the modules swap.js reaches through imports (no package.json,
//     README.md, test/, no unreached module);
//   - an import cycle is refused with a clear error and writes nothing;
//   - the stamped modules still load in Node;
//   - one changed byte in a leaf module changes the version of that leaf and of every importer up to swap.js and
//     index.html's reference, and leaves the versions of modules that do not import it unchanged;
//   - a non-empty output directory is refused.
// ENVIRONMENT: node >= 20, `node --test website/swap-site/test/`; no browser, no network, no environment variables.
// LEAVES BEHIND: nothing (temporary directories under os.tmpdir() are removed at the end of each test).
// FALSE PASS: the import check uses the same textual pattern as the stamp (`from '...'` and `import '...'`), so an
//   import written in a form neither knows is not seen by either; the real page imports are all of the first form
//   (checked below by the loading test and by the browser, not here). Loading in Node proves the specifiers resolve,
//   not that a browser resolves `?v=` the same way (it does: a query makes a distinct module URL, same file).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, readFile, readdir, writeFile, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { stamp } from '../stamp.mjs';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..');
const IMPORT_RE = /(\bfrom\s*|\bimport\s*)(['"])(\.\/[^'"?]+)\?v=([0-9a-f]+)\2/g;
const BARE_RE = /(\bfrom\s*|\bimport\s*)(['"])(\.\/[^'"?]+\.js)\2/g;   // a relative import WITHOUT ?v=

const sha12 = (buf) => createHash('sha256').update(buf).digest('hex').slice(0, 12);

async function tmp() { return mkdtemp(join(tmpdir(), 'swapstamp-')); }
async function freshOut() { const d = await tmp(); return join(d, 'out'); }
async function cleanup(...paths) { for (const p of paths) await rm(p, { recursive: true, force: true }); }

// A temporary copy of the source: index.html, swap.css and every .js at the top level.
async function copySource() {
  const d = await tmp();
  for (const n of await readdir(SRC)) {
    if (n === 'index.html' || n === 'swap.css' || n.endsWith('.js')) await copyFile(join(SRC, n), join(d, n));
  }
  return d;
}

test('every relative import carries the version of the imported output file; index.html matches', async () => {
  const out = await freshOut();
  try {
    await stamp(SRC, out);
    const files = await readdir(out);
    let imports = 0;
    for (const n of files.filter((f) => f.endsWith('.js'))) {
      const text = await readFile(join(out, n), 'latin1');
      assert.equal([...text.matchAll(BARE_RE)].length, 0, `${n} has an unstamped relative import`);
      for (const m of text.matchAll(IMPORT_RE)) {
        imports++;
        assert.equal(m[4], sha12(await readFile(join(out, m[3].slice(2)))), `${n} -> ${m[3]}`);
      }
    }
    assert.ok(imports >= 8, 'the page has at least 8 relative imports');
    const html = await readFile(join(out, 'index.html'), 'utf8');
    assert.ok(html.includes(`src="swap.js?v=${sha12(await readFile(join(out, 'swap.js')))}"`));
    assert.ok(html.includes(`href="swap.css?v=${sha12(await readFile(join(out, 'swap.css')))}"`));
    // nothing else in index.html changed
    const src = await readFile(join(SRC, 'index.html'), 'utf8');
    assert.equal(html.replace(/\?v=[0-9a-f]{12}"/g, '"'), src);
  } finally { await cleanup(dirname(out)); }
});

test('the output holds the page files and only the modules the page reaches', async () => {
  const srcDir = await copySource();
  const out = await freshOut();
  try {
    await writeFile(join(srcDir, 'orphan.js'), 'export const x = 1;\n');   // present in source, not imported
    const rows = await stamp(srcDir, out);
    const names = (await readdir(out)).sort();
    assert.ok(!names.includes('orphan.js'));
    assert.deepEqual(names, ['adapter.js', 'bot.js', 'extension.js', 'flow.js', 'index.html', 'log.js', 'swap-logic.js', 'swap.css', 'swap.js']);
    assert.deepEqual(rows.map((r) => r.name).sort(), names);
    for (const r of rows) assert.equal(r.sha256, createHash('sha256').update(await readFile(join(out, r.name))).digest('hex'));
  } finally { await cleanup(srcDir, dirname(out)); }
});

test('an import cycle is refused and nothing is written', async () => {
  const srcDir = await tmp();
  const out = await freshOut();
  try {
    await writeFile(join(srcDir, 'index.html'), '<script type="module" src="swap.js"></script><link rel="stylesheet" href="swap.css">');
    await writeFile(join(srcDir, 'swap.css'), 'body{}\n');
    await writeFile(join(srcDir, 'swap.js'), "import './a.js';\n");
    await writeFile(join(srcDir, 'a.js'), "import { b } from './b.js';\nexport const a = 1;\n");
    await writeFile(join(srcDir, 'b.js'), "import { a } from './a.js';\nexport const b = 2;\n");
    await assert.rejects(() => stamp(srcDir, out), /cycle/i);
    await assert.rejects(() => readdir(out), { code: 'ENOENT' });
  } finally { await cleanup(srcDir, dirname(out)); }
});

test('a non-empty output directory is refused', async () => {
  const d = await tmp();
  try {
    await writeFile(join(d, 'old.txt'), 'x');
    await assert.rejects(() => stamp(SRC, d), /not empty/i);
    assert.deepEqual(await readdir(d), ['old.txt']);
  } finally { await cleanup(d); }
});

test('the stamped modules still load in Node', async () => {
  const out = await freshOut();
  try {
    await stamp(SRC, out);
    // package.json is not part of the output; the module type comes from a file placed by this test only.
    await writeFile(join(out, 'package.json'), '{"type":"module"}');
    const logic = await import(pathToFileURL(join(out, 'swap-logic.js')).href);
    assert.equal(typeof logic, 'object');
    const flow = await import(pathToFileURL(join(out, 'flow.js')).href);
    assert.equal(typeof flow.createSwapFlow, 'function');
  } finally { await cleanup(dirname(out)); }
});

test('one changed byte in a leaf changes the leaf and every importer up to index.html', async () => {
  const srcDir = await copySource();
  const outA = await freshOut();
  const outB = await freshOut();
  try {
    const a = Object.fromEntries((await stamp(srcDir, outA)).map((r) => [r.name, r.version]));
    await writeFile(join(srcDir, 'swap-logic.js'), (await readFile(join(srcDir, 'swap-logic.js'))) + '\n// x');
    const b = Object.fromEntries((await stamp(srcDir, outB)).map((r) => [r.name, r.version]));
    // swap-logic.js is imported by flow.js, bot.js, adapter.js, extension.js and swap.js
    for (const n of ['swap-logic.js', 'flow.js', 'bot.js', 'adapter.js', 'extension.js', 'swap.js']) assert.notEqual(a[n], b[n], n);
    assert.equal(a['log.js'], b['log.js']);   // log.js imports nothing
    assert.equal(a['swap.css'], b['swap.css']);
    const htmlB = await readFile(join(outB, 'index.html'), 'utf8');
    assert.ok(htmlB.includes(`src="swap.js?v=${b['swap.js']}"`));
    assert.notEqual(await readFile(join(outA, 'index.html'), 'utf8'), htmlB);
  } finally { await cleanup(srcDir, dirname(outA), dirname(outB)); }
});
