// Deploy stamp of the swap page: writes the deployable copy of the page into <outDir> with a content version on
// every script and on the stylesheet. Usage: node website/swap-site/stamp.mjs <outDir>
//
// Cache busting: the page's scripts are served with a long max-age by the public edge while the page is
// revalidated, so the page must ask for the exact version it was built with, otherwise a browser pairs a new
// page with an older cached script (same rule as website/build-portals.mjs: first 12 hex of sha256, `?v=`).
//
// The modules are those swap.js reaches through static imports. A relative import './name.js' becomes
// './name.js?v=<v>', <v> from the target's OUTPUT content (its own imports already stamped), leaves first, so a
// change in any module changes the version of every module that imports it, up to swap.js. The source is left
// untouched; every other byte of every file is copied as is.

import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ENTRY = 'swap.js';
const SPEC_RE = /(\bfrom\s*|\bimport\s*)(['"])(\.[^'"]*)\2/g;   // static import / export-from / bare import specifiers
const FLAT_JS = /^\.\/([A-Za-z0-9_.-]+\.js)$/;

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// Relative specifiers of a module's text, as file names in the same directory.
function importsOf(name, text) {
  const out = [];
  for (const m of text.matchAll(SPEC_RE)) {
    const f = FLAT_JS.exec(m[3]);
    if (!f) throw new Error(`${name}: unsupported relative import '${m[3]}' (only './<name>.js' in the same directory)`);
    out.push(f[1]);
  }
  return out;
}

// Returns [{ name, version, sha256 }] in the order written. Throws, writing nothing, on a cycle, a missing file,
// or a non-empty outDir.
export async function stamp(srcDir, outDir) {
  srcDir = resolve(srcDir);
  outDir = resolve(outDir);

  let existing = [];
  try { existing = await readdir(outDir); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (existing.length) throw new Error(`output directory ${outDir} is not empty`);

  // Source text as latin1: one char per byte, so the rewrite leaves every other byte exactly as it was.
  const read = async (name) => (await readFile(join(srcDir, name))).toString('latin1');

  const done = new Map();      // module name -> { text (output, latin1), version }
  const visiting = [];
  async function build(name) {
    if (done.has(name)) return;
    if (visiting.includes(name)) throw new Error(`import cycle: ${[...visiting.slice(visiting.indexOf(name)), name].join(' -> ')}`);
    visiting.push(name);
    const text = await read(name);
    for (const dep of importsOf(name, text)) await build(dep);
    visiting.pop();
    const stamped = text.replace(SPEC_RE, (all, kw, q, spec) => {
      const dep = FLAT_JS.exec(spec)[1];
      return `${kw}${q}./${dep}?v=${done.get(dep).version}${q}`;
    });
    done.set(name, { text: stamped, version: sha256(Buffer.from(stamped, 'latin1')).slice(0, 12) });
  }
  await build(ENTRY);

  const css = await readFile(join(srcDir, 'swap.css'));
  const cssVersion = sha256(css).slice(0, 12);

  let html = await read('index.html');
  const swapRef = `src="${ENTRY}"`;
  const cssRef = 'href="swap.css"';
  for (const ref of [swapRef, cssRef]) {
    if (html.split(ref).length !== 2) throw new Error(`index.html must contain ${ref} exactly once`);
  }
  html = html.replace(swapRef, `src="${ENTRY}?v=${done.get(ENTRY).version}"`)
             .replace(cssRef, `href="swap.css?v=${cssVersion}"`);

  const files = [{ name: 'index.html', data: Buffer.from(html, 'latin1'), version: '-' }];
  files.push({ name: 'swap.css', data: css, version: cssVersion });
  for (const [name, m] of done) files.push({ name, data: Buffer.from(m.text, 'latin1'), version: m.version });

  await mkdir(outDir, { recursive: true });
  const rows = [];
  for (const f of files) {
    await writeFile(join(outDir, f.name), f.data);
    rows.push({ name: f.name, version: f.version, sha256: sha256(f.data) });
  }
  return rows;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outDir = process.argv[2];
  if (!outDir || process.argv.length !== 3) {
    console.error('usage: node stamp.mjs <outDir>');
    process.exit(2);
  }
  try {
    const rows = await stamp(fileURLToPath(new URL('.', import.meta.url)), outDir);
    for (const r of rows) console.log(`${r.name} ${r.version} ${r.sha256}`);
  } catch (e) {
    console.error(`stamp: ${e.message}`);
    process.exit(1);
  }
}
