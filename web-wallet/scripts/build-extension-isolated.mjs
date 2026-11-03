// Same production configs and license union as vite.extension.config.js, with
// each graph built in a fresh process to bound peak JS heap on small runners.
// Builds files only; never installs an extension, launches a browser or deploys.
import { build } from 'vite';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import config, { classicEntries, collectRenderedIds, extensionClassicConfig } from '../vite.extension.config.js';
import { collectThirdPartyLicenses, formatThirdPartyLicenses } from './third-party-licenses.mjs';
const here = dirname(fileURLToPath(import.meta.url)), root = resolve(here, '..');
const [stage, scratch, index] = process.argv.slice(2);
const unminified = process.env.EXTENSION_UNMINIFIED === '1';
if (stage) {
  if (!scratch || !['html', 'classic'].includes(stage)) throw new Error('Invalid isolated build stage.');
  const ids = new Set();
  if (stage === 'html') {
    await build({ ...config, configFile: false, ...(unminified ? { build: { ...config.build, minify: false } } : {}), plugins: [
      ...config.plugins.filter(plugin => plugin.name !== 'nodus-extension-classic-scripts-and-licenses'),
      { name: 'isolated-license-module-ids', generateBundle(_options, bundle) { collectRenderedIds(bundle, ids); } },
    ] });
  } else {
    const entry = classicEntries[Number(index)];
    const classic = extensionClassicConfig(entry);
    const result = await build(unminified ? { ...classic, build: { ...classic.build, minify: false } } : classic);
    if (Array.isArray(result) || !result.output) throw new Error('Unexpected classic build output.');
    const chunks = result.output.filter(output => output.type === 'chunk');
    if (result.output.length !== 1 || chunks.length !== 1 || chunks[0].imports.length || chunks[0].dynamicImports.length) throw new Error('Classic script must be self contained.');
    collectRenderedIds(chunks, ids);
    const destination = resolve(root, 'dist-extension/unpacked', entry);
    mkdirSync(dirname(destination), { recursive: true }); writeFileSync(destination, chunks[0].code);
  }
  writeFileSync(join(scratch, stage === 'html' ? 'html.json' : `classic-${index}.json`), JSON.stringify([...ids]));
} else {
  const scratch = mkdtempSync(join(tmpdir(), 'nodus-extension-build-'));
  try {
    const stages = [['html'], ...classicEntries.map((_, index) => ['classic', String(index)])];
    for (const [name, index] of stages) {
      const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), name, scratch, ...(index === undefined ? [] : [index])], { cwd: root, env: process.env, stdio: 'inherit' });
      if (result.error) throw result.error;
      if (result.status !== 0) throw new Error(`Extension ${name} build failed (${result.signal || result.status}).`);
    }
    const ids = new Set(JSON.parse(readFileSync(join(scratch, 'html.json'))));
    for (let i = 0; i < classicEntries.length; i++) for (const id of JSON.parse(readFileSync(join(scratch, `classic-${i}.json`)))) ids.add(id);
    writeFileSync(resolve(root, 'dist-extension/unpacked/THIRD-PARTY-LICENSES.txt'), formatThirdPartyLicenses(collectThirdPartyLicenses([...ids])));
    console.log(`Isolated extension build complete (minified: ${!unminified}); no installation or deployment.`);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
