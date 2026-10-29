import { build, defineConfig } from 'vite';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import walletConfig from './vite.config.js';
import { collectThirdPartyLicenses, formatThirdPartyLicenses } from './scripts/third-party-licenses.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const extension = resolve(here, 'extension');
const require = createRequire(import.meta.url);
const manifest = JSON.parse(readFileSync(resolve(extension, 'manifest.json'), 'utf8'));
const classicEntries = [manifest.background.service_worker, ...manifest.content_scripts.flatMap(entry => entry.js)];
const wasm = [
  ['src/nodus/send.js', 'send.wasm', 'src/nodus/send.wasm'],
  ['src/nodus/derive.js', './mldsa87.wasm', 'src/nodus/mldsa87.wasm'],
  ['src/cpunk/derive.js', './legacy-dilithium.wasm', 'src/cpunk/legacy-dilithium.wasm'],
];

// readable-stream 4.7.0 lib/internal/streams/{readable,writable}.js imports
// process/, events and buffer. Resolve the installed browser implementations,
// rather than Vite's Node-builtin external placeholders. No new dependency.
const alias = [
  { find: /^buffer\/?$/u, replacement: require.resolve('buffer/') },
  { find: /^events\/?$/u, replacement: require.resolve('events/') },
  { find: /^process\/?$/u, replacement: require.resolve('process/browser.js') },
];
const define = { ...walletConfig.define, 'process.env.IN_TEST': 'false', global: 'globalThis' };

function collectRenderedIds(bundle, ids) {
  for (const output of Object.values(bundle)) {
    if (output.type !== 'chunk') continue;
    for (const [id, info] of Object.entries(output.modules)) if (info.renderedLength > 0) ids.add(id);
  }
}

function streamProcess() {
  return {
    name: 'nodus-extension-stream-process', enforce: 'pre',
    transform(code, id) {
      // MetaMask v13.54.0 development/webpack/webpack.config.ts:220-225
      // supplies process/browser.js with ProvidePlugin. The installed stream
      // 3 sources use unbound process.nextTick (lib/_stream_readable.js:490,
      // _stream_writable.js:267); stream 4 already imports process explicitly.
      // Inject a module-local CommonJS import before Vite converts CommonJS.
      // In particular, this never installs process on the host page's globals.
      if (!/\/node_modules\/readable-stream\/(?:lib\/.*|readable\.js)$/u.test(id) ||
        !/\bprocess\./u.test(code) || /\b(?:var|let|const)\s+process\s*=/u.test(code)) return;
      return { code: `var process = require('process/');\n${code}`, map: null };
    },
  };
}

// The three web-wallet loaders use new URL(..., import.meta.url). Give copied
// binaries fixed extension URLs before Vite's asset transform; this also avoids
// a document.currentScript fallback in the classic service worker. The glue's
// other import.meta.url becomes self.location.href in that worker build.
function wasmUrls() {
  return {
    name: 'nodus-extension-wasm-urls', enforce: 'pre',
    transform(code, id) {
      const entry = wasm.find(([loader]) => id.split('?')[0] === resolve(here, loader));
      if (!entry) return;
      const [, relative, source] = entry;
      const pattern = /new\s+URL\(\s*(['"])([^'"]+)\1\s*,\s*import\.meta\.url\s*\)/gu;
      let replaced = 0;
      const rewritten = code.replace(pattern, (expression, _quote, path) => {
        if (path !== relative) return expression;
        replaced++;
        return `new URL(chrome.runtime.getURL(${JSON.stringify(`wasm/${source.split('/').at(-1)}`)}))`;
      });
      if (replaced !== 1) this.error(`Expected one WASM URL in ${entry[0]}, found ${replaced}`);
      return { code: rewritten, map: null };
    },
  };
}

function packageAssets() {
  return {
    name: 'nodus-extension-assets',
    generateBundle() {
      const packaged = structuredClone(manifest);
      const sizes = [...new Set([...Object.keys(packaged.icons), ...Object.keys(packaged.action.default_icon)])]
        .map(Number).sort((a, b) => a - b);
      // No pinned Chrome icon-format document was found under /home/nocdem/refs
      // (filename search plus Chrome URL/SVG-icon text search, 2026-10-29).
      // Inference relative to the pinned reference set: source SVG manifest
      // paths need rasterization. Current Chrome documentation confirms PNG and
      // excludes SVG: https://developer.chrome.com/docs/extensions/reference/manifest/icons
      // Render the existing mark; the source manifest remains a source-asset map.
      for (const size of sizes) {
        if (!Number.isSafeInteger(size) || size <= 0) this.error(`Invalid manifest icon size: ${size}`);
        const fileName = `icons/nodus-${size}.png`;
        const png = execFileSync('/usr/bin/rsvg-convert', ['--format=png', `--width=${size}`, `--height=${size}`,
          resolve(here, 'public/assets/nodus-mark.svg')]);
        this.emitFile({ type: 'asset', fileName, source: png });
        for (const icons of [packaged.icons, packaged.action.default_icon]) if (Object.hasOwn(icons, size)) icons[size] = fileName;
      }
      this.emitFile({ type: 'asset', fileName: 'manifest.json', source: `${JSON.stringify(packaged, null, 2)}\n` });
      // These are the orchestrator-built files. This build neither compiles nor
      // substitutes WASM; missing inputs fail. site-sdk is not a build input.
      for (const [, , source] of wasm) this.emitFile({ type: 'asset', fileName: `wasm/${source.split('/').at(-1)}`,
        source: readFileSync(resolve(here, source)) });
    },
  };
}

function classicScriptsAndLicenses() {
  return {
    name: 'nodus-extension-classic-scripts-and-licenses',
    async generateBundle(_options, bundle) {
      const ids = new Set();
      collectRenderedIds(bundle, ids);
      // Chrome's content_scripts schema exposes js/run_at/world, not a module
      // type: https://developer.chrome.com/docs/extensions/reference/manifest/content-scripts (web page, not pinned; inference)
      // Both ISOLATED and MAIN entries in extension/manifest.json therefore get
      // independent IIFEs, with no shared imports. The worker has no type:module
      // either; inline its lazy background import (MV3 disallows import()).
      // https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/basics#import-scripts (web page, not pinned; pinned support: refs/metamask-extension-v13.54.0/development/webpack/README.md:237 "Service workers, used by MV3, must load dependencies via importScripts")
      for (const entry of classicEntries) {
        const result = await build({
          configFile: false, root: extension, base: './', publicDir: false,
          // Vite's lazy-import helper adds import.meta.url, which Rollup's iife output renders through
          // document.baseURI; a worker has no document. Resolve it as the define above does.
          resolve: { alias }, plugins: [streamProcess(), wasmUrls(), { name: 'nodus-extension-classic-import-meta',
            resolveImportMeta: property => (property === 'url' ? 'self.location.href' : null) }],
          define: { ...define, 'import.meta.url': 'self.location.href' },
          build: {
            target: 'chrome123', write: false, emptyOutDir: false, copyPublicDir: false,
            modulePreload: false,
            rollupOptions: {
              input: resolve(extension, entry), preserveEntrySignatures: false,
              output: { format: 'iife', inlineDynamicImports: true, entryFileNames: entry },
            },
          },
        });
        if (Array.isArray(result) || !('output' in result)) this.error(`Unexpected Vite output for ${entry}`);
        const chunks = result.output.filter(output => output.type === 'chunk');
        if (result.output.length !== 1 || chunks.length !== 1 || chunks[0].imports.length || chunks[0].dynamicImports.length) {
          this.error(`Classic entry ${entry} must be one self-contained script`);
        }
        collectRenderedIds(chunks, ids);
        this.emitFile({ type: 'asset', fileName: entry, source: chunks[0].code });
      }
      // Same renderedLength gate and license formatter as vite.config.js;
      // collect once across HTML, worker, isolated-world and main-world builds.
      let packages;
      try { packages = collectThirdPartyLicenses([...ids]); } catch (error) { this.error(error.message); }
      this.emitFile({ type: 'asset', fileName: 'THIRD-PARTY-LICENSES.txt', source: formatThirdPartyLicenses(packages) });
    },
  };
}

export default defineConfig({
  ...walletConfig,
  root: extension, base: './', publicDir: resolve(here, 'public'),
  resolve: { alias }, define,
  // Replace the wallet's private license plugin with the union collector above.
  plugins: [streamProcess(), wasmUrls(), packageAssets(), classicScriptsAndLicenses()],
  build: {
    target: 'chrome123', outDir: resolve(here, 'dist-extension/unpacked'), emptyOutDir: true,
    assetsInlineLimit: 0,
    rollupOptions: { input: {
      popup: resolve(extension, 'popup.html'), notification: resolve(extension, 'notification.html'), home: resolve(extension, 'home.html'),
    } },
  },
});
