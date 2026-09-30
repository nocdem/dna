import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
import { collectThirdPartyLicenses, formatThirdPartyLicenses } from './scripts/third-party-licenses.mjs';

// The Messages preview (package NC-4c of docs/plans/2026-09-24-web-connect-design.md
// rev 5, §1.10): a SEPARATE Vite build rooted at /preview/. Every file it emits
// lives under /preview/ (base), and the page requests nothing outside /preview/
// except the node WebSockets:
//   - root is preview/, so only preview/index.html is an entry;
//   - publicDir is off, so the wallet's /assets/ (fonts, logo) is neither
//     copied nor referenced — the preview uses the system font stack and a
//     data: favicon (preview/index.html);
//   - CSS and the module's .wasm are imported from the entry, so they are
//     emitted under /preview/assets/.
// The live wallet build (vite.config.js -> dist/) is not touched (D9).
//
// THIRD-PARTY-LICENSES.txt: the same plugin body as vite.config.js (which keeps
// its plugin local), writing into dist-preview/.
function thirdPartyLicenses() {
  return {
    name: 'nodus-third-party-licenses',
    apply: 'build',
    generateBundle(_options, bundle) {
      const ids = [];
      for (const output of Object.values(bundle)) {
        if (output.type !== 'chunk') continue;
        for (const [id, info] of Object.entries(output.modules)) if (info.renderedLength > 0) ids.push(id);
      }
      let packages;
      try { packages = collectThirdPartyLicenses(ids); } catch (error) { this.error(error.message); }
      this.emitFile({ type: 'asset', fileName: 'THIRD-PARTY-LICENSES.txt', source: formatThirdPartyLicenses(packages) });
    }
  };
}

const here = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  root: `${here}preview`,
  base: '/preview/',
  publicDir: false,
  plugins: [thirdPartyLicenses()],
  // The entry imports ../src/ (vault, recovery, the core glue); the dev server
  // must be allowed to serve the whole web-wallet tree, not only preview/.
  server: { fs: { allow: [here] } },
  build: { outDir: `${here}dist-preview`, emptyOutDir: true }
});
