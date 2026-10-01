import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { collectThirdPartyLicenses, formatThirdPartyLicenses } from './scripts/third-party-licenses.mjs';

// The Nodus Connect site (connect.nodusnetwork.io; decision
// docs/plans/decisions/2026-10-01-connect-own-origin.md): the wallet AND
// Messages in one page, built from the same web-wallet/ sources as a SECOND
// Vite build. The wallet build (vite.config.js -> dist/) is unchanged and
// carries no Messages code: only this build's entry (connect-site/index.html
// -> src/connect-main.js) imports src/connect/ui/.
//   - root is connect-site/, so only connect-site/index.html is an entry;
//   - base '/', the site has its own origin;
//   - publicDir is the wallet's public/ (fonts, logo under /assets/), so the
//     page looks and loads like the wallet;
//   - output dist-connect/, with its own THIRD-PARTY-LICENSES.txt.
//
// THIRD-PARTY-LICENSES.txt: the same plugin body as vite.config.js (which
// keeps its plugin local), writing into dist-connect/.
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
// The release shown on the page (src/connect-main.js, "Version x.y.z").
const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default defineConfig({
  root: `${here}connect-site`,
  base: '/',
  publicDir: `${here}public`,
  plugins: [thirdPartyLicenses()],
  define: { __APP_VERSION__: JSON.stringify(version) },
  // The entry imports ../src/; the dev server must be allowed to serve the
  // whole web-wallet tree, not only connect-site/.
  server: { fs: { allow: [here] } },
  build: { outDir: `${here}dist-connect`, emptyOutDir: true }
});
