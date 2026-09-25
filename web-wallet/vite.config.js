import { defineConfig } from 'vite';
import { collectThirdPartyLicenses, formatThirdPartyLicenses } from './scripts/third-party-licenses.mjs';

// Writes dist/THIRD-PARTY-LICENSES.txt (0.1.22): the license notice of every npm
// package with code in the output. Only modules Rollup actually rendered into a
// chunk count (renderedLength > 0), so tree-shaken packages are not listed and
// a build flag that drops a package drops its notice too. A bundled package
// with neither a license field nor a license file fails the build.
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

export default defineConfig({ plugins: [thirdPartyLicenses()] });
