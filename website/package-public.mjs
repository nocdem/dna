import { mkdtemp, mkdir, copyFile, lstat, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { siteFiles } from './public-files.mjs';

const root = fileURLToPath(new URL('./', import.meta.url));
const output = await mkdtemp('/tmp/nodus-sites-');
const summary = [];
for (const [site, manifest] of Object.entries(siteFiles)) {
  let bytes = 0;
  for (const [destination, source] of manifest) {
    const absolute = join(root, source);
    const stat = await lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Expected a regular public file: ' + source);
    const target = join(output, site, destination);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(absolute, target); bytes += stat.size;
  }
  summary.push({ site, files: manifest.size, bytes });
}
await writeFile(join(output, 'manifest.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({ output, sites: summary }, null, 2));
