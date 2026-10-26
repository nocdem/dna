import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { PACKAGE_ROOT, packagePath } from './artifacts.mjs';

export function loadSdk(root = PACKAGE_ROOT) {
  return import(pathToFileURL(join(root, 'runtime/sdk/js/src/index.js')).href);
}

export async function loadTemplates(root = PACKAGE_ROOT) {
  const manifest = JSON.parse(await readFile(join(root, 'templates/manifest.json'), 'utf8'));
  const result = {};
  for (const [id, template] of Object.entries(manifest.templates)) {
    result[id] = {
      ...template,
      abi: JSON.parse(await readFile(packagePath(root, template.abi), 'utf8')),
      bytecode: (await readFile(packagePath(root, template.bytecode), 'utf8')).trim(),
      runtimeBytecode: (await readFile(packagePath(root, template.runtimeBytecode), 'utf8')).trim()
    };
  }
  return result;
}
