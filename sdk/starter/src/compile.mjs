import { readFile, mkdir, mkdtemp, rm, copyFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { CONTRACT_SOURCES } from './distribution.mjs';
import { PACKAGE_ROOT, childEnvironment } from './artifacts.mjs';

// doctor() is called by the CLI before this helper executes the compiler.
// Compile the original source unit names so Solidity metadata stays identical.
export async function compileTemplate(id, root = PACKAGE_ROOT, output = resolve('build')) {
  if (!['vault', 'escrow'].includes(id)) throw new Error('compile needs vault or escrow.');
  const manifest = JSON.parse(await readFile(join(root, 'templates/manifest.json'), 'utf8'));
  const template = manifest.templates[id];
  await mkdir(output, { recursive: true });
  const temporary = await mkdtemp(join(output, '.compile-'));
  try {
    const compiled = spawnSync(resolve(root, 'compiler/solc-nodus'), [
      ...manifest.compiler.flags, '-o', temporary, ...CONTRACT_SOURCES.map(path => `src/${path}`)
    ], { cwd: join(root, 'templates/library'), env: childEnvironment(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 4 * 1024 * 1024 });
    if (compiled.error || compiled.status !== 0 || compiled.stderr) throw new Error(`Compiler failed or reported diagnostics: ${compiled.stderr || compiled.error?.message || compiled.status}`);
    const pairs = [['abi', template.abi], ['bin', template.bytecode], ['bin-runtime', template.runtimeBytecode]];
    for (const [extension, path] of pairs) {
      const built = await readFile(join(temporary, `${template.contract}.${extension}`));
      if (!built.equals(await readFile(join(root, path)))) throw new Error(`Compiled ${template.contract}.${extension} differs from the packaged artifact.`);
    }
    const destination = join(output, id);
    await mkdir(destination, { recursive: true });
    for (const [extension] of pairs) await copyFile(join(temporary, `${template.contract}.${extension}`), join(destination, `${template.contract}.${extension}`));
    return { contract: template.contract, output: destination, matchesPackagedArtifacts: true };
  } catch (error) {
    if (error.stderr?.length) throw new Error(`Compiler failed: ${String(error.stderr)}`);
    throw error;
  } finally { await rm(temporary, { recursive: true, force: true }); }
}
