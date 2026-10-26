import { createHash } from 'node:crypto';
import { readFile, lstat, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { assertNode } from './version.mjs';
import { assertDistributionPaths, PROTECTED_DIRECTORIES, COMPILER_SHA256, COMPILER_VERSION } from './distribution.mjs';

export const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export function childEnvironment() {
  const env = { ...process.env };
  delete env.NODUS_PHRASE;
  return env;
}

export function packagePath(root, path) {
  if (typeof path !== 'string' || !/^[A-Za-z0-9_.\-/]+$/.test(path) || path.startsWith('/') || path.split('/').some(part => part === '..' || part === '.' || !part)) {
    throw new Error('Invalid artifact path.');
  }
  return join(root, path);
}

async function regularFile(root, path) {
  const parts = path.split('/');
  for (let i = 1; i <= parts.length; i++) {
    const stat = await lstat(packagePath(root, parts.slice(0, i).join('/')));
    if (stat.isSymbolicLink() || (i === parts.length ? !stat.isFile() : !stat.isDirectory())) throw new Error(`Artifact is not a regular file: ${path}`);
  }
  return readFile(packagePath(root, path));
}

async function listFiles(root, relative) {
  const paths = [];
  for (const entry of await readdir(packagePath(root, relative), { withFileTypes: true })) {
    const path = `${relative}/${entry.name}`;
    if (entry.isDirectory()) paths.push(...await listFiles(root, path));
    else if (entry.isFile()) paths.push(path);
    else throw new Error(`Unexpected artifact type: ${path}`);
  }
  return paths.sort();
}

// Generic file-integrity check also used by the isolated tampering tests.
export async function verifyFiles(root, files, directories = PROTECTED_DIRECTORIES) {
  if (!files || typeof files !== 'object' || Array.isArray(files)) throw new Error('Invalid artifact manifest.');
  for (const [path, expected] of Object.entries(files)) {
    if (!expected || !/^[0-9a-f]{64}$/.test(expected.sha256 ?? '') || !Number.isSafeInteger(expected.size) || expected.size < 0) throw new Error('Invalid artifact hash or size.');
    let bytes;
    try { bytes = await regularFile(root, path); } catch (error) { throw new Error(`Missing or invalid artifact: ${path}`, { cause: error }); }
    if (bytes.length !== expected.size || sha256(bytes) !== expected.sha256) throw new Error(`Artifact checksum mismatch: ${path}`);
  }
  for (const directory of directories) {
    const expected = Object.keys(files).filter(path => path.startsWith(`${directory}/`)).sort();
    const actual = await listFiles(root, directory);
    if (actual.length !== expected.length || actual.some((path, i) => path !== expected[i])) throw new Error(`Unexpected or missing files under ${directory}.`);
  }
}

export function releaseWasm(bytes) {
  const exports = WebAssembly.Module.exports(new WebAssembly.Module(bytes)).map(entry => entry.name);
  if (exports.some(name => name.startsWith('nsw_test_'))) throw new Error('Test-only exports found in release WASM.');
  for (const name of ['nsw_evm_deposit', 'nsw_evm_call', 'nsw_evm_create', 'nsw_evm_withdraw', 'nsw_evm_query', 'nsw_evm_offline_build']) {
    if (!exports.includes(name)) throw new Error(`Release WASM is missing ${name}.`);
  }
  return exports;
}

export async function doctor(root = PACKAGE_ROOT, { compiler = true } = {}) {
  assertNode();
  let manifest;
  try { manifest = JSON.parse(await readFile(join(root, 'artifact-manifest.json'), 'utf8')); } catch {
    throw new Error('Missing or invalid artifact-manifest.json. Use an extracted starter archive; maintainers must run the package build first.');
  }
  if (manifest.schemaVersion !== 1 || manifest.compilerArchiveSha256 !== COMPILER_SHA256 || !/^[0-9a-f]{40}$/.test(manifest.sourceCommit ?? '') || typeof manifest.worktreeDirty !== 'boolean') throw new Error('Invalid distribution provenance.');
  assertDistributionPaths(Object.keys(manifest.files ?? {}));
  await verifyFiles(root, manifest.files);
  const bytes = await readFile(join(root, 'runtime/sdk/js/wasm/send-node.wasm'));
  releaseWasm(bytes);
  if (manifest.walletWasmSha256 !== sha256(bytes)) throw new Error('WASM parity reference differs from the SDK binary.');
  if (compiler) {
    if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('The bundled compiler requires Linux x86-64; this starter release supports that platform only.');
    let version;
    try { version = execFileSync(resolve(root, 'compiler/solc-nodus'), ['--version'], { encoding: 'utf8', env: childEnvironment(), timeout: 10000 }).trim().split('\n').at(-1); }
    catch { throw new Error('Cannot run bundled solc-nodus; see compiler/README.md for the glibc/libstdc++ requirements.'); }
    if (version !== COMPILER_VERSION) throw new Error('Bundled compiler version differs from the pin.');
  }
  return manifest;
}
