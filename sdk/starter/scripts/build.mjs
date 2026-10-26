// Maintainer-only packaging. Copies the explicit allowlist, checks release WASM
// parity and the pinned compiler tarball, recompiles library artifacts, then
// creates an archive without source mtimes, user state or install scripts.
import { readFile, writeFile, mkdir, mkdtemp, rm, chmod, lstat, rename } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { assertNode } from '../src/version.mjs';
import { COPY_FILES, COMPILER_ARCHIVE, COMPILER_FILES, COMPILER_SHA256, assertDistributionPaths } from '../src/distribution.mjs';
import { sha256, doctor, releaseWasm, childEnvironment } from '../src/artifacts.mjs';

assertNode();
const repo = fileURLToPath(new URL('../../../', import.meta.url));
const starter = join(repo, 'sdk/starter');
const args = process.argv.slice(2), options = {};
for (let i = 0; i < args.length; i += 2) {
  if (!['--compiler', '--wallet-wasm', '--out-dir'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new Error('Usage: node scripts/build.mjs --compiler <pinned.tar.gz> [--wallet-wasm <same-source-send.wasm>] [--out-dir <directory>]');
  options[args[i]] = resolve(args[i + 1]);
}
if (!options['--compiler']) throw new Error('Supply --compiler <verified Nodus solc tar.gz>; the build never downloads or installs a compiler.');
const archiveBytes = await readFile(options['--compiler']);
if (sha256(archiveBytes) !== COMPILER_SHA256) throw new Error('Compiler archive SHA256 differs from the pinned release. Nothing extracted.');
const walletBytes = await readFile(options['--wallet-wasm'] ?? join(repo, 'web-wallet/src/nodus/send.wasm'));
const sdkBytes = await readFile(join(repo, 'sdk/js/wasm/send-node.wasm'));
if (!walletBytes.equals(sdkBytes)) throw new Error('SDK WASM differs from the wallet reference. Rebuild both from the same checkout; use --wallet-wasm for the rebuilt wallet artifact when the committed one is stale.');
releaseWasm(sdkBytes);
const archiveEntries = execFileSync('tar', ['-tzf', options['--compiler']], { encoding: 'utf8', env: childEnvironment() }).trim().split('\n');
const expectedEntries = [COMPILER_ARCHIVE + '/', ...COMPILER_FILES.map(name => `${COMPILER_ARCHIVE}/${name}`)].sort();
if (JSON.stringify(archiveEntries.sort()) !== JSON.stringify(expectedEntries)) throw new Error('Compiler archive contains unexpected paths.');

const pkg = JSON.parse(await readFile(join(starter, 'package.json'), 'utf8'));
const name = `nodus-developer-starter-${pkg.version}-linux-x86_64`;
if (!/^nodus-developer-starter-\d+\.\d+\.\d+-linux-x86_64$/.test(name)) throw new Error('Invalid starter version.');
const outDir = options['--out-dir'] ?? join(starter, 'dist');
await mkdir(outDir, { recursive: true });
const stage = await mkdtemp(join(outDir, '.package-')), root = join(stage, name);
await mkdir(root, { mode: 0o755 });
const commandOptions = { cwd: repo, encoding: 'utf8', env: childEnvironment(), maxBuffer: 8 * 1024 * 1024 };
try {
  const files = {};
  for (const [source, destination] of COPY_FILES) {
    const stat = await lstat(join(repo, source));
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Source is not a regular file: ${source}`);
    const bytes = await readFile(join(repo, source)), path = join(root, destination);
    await mkdir(dirname(path), { recursive: true, mode: 0o755 });
    await writeFile(path, bytes, { flag: 'wx', mode: 0o644 });
    files[destination] = { sha256: sha256(bytes), size: bytes.length };
  }
  for (const file of COMPILER_FILES) {
    const bytes = execFileSync('tar', ['-xzOf', options['--compiler'], '--', `${COMPILER_ARCHIVE}/${file}`], { maxBuffer: 64 * 1024 * 1024, env: childEnvironment() });
    await writeFile(join(root, 'compiler', file), bytes, { flag: 'wx', mode: file === 'solc-nodus' ? 0o755 : 0o644 });
    files[`compiler/${file}`] = { sha256: sha256(bytes), size: bytes.length };
  }
  assertDistributionPaths(Object.keys(files));
  const sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], commandOptions).trim();
  // Generated WASM depends on tracked C outside the copied JS closure. Report
  // any tracked worktree change, plus new included files, not just JS changes.
  const trackedDirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], commandOptions).length > 0;
  const includedDirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal', '--', ...new Set(COPY_FILES.map(([source]) => source))], commandOptions).length > 0;
  const worktreeDirty = trackedDirty || includedDirty;
  const manifest = {
    schemaVersion: 1, starterVersion: pkg.version, sourceCommit, worktreeDirty,
    provenance: 'worktreeDirty covers all tracked changes and included untracked sources. File hashes identify shipped bytes, not source equivalence or an external audit.',
    compilerArchiveSha256: COMPILER_SHA256, walletWasmSha256: sha256(walletBytes),
    walletWasmReference: options['--wallet-wasm'] ? 'explicit-maintainer-reference' : 'checkout-wallet-artifact',
    files: Object.fromEntries(Object.entries(files).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))
  };
  await writeFile(join(root, 'artifact-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o644 });
  await doctor(root);
  // The existing script compiles into a temporary directory, compares all
  // committed library outputs, then removes it; it changes no source files.
  process.stdout.write(execFileSync('bash', [join(repo, 'nodus/tools/evm/contracts/verify.sh'), join(root, 'compiler/solc-nodus')], commandOptions));
  await chmod(root, 0o755);
  const tar = execFileSync('tar', ['--sort=name', '--owner=0', '--group=0', '--numeric-owner', '--mtime=@0', '--mode=u=rwX,go=rX', '--format=gnu', '-C', stage, '-cf', '-', name], { maxBuffer: 128 * 1024 * 1024, env: childEnvironment() });
  const packed = gzipSync(tar, { level: 9 });
  const archive = join(outDir, `${name}.tar.gz`), temporary = join(stage, 'archive.tar.gz');
  await writeFile(temporary, packed, { mode: 0o644 });
  await rename(temporary, archive);
  await writeFile(`${archive}.sha256`, `${sha256(packed)}  ${name}.tar.gz\n`, { mode: 0o644 });
  console.log(`Archive: ${archive}\nSHA256: ${sha256(packed)}\nSource HEAD: ${sourceCommit}; worktree changes: ${worktreeDirty}`);
} finally {
  await rm(stage, { recursive: true, force: true });
}
