// File-integrity tests only: no compiler/WASM execution, no network or keys.
// Default Node build, no env needed; temporary dirs removed. Hashes here test
// changed-byte detection, not authentication of a maliciously replaced release.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyFiles, sha256, packagePath } from '../src/artifacts.mjs';
import { DISTRIBUTION_FILES, assertDistributionPaths } from '../src/distribution.mjs';

test('release allowlist contains no test signing module, contract mock, secret or node_modules', () => {
  assertDistributionPaths(DISTRIBUTION_FILES);
  assert.ok(!DISTRIBUTION_FILES.some(path => /send-test|Mock[^/]*\.(sol|hex|json)|(^|\/)\.env|node_modules/.test(path)));
  assert.throws(() => assertDistributionPaths([...DISTRIBUTION_FILES, 'templates/MockActor.sol']), /allowlist/);
  assert.throws(() => assertDistributionPaths(DISTRIBUTION_FILES.slice(1)), /allowlist/);
  for (const path of ['../secret', '/secret', 'runtime/../secret', 'runtime//x']) assert.throws(() => packagePath('/tmp', path), /path/);
});

test('missing, changed, symlinked and unlisted runtime artifacts refuse', async t => {
  const root = await mkdtemp(join(tmpdir(), 'nodus-artifacts-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'runtime'));
  const file = join(root, 'runtime/a.js'), bytes = Buffer.from('export const a = 1;\n');
  const files = { 'runtime/a.js': { sha256: sha256(bytes), size: bytes.length } };
  await assert.rejects(verifyFiles(root, files, ['runtime']), /Missing/);
  await writeFile(file, bytes);
  await verifyFiles(root, files, ['runtime']);
  await writeFile(file, 'changed');
  await assert.rejects(verifyFiles(root, files, ['runtime']), /checksum/);
  await writeFile(file, bytes);
  await writeFile(join(root, 'runtime/extra.js'), 'unsafe');
  await assert.rejects(verifyFiles(root, files, ['runtime']), /Unexpected/);
  await rm(join(root, 'runtime/extra.js'));
  await rm(file); await writeFile(join(root, 'outside.js'), bytes); await symlink('../outside.js', file);
  await assert.rejects(verifyFiles(root, files, ['runtime']), /invalid artifact/);
});
