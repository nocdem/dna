// Extracted-package smoke: real imports, 32-byte codec, release-export checks,
// both ABIs and pinned compiler/artifact parity. Requires npm ci --ignore-scripts
// inside the extracted package, supported Node/Linux x64 and compiler system
// libraries. STARTER_PACKAGE_DIR points to that root when run from the repo;
// default is this package's root. No phrase, network or transaction; no skip.
// Temporary compilation output is removed. This does NOT prove chain acceptance
// or real signing; sdk/js/test/module.test.js covers offline release signing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { doctor, PACKAGE_ROOT, childEnvironment } from '../src/artifacts.mjs';
import { loadSdk, loadTemplates } from '../src/sdk.mjs';
import { compileTemplate } from '../src/compile.mjs';

const root = resolve(process.env.STARTER_PACKAGE_DIR || PACKAGE_ROOT);
test('extracted SDK and both template ABIs work using only package-local files', async () => {
  const manifest = await doctor(root);
  assert.equal(manifest.schemaVersion, 1);
  const sdk = await loadSdk(root), templates = await loadTemplates(root);
  assert.equal(typeof sdk.NodusEvm.prototype.transfer, 'function');
  const high = `0x${'f'.repeat(24)}${'1'.repeat(40)}`;
  assert.equal(sdk.parseAddress(high), high.slice(2));
  assert.throws(() => sdk.parseAddress(`0x${'1'.repeat(40)}`), /20-byte/);
  const other = `0x${'2'.repeat(64)}`, third = `0x${'3'.repeat(64)}`;
  const vault = new sdk.Interface(templates.vault.abi);
  const escrow = new sdk.Interface(templates.escrow.abi);
  assert.ok(vault.encodeDeploy(`0x${templates.vault.bytecode}`, [[high, other], 2n]).length > templates.vault.bytecode.length / 2);
  assert.ok(escrow.encodeDeploy(`0x${templates.escrow.bytecode}`, [high, other, third, [10000000000n], 2000000000n]).length > templates.escrow.bytecode.length / 2);
  const output = execFileSync(process.execPath, [join(root, 'bin/nodus-starter.mjs'), 'doctor'], { cwd: root, env: childEnvironment(), encoding: 'utf8' });
  assert.equal(JSON.parse(output).ok, true);
});

test('both production templates recompile to the packaged ABI, creation and runtime bytes', async t => {
  const out = await mkdtemp(join(tmpdir(), 'nodus-compile-smoke-'));
  t.after(() => rm(out, { recursive: true, force: true }));
  for (const id of ['vault', 'escrow']) {
    assert.equal((await compileTemplate(id, root, out)).matchesPackagedArtifacts, true);
  }
});
