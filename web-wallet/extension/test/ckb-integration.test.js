import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('CKB trusted-port integration with production mainnet gate', () => {
  const root = fileURLToPath(new URL('../..', import.meta.url));
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--no-warnings', '--test', './extension/test/ckb-integration/exercise.mjs'], { cwd: root, encoding: 'utf8', timeout: 30000, env });
  assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /source-bound CKB trusted port signs/);
});
