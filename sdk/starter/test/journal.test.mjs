// Local filesystem tests, no keys/network or special build flags/env. Temporary
// directories are removed. These prove process/disk behavior, not chain finality.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { acquireJournal } from '../src/journal.mjs';

const fingerprint = '1'.repeat(128), chainId = '2'.repeat(64);
const row = { hash: '3'.repeat(128), expiryHeight: '1090', fromHeight: '1001', inputs: ['4'.repeat(128)] };
async function fixture(t) {
  const stateDir = await mkdtemp(join(tmpdir(), 'nodus-journal-'));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  return { stateDir, chainId, fingerprint };
}

test('pending rows persist across restart and identity operations are exclusive', async t => {
  const options = await fixture(t);
  const first = await acquireJournal(options);
  try {
    await first.record(row);
    await assert.rejects(acquireJournal(options), /locked/);
    assert.deepEqual(JSON.parse(await readFile(first.path, 'utf8')).pending, [row]);
  } finally { await first.close(); }
  const second = await acquireJournal(options);
  try {
    assert.deepEqual(second.pending(), [row]);
    await assert.rejects(second.record({ ...row, hash: '5'.repeat(128) }), /pending/);
    await second.replace([]);
  } finally { await second.close(); }
  const third = await acquireJournal(options);
  try { assert.deepEqual(third.pending(), []); } finally { await third.close(); }
});

test('malformed, mismatched and unknown journal state fail closed without overwriting', async t => {
  const options = await fixture(t);
  const journal = await acquireJournal(options);
  const path = journal.path;
  await journal.close();
  for (const bytes of ['{bad json', JSON.stringify({ version: 1, chainId, fingerprint: '5'.repeat(128), pending: [] }),
    JSON.stringify({ version: 1, chainId, fingerprint, pending: [{ ...row, inputs: [row.inputs[0], row.inputs[0]] }] }),
    JSON.stringify({ version: 1, chainId, fingerprint, pending: [], phrase: 'do not persist' })]) {
    await writeFile(path, bytes, { mode: 0o600 });
    await assert.rejects(acquireJournal(options), /journal/i);
    assert.equal(await readFile(path, 'utf8'), bytes);
  }
});

test('a symlink journal is refused and its target is unchanged', async t => {
  const options = await fixture(t);
  const journal = await acquireJournal(options), path = journal.path;
  await journal.close();
  const target = join(options.stateDir, 'target');
  await writeFile(target, 'sentinel');
  await rm(path);
  await symlink(target, path);
  await assert.rejects(acquireJournal(options), /journal/i);
  assert.equal(await readFile(target, 'utf8'), 'sentinel');
});

test('first-use directory entries are fsynced through ancestors before journal writes', async t => {
  const options = await fixture(t);
  const nested = join(options.stateDir, 'new-parent', 'state');
  const synced = [], originalOpen = fs.open;
  const patch = t.mock.method(fs, 'open', async (path, ...args) => {
    const handle = await originalOpen(path, ...args), sync = handle.sync.bind(handle);
    handle.sync = async () => { synced.push(path); return sync(); };
    return handle;
  });
  syncBuiltinESMExports();
  try {
    const journal = await acquireJournal({ ...options, stateDir: nested });
    try { await journal.record(row); } finally { await journal.close(); }
    const firstWrite = synced.findIndex(path => path.endsWith('/pending.next'));
    assert.ok(firstWrite >= 0);
    for (const path of [options.stateDir, join(options.stateDir, 'new-parent'), nested, join(nested, chainId), join(nested, chainId, fingerprint)]) {
      assert.ok(synced.indexOf(path) >= 0 && synced.indexOf(path) < firstWrite, `directory entry durable before record: ${path}`);
    }
  } finally { patch.mock.restore(); syncBuiltinESMExports(); }
});

test('an already-existing hierarchy is also fsynced through root before journal writes', async t => {
  const options = await fixture(t), directory = join(options.stateDir, chainId, fingerprint);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const synced = [], originalOpen = fs.open;
  const patch = t.mock.method(fs, 'open', async (path, ...args) => {
    const handle = await originalOpen(path, ...args), sync = handle.sync.bind(handle);
    handle.sync = async () => { synced.push(path); return sync(); };
    return handle;
  });
  syncBuiltinESMExports();
  try {
    const journal = await acquireJournal(options);
    await journal.close();
    const firstWrite = synced.findIndex(path => path.endsWith('/pending.next'));
    assert.ok(firstWrite >= 0);
    for (let path = directory; ; path = dirname(path)) {
      assert.ok(synced.indexOf(path) >= 0 && synced.indexOf(path) < firstWrite, `existing parent durable before record: ${path}`);
      if (dirname(path) === path) break;
    }
  } finally { patch.mock.restore(); syncBuiltinESMExports(); }
});

test('failure to fsync a newly created ancestor refuses journal acquisition', async t => {
  const options = await fixture(t), originalOpen = fs.open;
  const nested = join(options.stateDir, 'new-parent', 'state');
  const patch = t.mock.method(fs, 'open', async (path, ...args) => {
    const handle = await originalOpen(path, ...args);
    if (path === options.stateDir) handle.sync = async () => { throw new Error('injected ancestor fsync failure'); };
    return handle;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(acquireJournal({ ...options, stateDir: nested }), /ancestor fsync/);
    await assert.rejects(readFile(join(nested, chainId, fingerprint, 'pending.json')), { code: 'ENOENT' });
  } finally { patch.mock.restore(); syncBuiltinESMExports(); }
});
