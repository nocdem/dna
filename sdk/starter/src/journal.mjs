// Local per-chain/per-identity reservation. An exclusive lock is deliberately
// not reclaimed automatically: a crashed process may have submitted a write.
import { constants } from 'node:fs';
import { mkdir, lstat, open, rename, unlink } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/;
const keysAre = (object, keys) => object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).every(k => keys.includes(k));
const height = value => typeof value === 'string' && /^(0|[1-9]\d{0,19})$/.test(value) && BigInt(value) < 2n ** 64n;

function rowsChecked(rows) {
  if (!Array.isArray(rows) || rows.length > 1) throw new Error('Invalid journal pending list.');
  return rows.map(row => {
    if (!keysAre(row, ['hash', 'expiryHeight', 'fromHeight', 'inputs']) || !HEX128.test(row.hash ?? '') ||
        !height(row.expiryHeight) || (row.fromHeight !== undefined && !height(row.fromHeight)) ||
        !Array.isArray(row.inputs) || row.inputs.length < 1 || row.inputs.length > 15 ||
        !row.inputs.every(value => typeof value === 'string' && HEX128.test(value)) || new Set(row.inputs).size !== row.inputs.length) {
      throw new Error('Invalid journal pending transaction.');
    }
    return { hash: row.hash, expiryHeight: row.expiryHeight, ...(row.fromHeight === undefined ? {} : { fromHeight: row.fromHeight }), inputs: [...row.inputs] };
  });
}

async function privateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) {
    throw new Error(`Journal directory must be private, owned by this user and not a symlink: ${path}`);
  }
  // An existing directory could have just been created by another process
  // whose parent fsync has not completed. Existence is not durability: sync
  // this hierarchy through the filesystem root on every acquisition.
  let current = resolve(path);
  for (;;) {
    await syncDirectory(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

async function syncDirectory(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}

export async function acquireJournal({ stateDir, chainId, fingerprint }) {
  if (!HEX64.test(chainId ?? '') || !HEX128.test(fingerprint ?? '')) throw new Error('Invalid journal identity or chain.');
  await privateDirectory(stateDir);
  await privateDirectory(join(stateDir, chainId));
  const directory = join(stateDir, chainId, fingerprint);
  await privateDirectory(directory);
  const lockPath = join(directory, 'operation.lock'), path = join(directory, 'pending.json');
  let lock;
  try { lock = await open(lockPath, 'wx', 0o600); } catch (error) {
    if (error.code === 'EEXIST') throw new Error(`Identity journal is locked: ${lockPath}. Stop the other process; after a crash inspect the lock and journal before removing only the lock. Never delete pending.json to retry a transaction.`);
    throw error;
  }
  let closed = false, pending = [];
  const close = async () => {
    if (closed) return;
    closed = true;
    try { await lock.close(); } finally { await unlink(lockPath); await syncDirectory(directory); }
  };
  const replace = async rows => {
    if (closed) throw new Error('Journal is closed.');
    const checked = rowsChecked(rows);
    const bytes = JSON.stringify({ version: 1, chainId, fingerprint, pending: checked }, null, 2) + '\n';
    const temp = join(directory, 'pending.next');
    let handle, created = false;
    try {
      handle = await open(temp, 'wx', 0o600); created = true;
      await handle.writeFile(bytes, 'utf8');
      await handle.sync();
      await handle.close(); handle = undefined;
      await rename(temp, path);
      await syncDirectory(directory);
      pending = checked;
    } finally {
      await handle?.close();
      if (created) await unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; });
    }
  };
  try {
    await lock.writeFile(JSON.stringify({ pid: process.pid }) + '\n');
    await lock.sync(); await syncDirectory(directory);
    let handle, missing = false;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 16384 || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) throw new Error('Invalid journal file or permissions.');
      let data;
      try { data = JSON.parse(await handle.readFile('utf8')); } catch { throw new Error('Invalid journal JSON; preserve it and inspect before continuing.'); }
      if (!keysAre(data, ['version', 'chainId', 'fingerprint', 'pending']) || data.version !== 1 || data.chainId !== chainId || data.fingerprint !== fingerprint) throw new Error('Journal identity, chain or schema mismatch.');
      pending = rowsChecked(data.pending);
    } catch (error) {
      if (error.code === 'ENOENT') missing = true;
      else if (error.code === 'ELOOP') throw new Error('A journal file must not be a symlink.');
      else throw error;
    } finally { await handle?.close(); }
    if (missing) await replace([]);
    return {
      path,
      pending: () => rowsChecked(pending),
      replace,
      async record(row) {
        if (pending.length) throw new Error('A pending transaction already reserves this identity.');
        await replace([row]);
      },
      close
    };
  } catch (error) { await close(); throw error; }
}
