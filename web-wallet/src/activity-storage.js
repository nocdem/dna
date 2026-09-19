import { CHAINS } from './config.js';
import { validHash } from './activity.js';
export function serializeActivity(id, rows) {
  return JSON.stringify({ version: 1, id, rows: rows.slice(-100).map(({ chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, createdAt, status }) => ({ chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, createdAt, status })) });
}
export function parseActivity(text, id, addresses) {
  if (!text) return [];
  if (typeof text !== 'string' || text.length > 150000) throw new Error('Saved activity is too large.');
  const data = JSON.parse(text);
  if (data?.version !== 1 || data.id !== id || !Array.isArray(data.rows) || data.rows.length > 100) throw new Error('Saved activity does not match this wallet.');
  return data.rows.map(row => {
    if (!row || !Object.hasOwn(CHAINS, row.chain) || row.address !== addresses[row.chain] || !validHash(row.chain, row.hash) || typeof row.to !== 'string' || row.to.length > 128 || typeof row.symbol !== 'string' || row.symbol.length > 12 || typeof row.amount !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(row.amount) || typeof row.createdAt !== 'string' || !Number.isFinite(Date.parse(row.createdAt)) || !['pending','included','unknown','confirmed','failed','expired'].includes(row.status)) throw new Error('Invalid saved activity.');
    if (row.lastValidBlockHeight !== undefined && (!Number.isSafeInteger(row.lastValidBlockHeight) || row.lastValidBlockHeight < 0)) throw new Error('Invalid saved expiry.');
    // Public metadata is untrusted: even a stored final status is rechecked after unlock.
    return { chain: row.chain, address: row.address, to: row.to, symbol: row.symbol, amount: row.amount, endpoint: CHAINS[row.chain].endpoint, hash: row.hash, createdAt: row.createdAt, lastValidBlockHeight: row.lastValidBlockHeight, status: 'pending', note: 'Restored local record; verifying network status.' };
  });
}
