import { CHAINS } from './config.js';
import { validHash } from './activity.js';
const encoder = new TextEncoder(), MAX_PLAIN = 150000;
const context = 'nodus.wallet.activity.v2';
function encode(bytes) {
  let value = ''; for (let i = 0; i < bytes.length; i += 4096) value += String.fromCharCode(...bytes.subarray(i, i + 4096));
  return btoa(value);
}
function decode(value, max, exact) {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Invalid saved activity encoding.');
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (bytes.length > max || (exact && bytes.length !== exact) || encode(bytes) !== value) throw new Error('Invalid saved activity encoding.');
  return bytes;
}
export async function activityKeyFor(phrase, id) {
  const bytes = encoder.encode(phrase);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode(id, 16, 16), info: encoder.encode(context) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}
const header = data => ({ version: data.version, id: data.id, cipher: data.cipher, iv: data.iv });
export async function serializeActivity(id, rows, key) {
  const data = { version: 2, id, cipher: 'AES-256-GCM', iv: encode(crypto.getRandomValues(new Uint8Array(12))) };
  const selected = rows.slice(-100).map(({ chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, nonce, createdAt, status }) => ({ chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, nonce, createdAt, status }));
  const bytes = encoder.encode(JSON.stringify(selected));
  try {
    if (bytes.length > MAX_PLAIN) throw new Error('Saved activity is too large.');
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: decode(data.iv, 12, 12), additionalData: encoder.encode(context + JSON.stringify(header(data))), tagLength: 128 }, key, bytes);
    return JSON.stringify({ ...data, ciphertext: encode(new Uint8Array(ciphertext)) });
  } finally { bytes.fill(0); }
}
export async function parseActivity(text, id, addresses, key) {
  if (!text) return [];
  if (typeof text !== 'string' || text.length > 202000) throw new Error('Saved activity is too large.');
  const data = JSON.parse(text);
  if (data?.version === 1) throw new Error('Old activity was not authenticated and cannot be trusted. Check the explorer before resending.');
  if (!data || Object.keys(data).sort().join() !== 'cipher,ciphertext,id,iv,version' || data.version !== 2 || data.id !== id || data.cipher !== 'AES-256-GCM') throw new Error('Saved activity does not match this wallet.');
  let bytes, rows;
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(data.iv, 12, 12), additionalData: encoder.encode(context + JSON.stringify(header(data))), tagLength: 128 }, key, decode(data.ciphertext, MAX_PLAIN + 16)));
    rows = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { throw new Error('Saved activity authentication failed. Check the explorer before resending.'); }
  finally { bytes?.fill(0); }
  if (!Array.isArray(rows) || rows.length > 100) throw new Error('Invalid saved activity.');
  return rows.map(row => {
    if (!row || !Object.hasOwn(CHAINS, row.chain) || row.address !== addresses[row.chain] || !validHash(row.chain, row.hash) || typeof row.to !== 'string' || row.to.length > 128 || typeof row.symbol !== 'string' || row.symbol.length > 12 || typeof row.amount !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(row.amount) || typeof row.createdAt !== 'string' || !Number.isFinite(Date.parse(row.createdAt)) || !(row.nonce === undefined || Number.isSafeInteger(row.nonce)) || !['pending','included','unknown','confirmed','failed','expired','replaced','abandoned'].includes(row.status)) throw new Error('Invalid saved activity.');
    if (row.lastValidBlockHeight !== undefined && (!Number.isSafeInteger(row.lastValidBlockHeight) || row.lastValidBlockHeight < 0)) throw new Error('Invalid saved expiry.');
    if (row.expiration !== undefined && (!Number.isSafeInteger(row.expiration) || row.expiration < 0)) throw new Error('Invalid saved expiry.');
    return { chain: row.chain, address: row.address, to: row.to, symbol: row.symbol, amount: row.amount, endpoint: CHAINS[row.chain].endpoint, hash: row.hash, createdAt: row.createdAt, lastValidBlockHeight: row.lastValidBlockHeight, expiration: row.expiration, nonce: row.nonce, ...(row.status === 'abandoned' ? { status: 'abandoned', note: 'Marked abandoned by you; the network may still include it. Check the explorer.' } : { status: 'pending', note: 'Authenticated local record; verifying network status.' }) };
  });
}
