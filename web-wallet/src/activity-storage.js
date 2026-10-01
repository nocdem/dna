import { CHAINS } from './config.js';
import { validHash, validNodusPending } from './activity.js';
import { NODUS_ASSET } from './nodus/network.js';
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
// `info` separates the keys of the saved records of one wallet (RFC 5869
// §3.2: the HKDF "info" binds a key to its use): activity, and since 0.1.41
// the last balances (BALANCES_CONTEXT). Same phrase, same vault id salt.
export async function activityKeyFor(phrase, id, info = context) {
  const bytes = encoder.encode(phrase);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode(id, 16, 16), info: encoder.encode(info) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}

// The last balance read per asset, saved only with a saved wallet (decision
// 2026-10-02-device-cache-only-when-saved; the app's wallet cache,
// messenger/database/wallet_cache.h). The same envelope as the activity
// (AES-256-GCM, random 12-byte IV, the header as additional data) under its
// own key: balancesKeyFor.
export const BALANCES_CONTEXT = 'nodus.wallet.balances.v1';
const BALANCES_MAX_PLAIN = 20000, BALANCES_MAX = 64;
export const balancesKeyFor = (phrase, id) => activityKeyFor(phrase, id, BALANCES_CONTEXT);
export async function serializeBalances(id, entries, key) {
  const data = { version: 1, id, cipher: 'AES-256-GCM', iv: encode(crypto.getRandomValues(new Uint8Array(12))) };
  const selected = Object.entries(entries).slice(0, BALANCES_MAX).map(([asset, e]) => [asset, { units: e.units, observedAt: e.observedAt, address: e.address }]);
  const bytes = encoder.encode(JSON.stringify(Object.fromEntries(selected)));
  try {
    if (bytes.length > BALANCES_MAX_PLAIN) throw new Error('Saved balances are too large.');
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: decode(data.iv, 12, 12), additionalData: encoder.encode(BALANCES_CONTEXT + JSON.stringify(header(data))), tagLength: 128 }, key, bytes);
    return JSON.stringify({ ...data, ciphertext: encode(new Uint8Array(ciphertext)) });
  } finally { bytes.fill(0); }
}
// -> { assetKey: { units: bigint, observedAt, address } }; anything that does
// not authenticate or check out throws (the caller then shows nothing kept).
export async function parseBalances(text, id, key, now = Date.now()) {
  if (!text) return {};
  if (typeof text !== 'string' || text.length > 30000) throw new Error('Saved balances are too large.');
  const data = JSON.parse(text);
  if (!data || Object.keys(data).sort().join() !== 'cipher,ciphertext,id,iv,version' || data.version !== 1 || data.id !== id || data.cipher !== 'AES-256-GCM') throw new Error('Saved balances do not match this wallet.');
  let bytes, entries;
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(data.iv, 12, 12), additionalData: encoder.encode(BALANCES_CONTEXT + JSON.stringify(header(data))), tagLength: 128 }, key, decode(data.ciphertext, BALANCES_MAX_PLAIN + 16)));
    entries = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { throw new Error('Saved balances authentication failed.'); }
  finally { bytes?.fill(0); }
  if (!entries || typeof entries !== 'object' || Array.isArray(entries) || Object.keys(entries).length > BALANCES_MAX) throw new Error('Invalid saved balances.');
  const out = {};
  for (const [asset, e] of Object.entries(entries)) {
    if (!/^[a-z0-9]{1,24}:[A-Za-z0-9]{1,12}$/.test(asset) || !e || typeof e.units !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(e.units) ||
        !Number.isSafeInteger(e.observedAt) || e.observedAt <= 0 || e.observedAt > now + 60000 ||
        typeof e.address !== 'string' || e.address.length === 0 || e.address.length > 128) throw new Error('Invalid saved balances.');
    out[asset] = { units: BigInt(e.units), observedAt: e.observedAt, address: e.address };
  }
  return out;
}
const header = data => ({ version: data.version, id: data.id, cipher: data.cipher, iv: data.iv });
export async function serializeActivity(id, rows, key) {
  const data = { version: 2, id, cipher: 'AES-256-GCM', iv: encode(crypto.getRandomValues(new Uint8Array(12))) };
  // expiryHeight / fromHeight / inputs exist only on NODUS rows; JSON drops
  // them (undefined) for every other network, whose saved form is unchanged.
  const selected = rows.slice(-100).map(({ chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, nonce, createdAt, status, expiryHeight, fromHeight, inputs }) => ({ chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, nonce, createdAt, status, expiryHeight, fromHeight, inputs }));
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
    // A NODUS row: its address is derived after unlock (src/app.js
    // showNodusAddress), so while addresses.nodus is still unknown any 128-hex
    // owner is accepted — the row is inside this wallet's authenticated
    // envelope — and the app shows it only once the addresses match.
    const nodus = row?.chain === NODUS_ASSET.chain;
    if (nodus && (!(addresses.nodus === undefined ? /^[0-9a-f]{128}$/.test(row.address) : row.address === addresses.nodus) || row.symbol !== NODUS_ASSET.symbol || !/^[0-9a-f]{128}$/.test(row.to) || !validNodusPending(row) || row.lastValidBlockHeight !== undefined || row.expiration !== undefined || row.nonce !== undefined)) throw new Error('Invalid saved activity.');
    if (!row || !(nodus || Object.hasOwn(CHAINS, row.chain)) || (!nodus && row.address !== addresses[row.chain]) || !validHash(row.chain, row.hash) || typeof row.to !== 'string' || row.to.length > 128 || typeof row.symbol !== 'string' || row.symbol.length > 12 || typeof row.amount !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(row.amount) || typeof row.createdAt !== 'string' || !Number.isFinite(Date.parse(row.createdAt)) || !(row.nonce === undefined || Number.isSafeInteger(row.nonce)) || !['pending','included','unknown','confirmed','failed','expired','replaced','abandoned'].includes(row.status)) throw new Error('Invalid saved activity.');
    if (row.lastValidBlockHeight !== undefined && (!Number.isSafeInteger(row.lastValidBlockHeight) || row.lastValidBlockHeight < 0)) throw new Error('Invalid saved expiry.');
    if (row.expiration !== undefined && (!Number.isSafeInteger(row.expiration) || row.expiration < 0)) throw new Error('Invalid saved expiry.');
    // Every saved status is re-verified from the network (NODUS included: an
    // 'expired' row locks its coins again until a fresh scan says so).
    return { chain: row.chain, address: row.address, to: row.to, symbol: row.symbol, amount: row.amount, endpoint: nodus ? undefined : CHAINS[row.chain].endpoint, hash: row.hash, createdAt: row.createdAt, lastValidBlockHeight: row.lastValidBlockHeight, expiration: row.expiration, nonce: row.nonce, ...(nodus ? { expiryHeight: row.expiryHeight, fromHeight: row.fromHeight, inputs: [...row.inputs] } : {}), ...(row.status === 'abandoned' ? { status: 'abandoned', note: 'Marked abandoned by you; the network may still include it. Check the explorer.' } : { status: 'pending', note: 'Authenticated local record; verifying network status.' }) };
  });
}
