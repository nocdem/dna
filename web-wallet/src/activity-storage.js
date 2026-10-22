import { CHAINS } from './config.js';
import { validHash, validNodusPending, terminal } from './activity.js';
import { NODUS_ASSET } from './nodus/network.js';
import { historySupported, checkHistoryRows } from './history.js';
import { checkAddressBook, ADDRESS_BOOK_MAX } from './address-book.js';
import { localRowsToShow, NODUS_HISTORY_LIMIT } from './nodus/history.js';
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

// One sealed record (balances, history): version 1 envelope, `context` both
// the HKDF info of its key and the additional-data prefix. `what` names it in
// the errors.
async function sealRecord(context, id, value, key, maxPlain, what) {
  const data = { version: 1, id, cipher: 'AES-256-GCM', iv: encode(crypto.getRandomValues(new Uint8Array(12))) };
  const bytes = encoder.encode(JSON.stringify(value));
  try {
    if (bytes.length > maxPlain) throw new Error(`Saved ${what} are too large.`);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: decode(data.iv, 12, 12), additionalData: encoder.encode(context + JSON.stringify(header(data))), tagLength: 128 }, key, bytes);
    return JSON.stringify({ ...data, ciphertext: encode(new Uint8Array(ciphertext)) });
  } finally { bytes.fill(0); }
}
async function openRecord(context, text, id, key, maxPlain, what) {
  if (typeof text !== 'string' || text.length > Math.ceil((maxPlain + 16) / 3) * 4 + 400) throw new Error(`Saved ${what} are too large.`);
  const data = JSON.parse(text);
  if (!data || Object.keys(data).sort().join() !== 'cipher,ciphertext,id,iv,version' || data.version !== 1 || data.id !== id || data.cipher !== 'AES-256-GCM') throw new Error(`Saved ${what} do not match this wallet.`);
  let bytes;
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(data.iv, 12, 12), additionalData: encoder.encode(context + JSON.stringify(header(data))), tagLength: 128 }, key, decode(data.ciphertext, maxPlain + 16)));
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { throw new Error(`Saved ${what} authentication failed.`); }
  finally { bytes?.fill(0); }
}

// The account history per network (src/history.js), saved only with a saved
// wallet, under its own key: { chain: { address, readAt, rows } }.
export const HISTORY_CONTEXT = 'nodus.wallet.history.v1';
const HISTORY_MAX_PLAIN = 400000;
export const historyKeyFor = (phrase, id) => activityKeyFor(phrase, id, HISTORY_CONTEXT);
export async function serializeHistory(id, byChain, key) {
  const value = Object.fromEntries(Object.entries(byChain).map(([chain, h]) => [chain, { address: h.address, readAt: h.readAt, rows: h.rows }]));
  return sealRecord(HISTORY_CONTEXT, id, value, key, HISTORY_MAX_PLAIN, 'history');
}
export async function parseHistory(text, id, key, now = Date.now()) {
  if (!text) return {};
  const value = await openRecord(HISTORY_CONTEXT, text, id, key, HISTORY_MAX_PLAIN, 'history');
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid saved history.');
  const out = {};
  for (const [chain, h] of Object.entries(value)) {
    if (!historySupported(chain) || !h || typeof h.address !== 'string' || h.address.length === 0 || h.address.length > 128 ||
        !Number.isSafeInteger(h.readAt) || h.readAt <= 0 || h.readAt > now + 60000) throw new Error('Invalid saved history.');
    out[chain] = { address: h.address, readAt: h.readAt, rows: checkHistoryRows(chain, h.rows) };
  }
  return out;
}

// The address book (src/address-book.js), saved only with a saved wallet,
// under its own key: [{ id, label, network, address }]. Unlike the
// balances and the history this is the user's own data, not a cache:
// src/app.js reports a failed save.
export const ADDRESS_BOOK_CONTEXT = 'nodus.wallet.addressbook.v1';
const ADDRESS_BOOK_MAX_PLAIN = 60000;
export const addressBookKeyFor = (phrase, id) => activityKeyFor(phrase, id, ADDRESS_BOOK_CONTEXT);
export async function serializeAddressBook(id, entries, key) {
  if (!Array.isArray(entries) || entries.length > ADDRESS_BOOK_MAX) throw new Error('The address book is too large to save.');
  const value = entries.map(({ id: entryId, label, network, address }) => ({ id: entryId, label, network, address }));
  return sealRecord(ADDRESS_BOOK_CONTEXT, id, value, key, ADDRESS_BOOK_MAX_PLAIN, 'address book entries');
}
// -> the checked list (src/address-book.js checkAddressBook, `validators`
// as there); anything that does not authenticate or check out throws.
export async function parseAddressBook(text, id, key, validators) {
  if (!text) return [];
  return checkAddressBook(await openRecord(ADDRESS_BOOK_CONTEXT, text, id, key, ADDRESS_BOOK_MAX_PLAIN, 'address book entries'), validators);
}

export async function serializeBalances(id, entries, key) {
  const selected = Object.entries(entries).slice(0, BALANCES_MAX).map(([asset, e]) => [asset, { units: e.units, observedAt: e.observedAt, address: e.address }]);
  return sealRecord(BALANCES_CONTEXT, id, Object.fromEntries(selected), key, BALANCES_MAX_PLAIN, 'balances');
}
// -> { assetKey: { units: bigint, observedAt, address } }; anything that does
// not authenticate or check out throws (the caller then shows nothing kept).
export async function parseBalances(text, id, key, now = Date.now()) {
  if (!text) return {};
  const entries = await openRecord(BALANCES_CONTEXT, text, id, key, BALANCES_MAX_PLAIN, 'balances');
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
// This wallet's own identity, kept with a SAVED wallet only (0.1.97,
// operator 2026-10-12: "id saklanabilir … başka saklanabilecek bir şey varsa
// o da saklanabilir"; decision 2026-10-02-device-cache-only-when-saved): the
// receive-only addresses derived after unlock (NODUS = Nodus Connect's own
// ID, Cellframe, Ixios) and the own chain name and profile picture last
// shown. Shown at once on the next unlock while the addresses are derived
// again; a derived address always wins and replaces a kept one. Sealed like
// the balances under its own HKDF info (IDENTITY_CONTEXT).
export const IDENTITY_CONTEXT = 'nodus.wallet.identity.v1';
// Network keys are checked by form, not listed by name (0.1.102): a build
// without a network (Ixios off) must carry no mention of it
// (test/browser-ixios.js), and still reads a record that a build with it
// wrote — an address of a network this build lacks is ignored where shown
// (portfolio-view.js setAddress).
// `peers` (0.1.106, operator "kişi adlarını cüzdanda saklamayı da
// yapabilirsin"): the chain names of the NODUS account history's
// counterparties, fingerprint -> name, at most IDENTITY_PEERS_MAX (the last
// ones learned), shown at once on the next unlock and asked again that
// session. 200 × ~160 B + a 20 KB picture fit IDENTITY_MAX_PLAIN.
const IDENTITY_MAX_PLAIN = 60000, IDENTITY_CHAIN_KEY = /^[a-z][a-z0-9]{1,15}$/, IDENTITY_CHAINS_MAX = 8;
export const IDENTITY_PEERS_MAX = 200;
const IDENTITY_PEER_NAME = /^[a-z0-9]{1,64}$/;  // shape only; chain-names rules are checked where shown
const IDENTITY_AVATAR_MAX = 20480;              // base64 characters (connect/ui/text.js AVATAR_MAX_B64)
export const identityKeyFor = (phrase, id) => activityKeyFor(phrase, id, IDENTITY_CONTEXT);
// -> the checked identity, or throws. Shapes only: a name or picture is
// checked again where it is shown (connect/ui/chain-names.js chainNameOk,
// connect/ui/text.js avatarSource).
export function checkIdentity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !['addresses', 'name', 'avatar', 'peers'].includes(k))) throw new Error('Invalid saved identity.');
  const peers = value.peers ?? {};
  if (!peers || typeof peers !== 'object' || Array.isArray(peers) || Object.keys(peers).length > IDENTITY_PEERS_MAX ||
      Object.entries(peers).some(([fp, name]) => !/^[0-9a-f]{128}$/.test(fp) || typeof name !== 'string' || !IDENTITY_PEER_NAME.test(name))) throw new Error('Invalid saved identity.');
  const addresses = value.addresses ?? {};
  if (!addresses || typeof addresses !== 'object' || Array.isArray(addresses) || Object.keys(addresses).length > IDENTITY_CHAINS_MAX || Object.keys(addresses).some(k => !IDENTITY_CHAIN_KEY.test(k))) throw new Error('Invalid saved identity.');
  for (const [chain, a] of Object.entries(addresses)) {
    if (typeof a !== 'string' || (chain === 'nodus' ? !/^[0-9a-f]{128}$/.test(a) : !/^[A-Za-z0-9]{1,128}$/.test(a))) throw new Error('Invalid saved identity.');
  }
  if (value.name !== undefined && (typeof value.name !== 'string' || value.name.length > 64)) throw new Error('Invalid saved identity.');
  if (value.avatar !== undefined && (typeof value.avatar !== 'string' || value.avatar.length > IDENTITY_AVATAR_MAX || !/^[A-Za-z0-9+/]*={0,2}$/.test(value.avatar))) throw new Error('Invalid saved identity.');
  return { addresses: { ...addresses }, ...(value.name ? { name: value.name } : {}), ...(value.avatar ? { avatar: value.avatar } : {}), ...(Object.keys(peers).length ? { peers: { ...peers } } : {}) };
}
export async function serializeIdentity(id, value, key) {
  return sealRecord(IDENTITY_CONTEXT, id, checkIdentity(value), key, IDENTITY_MAX_PLAIN, 'identity');
}
export async function parseIdentity(text, id, key) {
  if (!text) return { addresses: {} };
  return checkIdentity(await openRecord(IDENTITY_CONTEXT, text, id, key, IDENTITY_MAX_PLAIN, 'identity'));
}
const header = data => ({ version: data.version, id: data.id, cipher: data.cipher, iv: data.iv });
// A smart-contract transaction's Activity row must be DURABLE before its
// envelope is sent (red-team 1 F8), and Activity is saved only for a wallet
// saved in this browser (src/app.js persistActivity resolves without saving
// when there is no saved session). The EVM record callback (src/app.js
// recordEvmActivity) calls this first (red-team 2): an unsaved wallet is
// refused there, so src/evm/contract.js confirm sends nothing. The NODUS
// send path does not use it.
export function requireSavedForEvm(saved) {
  if (saved !== true) throw new Error('Smart-contract transactions need this wallet to be saved in this browser first. Save it in Device & settings, then try again. Nothing was sent.');
}
const ACTIVITY_MAX_ROWS = 100;
// A row read back by parseActivity carries `savedStatus`, the status it was
// SAVED with (its live `status` is reset to 'pending' until the tracker
// re-verifies it). A row made in this session has none.
// - unresolvedForRetention: the live status is not terminal() AND the row
//   was not saved as terminal — a row saved confirmed / failed / expired /
//   replaced / abandoned and not re-verified yet counts as resolved here.
// - savedForm: the status written. The live one, except a parsed row still
//   at its reset 'pending' whose saved status is terminal: that keeps its
//   saved status, so a re-save before the tracker runs does not turn a
//   confirmed row into a saved 'pending'.
// What holds or releases coins (src/adapters/nodus.js lockedInputs) reads
// the live status only; neither rule changes it.
const unresolvedForRetention = row => !terminal(row.status) && (row.savedStatus === undefined || !terminal(row.savedStatus));
const savedForm = row => (row.status === 'pending' && row.savedStatus !== undefined && terminal(row.savedStatus) ? row.savedStatus : row.status);
// A network whose account history this wallet reads from the chain (NODUS,
// and src/history.js HISTORY_SOURCES). There a CONFIRMED send is the chain
// list's, not this device's (0.1.91, operator 2026-10-12: "İkisi de aynı
// şeyi gösteriyor … cihazdan gösterenin bir anlamı yok") — once that list
// has SHOWN it (`listed`, set by src/app.js renderActivity when the chain
// list holds its hash / wire / block; 0.1.96, BUGS W-05): then it is not
// shown under "Sent from here" and not kept (below), so it is not verified
// again on every unlock. Until then it stays, shown and saved. A send still
// waiting, or one that never made it (failed / expired / replaced /
// abandoned), is not in the chain list and stays here. The LIVE status
// decides (0.1.96, W-08): a row saved confirmed and not re-checked yet stays
// visible, so a guard that reads the live status always has a row to act on.
export const chainListsHistory = chain => chain === NODUS_ASSET.chain || historySupported(chain);
export const confirmedOnChainList = row => chainListsHistory(row.chain) && row.status === 'confirmed' && row.listed === true;
// The "Sent from here" rows of one network (src/app.js renderActivity; pure,
// 0.1.97 so it is tested): marks `listed` on a confirmed row the chain's own
// list shows — NODUS: its wire or block in the node's page
// (nodus/history.js localRowsToShow, which also hides a pending row whose
// wire is already listed); another network: its hash among `historyRows`
// (hex compared without case) — and returns the rows still to show.
export function sentRowsToShow(all, { nodus = false, nodusPage = null, historyRows = [] } = {}) {
  if (nodus) {
    const rows = localRowsToShow(all, nodusPage, { limit: NODUS_HISTORY_LIMIT });
    const shown = new Set(rows);
    for (const row of all) if (row.status === 'confirmed' && !shown.has(row)) row.listed = true;
    return rows;
  }
  const norm = h => (typeof h === 'string' && /^(0x)?[0-9a-fA-F]+$/.test(h) ? h.toLowerCase() : h);
  const hashes = new Set((historyRows || []).map(r => norm(r.hash)));
  for (const row of all) if (row.status === 'confirmed' && hashes.has(norm(row.hash))) row.listed = true;
  return all.filter(row => !confirmedOnChainList(row));
}
// The rows kept in the saved Activity, in their given (time) order: EVERY
// unresolved row (a pending NODUS send or EVM reservation holds coins and
// must survive any number of newer rows), then the newest resolved rows up
// to ACTIVITY_MAX_ROWS in total. More unresolved rows than that cannot be
// saved (parseActivity reads at most ACTIVITY_MAX_ROWS) and are refused as
// too large, never dropped. A confirmed send of a network with a chain list
// (confirmedOnChainList above) is not kept.
function keptActivity(rows) {
  rows = rows.filter(row => !confirmedOnChainList(row));
  const open = rows.filter(unresolvedForRetention).length;
  if (open > ACTIVITY_MAX_ROWS) throw new Error('Saved activity is too large.');
  let room = ACTIVITY_MAX_ROWS - open;
  const keep = new Array(rows.length).fill(false);
  for (let i = rows.length - 1; i >= 0; i--) {
    if (unresolvedForRetention(rows[i])) keep[i] = true;
    else if (room > 0) { keep[i] = true; room--; }
  }
  return rows.filter((_, i) => keep[i]);
}
export async function serializeActivity(id, rows, key) {
  const data = { version: 2, id, cipher: 'AES-256-GCM', iv: encode(crypto.getRandomValues(new Uint8Array(12))) };
  // expiryHeight / fromHeight / inputs exist only on NODUS rows; JSON drops
  // them (undefined) for every other network, whose saved form is unchanged.
  // `status` is written as savedForm (above); `savedStatus` is never written.
  const selected = keptActivity(rows).map(row => {
    const { chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, nonce, createdAt, expiryHeight, fromHeight, inputs, tokenId } = row;
    // tokenId: a pinned token's NODUS send only (src/activity.js recordActivity);
    // absent (dropped by JSON) for every native row and every other network.
    return { chain, address, to, symbol, amount, hash, lastValidBlockHeight, expiration, nonce, createdAt, status: savedForm(row), expiryHeight, fromHeight, inputs, tokenId };
  });
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
    // tokenId (design docs/plans/2026-10-22-connect-native-tokens-design.md
    // §6 item 7): a row without one is a native row (its symbol NODUS, as
    // every row saved before tokens); one WITH one is a token send — 128 hex,
    // not all zero (a native send never writes it), and a symbol of the
    // wallet's own shape. Whether the token is still pinned is NOT judged
    // here: such a row is kept either way (its coins stay held) and shown
    // "unknown token" by src/activity.js activitySymbol, so one token row
    // never costs the whole file. Any other network's row has none.
    const tokenRow = nodus && row.tokenId !== undefined;
    if (!nodus && row?.tokenId !== undefined) throw new Error('Invalid saved activity.');
    if (nodus && (!(addresses.nodus === undefined ? /^[0-9a-f]{128}$/.test(row.address) : row.address === addresses.nodus)
        || (tokenRow ? typeof row.tokenId !== 'string' || !/^[0-9a-f]{128}$/.test(row.tokenId) || row.tokenId === '0'.repeat(128) || typeof row.symbol !== 'string' || !/^[A-Za-z0-9]{1,12}$/.test(row.symbol) : row.symbol !== NODUS_ASSET.symbol)
        || !/^[0-9a-f]{128}$/.test(row.to) || !validNodusPending(row) || row.lastValidBlockHeight !== undefined || row.expiration !== undefined || row.nonce !== undefined)) throw new Error('Invalid saved activity.');
    if (!row || !(nodus || Object.hasOwn(CHAINS, row.chain)) || (!nodus && row.address !== addresses[row.chain]) || !validHash(row.chain, row.hash) || typeof row.to !== 'string' || row.to.length > 128 || typeof row.symbol !== 'string' || row.symbol.length > 12 || typeof row.amount !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(row.amount) || typeof row.createdAt !== 'string' || !Number.isFinite(Date.parse(row.createdAt)) || !(row.nonce === undefined || Number.isSafeInteger(row.nonce)) || !['pending','included','unknown','confirmed','failed','expired','replaced','abandoned'].includes(row.status)) throw new Error('Invalid saved activity.');
    if (row.lastValidBlockHeight !== undefined && (!Number.isSafeInteger(row.lastValidBlockHeight) || row.lastValidBlockHeight < 0)) throw new Error('Invalid saved expiry.');
    if (row.expiration !== undefined && (!Number.isSafeInteger(row.expiration) || row.expiration < 0)) throw new Error('Invalid saved expiry.');
    // Every saved status is re-verified from the network (NODUS included: an
    // 'expired' row locks its coins again until a fresh scan says so). The
    // status it was saved with stays in memory as `savedStatus`, for
    // serializeActivity's retention and re-save only (keptActivity / savedForm).
    return { savedStatus: row.status, chain: row.chain, address: row.address, to: row.to, symbol: row.symbol, amount: row.amount, endpoint: nodus ? undefined : CHAINS[row.chain].endpoint, hash: row.hash, createdAt: row.createdAt, lastValidBlockHeight: row.lastValidBlockHeight, expiration: row.expiration, nonce: row.nonce, ...(nodus ? { expiryHeight: row.expiryHeight, fromHeight: row.fromHeight, inputs: [...row.inputs], ...(tokenRow ? { tokenId: row.tokenId } : {}) } : {}), ...(row.status === 'abandoned' ? { status: 'abandoned', note: 'Marked abandoned by you; the network may still include it. Check the explorer.' } : { status: 'pending', note: 'Authenticated local record; verifying network status.' }) };
  });
}
