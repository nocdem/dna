// Shared vaults — the pure part: the vault message kinds, the kept vault
// record, the block-reading bookkeeping and a payment request's status.
// No DOM, no module: src/vaults/ui.js drives the module (src/nodus/
// send-module.js "SHARED VAULTS") and Messages (src/connect/ui/messages.js
// vaultHost); test/vaults.test.js exercises this file.
//
// Governing records: docs/plans/decisions/2026-09-29-general-multisig.md
// (M-of-N address, at most 7 keys per address, auth_kind 3, validity tip +
// 90 blocks) with design docs/plans/2026-09-29-general-multisig-design.md
// §7 rev 2; docs/plans/decisions/2026-09-25-web-wallet-nodus-send-
// transport.md (every byte rule is the C code nodus-cli uses — nothing in
// this file derives an address, decodes an envelope or checks a signature;
// it only checks the SHAPE of what it hands to the module); operator
// 2026-10-03 (vaults in Nodus Connect; a vault is listed only for its
// members, watch-only only when a user adds one by hand).
//
// MESSAGE KINDS — a 1:1 Messages text, JSON, "type": "nodus_vault", "v": 1
// (nc_plaintext_is_chat counts it as chat text, so Messages stores and
// acknowledges it like any text; the DNA Connect app shows it raw):
//   share     { kind, label, code, created }
//             code = the vault code (the descriptor as lowercase hex);
//             created = the block height to start reading its history at.
//             The receiver derives the address and the member IDs FROM the
//             code in the module — nothing in the message names them.
//   request   { kind, vault, chain, tip, signers, digest, env }
//             a payment request: nodus-cli's export without the unsigned
//             auth blob (nodus-send-wasm.c "VAULTS" / transport); the
//             receiver rebuilds it from its own copy of the vault code.
//             No description of the payment travels: the page shows only
//             what the module reads back from these bytes.
//   approval  { kind, vault, digest, signature }
//             signature = nodus-cli's signature text ("nodus-msig-sig v1").
// Every field is required and no other key is accepted; anything else is
// { kind: 'invalid' } and shown as such.

export const VAULT_MESSAGE_TYPE = 'nodus_vault';
export const VAULT_MESSAGE_VERSION = 1;
export const VAULT_MIN_MEMBERS = 2;            // shared/dnac/msig_wire.h DNA_MSIG_MIN_N
export const VAULT_MAX_MEMBERS = 7;            // DNA_MSIG_MAX_N (decision: "maksimum 7 anahtar")
export const VAULT_MAX_APPROVALS = 15;         // NODUS_RT_AUTH_MAX_SIGNERS
export const VAULT_LABEL_MAX = 48;             // characters
export const VAULT_MAX_COINS = 64;             // nodus-send-wasm.c NSW_MS_MAX_COINS
export const VAULT_MAX_EVENTS = 32;            // NSW_MS_MAX_EVENTS
export const VAULT_ENV_HEX_MAX = 2 * 65536;    // NSW_MS_PREFIX_MAX
export const VAULT_SIG_TEXT_MAX = 32768;       // NODUS_V2_MSIG_SIG_TEXT_MAX
export const VAULT_PAYLOAD_MAX = 60000;        // messages.js PAYLOAD_TEXT_MAX
// A kept record stays below one stored record (store.js PLAINTEXT_MAX 65536).
export const VAULT_RECORD_MAX = 60000;

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/, U64 = /^(0|[1-9]\d{0,19})$/;
// "NDS.MSIG.v1" zero-padded to 16 bytes, M, N, then 2..7 keys of 2592 bytes.
export const VAULT_CODE = /^4e44532e4d5349472e7631(00){5}[0-9a-f]{4}([0-9a-f]{5184}){2,7}$/;
const SIG_MAGIC = 'nodus-msig-sig v1\n';
const u64ok = (value, { min = 0n } = {}) => typeof value === 'string' && U64.test(value) && BigInt(value) < 2n ** 64n && BigInt(value) >= min;

// The (M, N) a vault code's header states, or null when the code is not the
// shape of one (the module checks everything else).
export function vaultCodeShape(code) {
  if (typeof code !== 'string' || !VAULT_CODE.test(code)) return null;
  const m = parseInt(code.slice(32, 34), 16), n = parseInt(code.slice(34, 36), 16);
  if (n < VAULT_MIN_MEMBERS || n > VAULT_MAX_MEMBERS || m < 1 || m > n) return null;
  if (code.length !== 2 * (18 + n * 2592)) return null;
  return { m, n };
}

// A label someone typed: trimmed, no control characters, at most
// VAULT_LABEL_MAX characters. '' is allowed (the page then shows a default).
export function vaultLabel(value) {
  if (typeof value !== 'string') throw new Error('Invalid vault name.');
  const label = value.trim();
  // C0 / C1 control characters and the two Unicode line separators — checked
  // on the value as given, before trimming: trim() also removes U+2028/U+2029,
  // so a separator at an edge would otherwise pass silently.
  const control = c => { const p = c.codePointAt(0); return p < 0x20 || (p >= 0x7f && p <= 0x9f) || p === 0x2028 || p === 0x2029; };
  if ([...label].length > VAULT_LABEL_MAX || [...value].some(control)) throw new Error(`A vault name can have at most ${VAULT_LABEL_MAX} characters, without line breaks.`);
  return label;
}

const frame = (kind, fields) => JSON.stringify({ type: VAULT_MESSAGE_TYPE, v: VAULT_MESSAGE_VERSION, kind, ...fields });
const fits = text => { if (new TextEncoder().encode(text).length > VAULT_PAYLOAD_MAX) throw new Error('This vault item is too large to send.'); return text; };

export function encodeShare({ code, label = '', created }) {
  if (!vaultCodeShape(code)) throw new Error('This is not a valid vault.');
  if (!u64ok(created, { min: 1n })) throw new Error('Invalid block height.');
  return fits(frame('share', { label: vaultLabel(label), code, created }));
}

export function checkRequest(request) {
  const r = request || {};
  if (!HEX64.test(r.chain ?? '') || !u64ok(r.tip, { min: 1n }) || !u64ok(r.signers, { min: 1n }) || BigInt(r.signers) > BigInt(VAULT_MAX_APPROVALS) ||
      !HEX128.test(r.digest ?? '') || typeof r.env !== 'string' || r.env.length === 0 || r.env.length > VAULT_ENV_HEX_MAX || !/^([0-9a-f]{2})+$/.test(r.env)) throw new Error('This payment request is damaged.');
  return { chain: r.chain, tip: r.tip, signers: r.signers, digest: r.digest, env: r.env };
}

export function encodeRequest({ vault, request }) {
  if (!HEX128.test(vault ?? '')) throw new Error('Invalid vault.');
  return fits(frame('request', { vault, ...checkRequest(request) }));
}

export function encodeApproval({ vault, digest, signature }) {
  if (!HEX128.test(vault ?? '') || !HEX128.test(digest ?? '')) throw new Error('Invalid approval.');
  if (typeof signature !== 'string' || !signature.startsWith(SIG_MAGIC) || signature.length > VAULT_SIG_TEXT_MAX) throw new Error('Invalid approval.');
  return fits(frame('approval', { vault, digest, signature }));
}

const KEYS = {
  share: ['type', 'v', 'kind', 'label', 'code', 'created'],
  request: ['type', 'v', 'kind', 'vault', 'chain', 'tip', 'signers', 'digest', 'env'],
  approval: ['type', 'v', 'kind', 'vault', 'digest', 'signature']
};

// A stored message text -> null (not a vault item), { kind: 'invalid' }, or
// one of the kinds above, checked.
export function decodeVaultMessage(text) {
  if (typeof text !== 'string' || text.length > VAULT_PAYLOAD_MAX || !text.startsWith('{')) return null;
  let value;
  try { value = JSON.parse(text); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.type !== VAULT_MESSAGE_TYPE) return null;
  const invalid = { kind: 'invalid' };
  if (value.v !== VAULT_MESSAGE_VERSION || !Object.hasOwn(KEYS, value.kind)) return invalid;
  const keys = Object.keys(value);
  if (keys.length !== KEYS[value.kind].length || !KEYS[value.kind].every(k => Object.hasOwn(value, k))) return invalid;
  try {
    if (value.kind === 'share') {
      if (!vaultCodeShape(value.code) || !u64ok(value.created, { min: 1n })) return invalid;
      return { kind: 'share', code: value.code, label: vaultLabel(value.label), created: value.created };
    }
    if (value.kind === 'request') {
      if (!HEX128.test(value.vault ?? '')) return invalid;
      return { kind: 'request', vault: value.vault, request: checkRequest(value) };
    }
    if (!HEX128.test(value.vault ?? '') || !HEX128.test(value.digest ?? '') || typeof value.signature !== 'string' ||
        !value.signature.startsWith(SIG_MAGIC) || value.signature.length > VAULT_SIG_TEXT_MAX) return invalid;
    return { kind: 'approval', vault: value.vault, digest: value.digest, signature: value.signature };
  } catch { return invalid; }
}

// ── the kept vault record ────────────────────────────────────────────────
// { v: 1, label, code, address, m, n, members: [ID], created, cursor, coins:
//   [{ id, amount, unlock, height }], events: [{ height, received, amount,
//   id }], watch, from, foundation }
// address / m / n / members come from the module (vaultOpen) — a record is
// made only from its answer.

// `genesisCoins` (the Foundation preset's, src/vaults/foundation.js): coins
// the vault holds from genesis — in no block, so they are the starting set
// the block reading continues from (a block that consumes one removes it,
// nodus-send-wasm.c nsw_ms_apply_item). The record is marked `genesis:
// true` so a record kept before they existed is seeded again.
export function makeVaultRecord({ info, label = '', created, watch = false, from = '', foundation = false, genesisCoins = [] }) {
  if (!info || !HEX128.test(info.address ?? '') || !vaultCodeShape(info.descriptor) || !Array.isArray(info.members) || !info.members.every(fp => HEX128.test(fp))) throw new Error('This is not a valid vault.');
  if (!u64ok(created, { min: 1n })) throw new Error('Invalid block height.');
  if (!Array.isArray(genesisCoins) || genesisCoins.length > VAULT_MAX_COINS ||
      !genesisCoins.every(c => c && HEX128.test(c.id ?? '') && u64ok(c.amount, { min: 1n }) && u64ok(c.unlock) && c.height === '0') ||
      new Set(genesisCoins.map(c => c.id)).size !== genesisCoins.length) throw new Error('Invalid genesis coins.');
  return {
    v: 1, label: vaultLabel(label), code: info.descriptor, address: info.address, m: info.m, n: info.n, members: [...info.members],
    created, cursor: created, coins: genesisCoins.map(c => ({ id: c.id, amount: c.amount, unlock: c.unlock, height: c.height })), events: [],
    watch: watch === true, from: HEX128.test(from) ? from : '', foundation: foundation === true, genesis: genesisCoins.length > 0
  };
}

// A kept record read back (store, memory): every field checked; a broken
// one is refused (the caller drops it).
export function checkVaultRecord(value) {
  const r = value || {};
  const shape = vaultCodeShape(r.code);
  if (r.v !== 1 || !shape || !HEX128.test(r.address ?? '') || r.m !== shape.m || r.n !== shape.n ||
      !Array.isArray(r.members) || r.members.length !== shape.n || !r.members.every(fp => HEX128.test(fp)) ||
      !u64ok(r.created, { min: 1n }) || !u64ok(r.cursor, { min: 1n }) || !Array.isArray(r.coins) || r.coins.length > VAULT_MAX_COINS ||
      !r.coins.every(c => c && HEX128.test(c.id ?? '') && u64ok(c.amount, { min: 1n }) && u64ok(c.unlock) && u64ok(c.height)) ||
      !Array.isArray(r.events) || r.events.length > VAULT_MAX_EVENTS ||
      !r.events.every(e => e && u64ok(e.height) && typeof e.received === 'boolean' && u64ok(e.amount) && (e.id === '' || HEX128.test(e.id ?? ''))) ||
      typeof r.watch !== 'boolean' || typeof r.from !== 'string' || (r.from !== '' && !HEX128.test(r.from)) || typeof r.foundation !== 'boolean' ||
      (r.genesis !== undefined && typeof r.genesis !== 'boolean')) throw new Error('A kept vault is damaged.');
  return { ...r, label: vaultLabel(r.label ?? ''), genesis: r.genesis === true };
}

// What is written to the store: within VAULT_RECORD_MAX bytes. The history
// goes first, then the found coins (the next reading starts again at the
// vault's first block).
export function recordForStorage(record) {
  const size = r => new TextEncoder().encode(JSON.stringify(r)).length;
  let r = { ...record };
  if (size(r) <= VAULT_RECORD_MAX) return r;
  r = { ...r, events: [] };
  if (size(r) <= VAULT_RECORD_MAX) return r;
  // a vault seeded with genesis coins must not lose them: mark it unseeded,
  // it is seeded again from the preset when it is loaded (src/vaults/ui.js)
  return { ...r, coins: [], cursor: r.created, genesis: false };
}

// One block-reading step (the module's vaultScan answer) applied: the found
// coins replace the old set, the cursor moves, new history items are added
// (newest kept, at most VAULT_MAX_EVENTS).
export function applyScan(record, result) {
  if (!result || !u64ok(result.next, { min: 1n }) || !u64ok(result.tip) || !Array.isArray(result.coins) || !Array.isArray(result.events)) throw new Error('The vault history could not be read.');
  if (BigInt(result.next) < BigInt(record.cursor)) throw new Error('The vault history could not be read.');
  const seen = new Set(record.events.map(e => `${e.height}|${e.id}|${e.received}`));
  const events = [...record.events];
  for (const e of result.events) {
    const key = `${e.height}|${e.id}|${e.received}`;
    if (!seen.has(key)) { seen.add(key); events.push({ height: e.height, received: e.received, amount: e.amount, id: e.id }); }
  }
  events.sort((a, b) => (BigInt(a.height) < BigInt(b.height) ? -1 : BigInt(a.height) > BigInt(b.height) ? 1 : 0));
  return { ...record, cursor: result.next, coins: result.coins.map(c => ({ id: c.id, amount: c.amount, unlock: c.unlock, height: c.height })), events: events.slice(-VAULT_MAX_EVENTS) };
}

// The total of the found coins (raw units, BigInt).
export function foundTotal(record) {
  return record.coins.reduce((sum, c) => sum + BigInt(c.amount), 0n);
}

// The "pubkey" line of a signature text (lowercase hex, 5184 characters),
// or '' — used only to count one approval per key: the module checks every
// approval itself (nodus_v2_msig_sig_check), and an ML-DSA-87 signature is
// hedged, so one member approving twice gives two DIFFERENT texts.
export function approvalKey(signature) {
  const match = typeof signature === 'string' ? /\npubkey ([0-9a-f]{5184})\n/.exec(signature) : null;
  return match ? match[1] : '';
}

// ── payment requests in the stored messages ─────────────────────────────
// messages: [{ fp, dir, text, at }] (vaultHost.messages). Returns, for one
// vault address, its requests by digest — { request, from (ID, or '' for
// this wallet's own), at } —, the approval texts by digest (one per key,
// approvalKey), and the digests this wallet already sent an approval for.
export function collectVaultItems(messages, address) {
  const requests = new Map(), approvals = new Map(), approvedHere = new Set();
  for (const m of messages) {
    const item = decodeVaultMessage(m.text);
    if (!item || item.kind === 'invalid' || item.vault !== address) continue;
    if (item.kind === 'request') {
      const digest = item.request.digest;
      if (!requests.has(digest)) requests.set(digest, { request: item.request, from: m.dir === 'out' ? '' : m.fp, at: m.at });
    } else if (item.kind === 'approval') {
      const key = approvalKey(item.signature);
      if (!key) continue;
      if (!approvals.has(item.digest)) approvals.set(item.digest, new Map());
      if (!approvals.get(item.digest).has(key)) approvals.get(item.digest).set(key, item.signature);
      if (m.dir === 'out') approvedHere.add(item.digest);
    }
  }
  return { requests, approvals: new Map([...approvals].map(([d, byKey]) => [d, [...byKey.values()]])), approvedHere };
}

// A request's state for the page, from the module's read-back (`review`),
// the approvals the module accepted (`accepted`) and the vault's history:
//   'paid'     the vault history holds its transaction (review.intentId)
//   'expired'  the network passed its last valid block: propose again
//   'ready'    enough approvals: it can be sent
//   'waiting'  more approvals are needed
export function requestState({ review, accepted, record }) {
  if (review?.intentId && record?.events?.some(e => e.id === review.intentId)) return 'paid';
  if (review?.expired) return 'expired';
  if (accepted >= (review?.approvals ?? Infinity)) return 'ready';
  return 'waiting';
}

// Blocks left before a request expires (BigInt, 0n when expired).
export function blocksLeft(review) {
  if (!review || !u64ok(review.expiryHeight) || !u64ok(review.tip)) return 0n;
  const left = BigInt(review.expiryHeight) - BigInt(review.tip);
  return left > 0n ? left : 0n;
}

// Whether this wallet may list the vault: only when its own ID is one of
// the members (operator 2026-10-03), unless the user added it by hand to
// watch it.
export function listedFor(record, ownFp) {
  return record.watch === true || (HEX128.test(ownFp ?? '') && record.members.includes(ownFp));
}
