// Shared vaults — the pure part: the vault message kinds, the kept vault
// record, the node's coin answer applied to it and a payment request's
// status.
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
//             created = the block height the vault was made at (kept in
//             the record; since 0.1.82 nothing reads blocks from it — the
//             key stays because every client decodes exactly these keys).
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

import { inspectUntrusted } from '../connect/ui/text.js';

export const VAULT_MESSAGE_TYPE = 'nodus_vault';
export const VAULT_MESSAGE_VERSION = 1;
export const VAULT_MIN_MEMBERS = 2;            // shared/dnac/msig_wire.h DNA_MSIG_MIN_N
export const VAULT_MAX_MEMBERS = 7;            // DNA_MSIG_MAX_N (decision: "maksimum 7 anahtar")
export const VAULT_MAX_APPROVALS = 15;         // NODUS_RT_AUTH_MAX_SIGNERS
export const VAULT_LABEL_MAX = 48;             // characters
export const VAULT_MAX_COINS = 64;             // nodus-send-wasm.c NSW_MS_MAX_COINS
// The `events` a record kept by 0.1.80 / 0.1.81 may still carry (the block
// reading's history, at most 32): still accepted when such a record is read
// back, never shown and never written again (see "the kept vault record").
export const VAULT_MAX_EVENTS = 32;
// The Error.code of vaultCoins / vaultHistory when the node does not have
// the member query (src/nodus/send-module.js).
export const VAULT_UNSUPPORTED = 'unsupported';
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
// The preset's name (src/vaults/foundation.js label): a shared vault may not
// take it, in any letter case or spacing (F4).
export const RESERVED_VAULT_LABEL = 'foundation vault';
const reservedLabel = label => label.toLowerCase().replace(/\s+/g, ' ').trim() === RESERVED_VAULT_LABEL;

export function vaultLabel(value, { reservedOk = false } = {}) {
  if (typeof value !== 'string') throw new Error('Invalid vault name.');
  const label = value.trim();
  // C0 / C1 control characters and the two Unicode line separators — checked
  // on the value as given, before trimming: trim() also removes U+2028/U+2029,
  // so a separator at an edge would otherwise pass silently.
  const control = c => { const p = c.codePointAt(0); return p < 0x20 || (p >= 0x7f && p <= 0x9f) || p === 0x2028 || p === 0x2029; };
  if ([...label].length > VAULT_LABEL_MAX || [...value].some(control)) throw new Error(`A vault name can have at most ${VAULT_LABEL_MAX} characters, without line breaks.`);
  // F4: the same untrusted-text rule Messages applies to names other people
  // wrote (src/connect/ui/text.js inspectUntrusted): direction controls,
  // invisible characters or mixed Latin / Cyrillic / Greek are refused, not
  // shown.
  if (inspectUntrusted(value, { name: true }).unusual) throw new Error('A vault name cannot contain invisible or direction-changing characters, or mix alphabets.');
  if (!reservedOk && reservedLabel(label)) throw new Error('“Foundation vault” is the name of the Foundation’s own vault; choose another name.');
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
//   [{ id, amount, unlock, height }], events: [], watch, from, foundation }
// address / m / n / members come from the module (vaultOpen) — a record is
// made only from its answer.
//
// coins = the node's LAST answer to the member query (vaultCoins), replaced
// on every Open / Refresh; actions hand them back to the module (F1: a
// request may spend only these). Between answers they are the last ones
// seen — the next Open replaces them.
//
// RECORD COMPATIBILITY (0.1.82): the shape is the one 0.1.80 / 0.1.81 kept,
// so every record already in a browser loads unchanged. Their block-reading
// fields are still accepted and ignored: `cursor` (the next block to read —
// now always written as `created`, never read), `events` (that reading's
// history — accepted up to VAULT_MAX_EVENTS, dropped when read back: the
// history comes from the node's page now) and the Foundation preset's
// `genesis` flag (whether its genesis coins were seeded — the member query
// returns those coins itself; dropped when read back). New records carry
// the same keys, so the checker never needs two shapes.
export function makeVaultRecord({ info, label = '', created, watch = false, from = '', foundation = false }) {
  if (!info || !HEX128.test(info.address ?? '') || !vaultCodeShape(info.descriptor) || !Array.isArray(info.members) || !info.members.every(fp => HEX128.test(fp))) throw new Error('This is not a valid vault.');
  if (!u64ok(created, { min: 1n })) throw new Error('Invalid block height.');
  return {
    v: 1, label: vaultLabel(label, { reservedOk: foundation === true }), code: info.descriptor, address: info.address, m: info.m, n: info.n, members: [...info.members],
    created, cursor: created, coins: [], events: [],
    watch: watch === true, from: HEX128.test(from) ? from : '', foundation: foundation === true
  };
}

// A kept record read back (store, memory): every field's SHAPE checked; a
// broken one is refused (the caller drops it). The address and member IDs
// are NOT re-derived here (no second copy of the derivation in JS):
// src/vaults/ui.js loadVaults asks the module (vaultOpen) for the kept code
// and drops a record whose address, M, N or members differ. A 0.1.80 /
// 0.1.81 record (cursor past `created`, block-reading `events`, `genesis`)
// is accepted; its `events` and `genesis` are dropped (see above).
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
  const out = { ...r, label: vaultLabel(r.label ?? '', { reservedOk: r.foundation === true }), events: [] };
  delete out.genesis;
  return out;
}

// What is written to the store: within VAULT_RECORD_MAX bytes. If the
// coins do not fit, they are left out (the next Open asks the node again).
export function recordForStorage(record) {
  const size = r => new TextEncoder().encode(JSON.stringify(r)).length;
  const r = { ...record, events: [] };
  if (size(r) <= VAULT_RECORD_MAX) return r;
  return { ...r, coins: [] };
}

// The node's coin answer (vaultCoins: { coins, truncated }) applied: the
// coins REPLACE the record's (the node's unspent set is the whole truth, a
// coin it no longer lists was spent). Each coin's shape is checked, at most
// VAULT_MAX_COINS, no coin twice; anything else throws and the record is
// kept as it was. -> { record, truncated }
export function applyCoins(record, result) {
  const bad = () => new Error('The Nodus node returned an invalid vault coin list.');
  if (!result || !Array.isArray(result.coins) || typeof result.truncated !== 'boolean' || result.coins.length > VAULT_MAX_COINS) throw bad();
  if (!result.coins.every(c => c && HEX128.test(c.id ?? '') && u64ok(c.amount, { min: 1n }) && u64ok(c.unlock) && u64ok(c.height)) ||
      new Set(result.coins.map(c => c.id)).size !== result.coins.length) throw bad();
  return { record: { ...record, coins: result.coins.map(c => ({ id: c.id, amount: c.amount, unlock: c.unlock, height: c.height })) }, truncated: result.truncated };
}

// At most this many approval texts per sender are handed to the module for
// one check (newest first): a member flooding junk approvals costs at most
// this many signature checks, and only that member's own approval can be
// pushed out by it (F2).
export const VAULT_APPROVAL_TRIES_PER_SENDER = 8;

// ── payment requests in the stored messages ─────────────────────────────
// messages: [{ fp, dir, text, at }] (vaultHost.messages); members: the
// vault's member IDs; ownFp: this wallet's ID. Returns, for one vault
// address:
//   requests     by digest — { request, from (ID, or '' for this wallet's
//                own), at }
//   approvals    by digest — [{ text, sender }]: the CANDIDATES the module
//                verifies (F2: nothing is counted here; one exact text per
//                sender once; at most VAULT_APPROVAL_TRIES_PER_SENDER per
//                sender, newest first)
//   approvedHere the digests this wallet sent an approval for
// An item received from someone who is NOT a member of the vault it names
// is ignored (F2).
export function collectVaultItems(messages, address, members = [], ownFp = '') {
  const requests = new Map(), raw = new Map(), approvedHere = new Set();
  const isMember = new Set(members);
  for (const m of [...messages].sort((a, b) => b.at - a.at)) {
    const item = decodeVaultMessage(m.text);
    if (!item || item.kind === 'invalid' || item.vault !== address) continue;
    const sender = m.dir === 'out' ? ownFp : m.fp;
    if (m.dir !== 'out' && !isMember.has(sender)) continue;
    if (item.kind === 'request') {
      const digest = item.request.digest;
      const prev = requests.get(digest);
      // the oldest item names who proposed it
      if (!prev || m.at < prev.at) requests.set(digest, { request: item.request, from: m.dir === 'out' ? '' : m.fp, at: m.at });
    } else if (item.kind === 'approval') {
      if (m.dir === 'out') approvedHere.add(item.digest);
      if (!HEX128.test(sender ?? '')) continue;
      if (!raw.has(item.digest)) raw.set(item.digest, new Map());
      const bySender = raw.get(item.digest);
      if (!bySender.has(sender)) bySender.set(sender, []);
      const list = bySender.get(sender);
      if (list.length < VAULT_APPROVAL_TRIES_PER_SENDER && !list.includes(item.signature)) list.push(item.signature);
    }
  }
  const approvals = new Map();
  for (const [digest, bySender] of raw) {
    const out = [];
    for (const [sender, texts] of bySender) for (const text of texts) out.push({ text, sender });
    approvals.set(digest, out);
  }
  return { requests, approvals, approvedHere };
}

// A request's state for the page, from the module's read-back (`review`),
// the approvals the module accepted (`accepted`), the vault's record (its
// coins: the node's last answer), whether that answer was cut short
// (`truncated`), the full-wire id THIS wallet submitted it under (`wireId`,
// '' when another member sent it or it was not sent from here) and the
// vault's history page (`history`, parseAddrHistory's answer or null):
//   'paid'     the history holds a row of the envelope this wallet sent
//              (its wire id — history rows carry the wire id, not the
//              intent id, nodus_witness_addr_index.h "wire")
//   'spent'    a coin it spends is no longer among the vault's coins (and
//              the node's answer was complete): it was paid — by whichever
//              member sent it — or another payment used that coin; either
//              way it can never be sent now. (Its review was made against
//              coins that held it, so the coin left the vault since.)
//   'expired'  the network passed its last valid block: propose again
//   'ready'    enough approvals: it can be sent
//   'waiting'  more approvals are needed
export function requestState({ review, accepted, record, truncated = false, wireId = '', history = null }) {
  if (HEX128.test(wireId ?? '') && history?.entries?.some(e => e.wire === wireId)) return 'paid';
  if (!truncated && Array.isArray(review?.inputs) && review.inputs.length && Array.isArray(record?.coins)) {
    const held = new Set(record.coins.map(c => c.id));
    if (review.inputs.some(id => !held.has(id))) return 'spent';
  }
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
