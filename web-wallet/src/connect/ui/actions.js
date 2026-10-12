// Message actions (web 0.1.89): reactions, delete notices and replies — the
// SAME plaintext forms the DNA Connect app writes and reads, so a message,
// reaction or deletion made here shows the same in the app (and in Jarvis's
// tool) and the other way round. Pure functions: no DOM, no network.
//
// Sources (read 2026-10-09):
//  - content hash: messenger/message_backup.c compute_content_hash
//    (:122-150) = SHA3-256 over sender fp ‖ recipient fp ‖ plaintext ‖
//    decimal timestamp, lowercase hex. The receiver uses the Seal's (sender's)
//    timestamp (messenger_transport.c:913); the app's sender uses the time
//    its message was QUEUED (messages.c:239, dna_engine_messaging.c:53)
//    while the Seal carries the send time (messages.c:37) — when the two
//    differ the app itself cannot match a reaction to that message. This
//    page always uses the Seal timestamp (its own sends put the same value
//    in both), so page <-> page always matches. Checked against the app
//    library's own stored hashes (test/connect-actions.test.js).
//  - reaction: messenger/src/reaction/reaction_json.c
//    dna_reaction_build_json `{"target":"<64 hex>","emoji":"<e>","op":"add|remove"}`
//    and its substring parsers; the 8 emojis of
//    dna_messenger_flutter/lib/screens/chat/widgets/reaction_emoji_bar.dart:5-14.
//  - delete notice: messenger/messenger/messages.c messenger_send_delete_notice
//    (:1323-1356) {"type":"delete","action":0,"hashes":[...]}; the receiver
//    marks those hashes "deleted by sender" (messenger_transport.c:875-889).
//  - reply: chat_screen.dart _sendMessage (:1058-1071) "↩ Re: <sender>\n> <quote>\n<text>"
//    and _parseReplyData (:2087-2105).
import { sha3_256 } from '@noble/hashes/sha3';

const HEX128 = /^[0-9a-f]{128}$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;
const U64 = /^(0|[1-9]\d{0,19})$/;

export const REACTION_EMOJIS = Object.freeze(['❤️', '👍', '😂', '😮', '😢', '🙏', '🔥', '🎉']);

const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

// The app reads its C strings up to the first NUL (strlen).
const cString = text => { const s = String(text); const i = s.indexOf('\0'); return i < 0 ? s : s.slice(0, i); };

export function contentHash(senderFp, recipientFp, text, ts) {
  if (!HEX128.test(senderFp) || !HEX128.test(recipientFp) || !U64.test(String(ts))) return null;
  return toHex(sha3_256(new TextEncoder().encode(senderFp + recipientFp + cString(text) + String(BigInt(ts)))));
}

// The hash of a stored 1:1 message record of this page: own sends carry `ts`
// (the Seal timestamp the page wrote), received ones `senderTs`.
export function messageHash(m, ownFp) {
  if (!m || (m.dir !== 'in' && m.dir !== 'out')) return null;
  return m.dir === 'out'
    ? contentHash(ownFp, m.fp, m.text, m.ts)
    : contentHash(m.fp, ownFp, m.text, m.senderTs);
}

// ── reactions ───────────────────────────────────────────────────────────
export function buildReaction(target, emoji, op) {
  if (!HEX64.test(target) || !REACTION_EMOJIS.includes(emoji) || (op !== 'add' && op !== 'remove')) throw new Error('Invalid reaction.');
  return `{"target":"${target}","emoji":"${emoji}","op":"${op}"}`;
}

// The app's substring readers: the value after `"<name>":"` up to the next '"'.
const field = (s, name) => {
  const prefix = `"${name}":"`, at = s.indexOf(prefix);
  if (at < 0) return null;
  const start = at + prefix.length, end = s.indexOf('"', start);
  return end < 0 ? null : s.slice(start, end);
};

export function parseReaction(text) {
  const s = cString(text);
  const target = field(s, 'target'), emoji = field(s, 'emoji'), op = field(s, 'op');
  // The app replays only an emoji that fits its char[8] (message_backup.c
  // :771-773, reaction_json.c dna_reaction_parse_emoji): 1..7 bytes.
  if (!target || !HEX64.test(target) || (op !== 'add' && op !== 'remove') || !emoji ||
      new TextEncoder().encode(emoji).length > 7) return null;
  return { target, emoji, op };
}

// target hash -> [{ emoji, count, mine }] in REACTION_EMOJIS order, then any
// other emoji in first-seen order. Every reaction record of the
// conversation is replayed in sender-time order (the app's (reactor, emoji,
// op) replay): the last op of a reactor for an emoji wins.
export function reactionSummary(records, ownFp) {
  const rows = [];
  for (const m of records) {
    if (m.kind !== 'reaction') continue;
    const r = parseReaction(m.text);
    if (!r) continue;
    const reactor = m.dir === 'out' ? ownFp : m.fp;
    const ts = m.dir === 'out' ? m.ts : m.senderTs;
    if (!U64.test(String(ts))) continue;
    rows.push({ ...r, reactor, ts: BigInt(ts), seq: BigInt(m.seq ?? 0) });
  }
  rows.sort((a, b) => (a.ts === b.ts ? (a.seq < b.seq ? -1 : a.seq > b.seq ? 1 : 0) : a.ts < b.ts ? -1 : 1));
  const state = new Map();                         // target -> Map(emoji -> Map(reactor -> on))
  for (const r of rows) {
    const key = r.target.toLowerCase();
    if (!state.has(key)) state.set(key, new Map());
    const byEmoji = state.get(key);
    if (!byEmoji.has(r.emoji)) byEmoji.set(r.emoji, new Map());
    byEmoji.get(r.emoji).set(r.reactor, r.op === 'add');
  }
  const out = new Map();
  for (const [target, byEmoji] of state) {
    const list = [];
    for (const [emoji, who] of byEmoji) {
      const on = [...who.entries()].filter(([, v]) => v);
      if (on.length) list.push({ emoji, count: on.length, mine: on.some(([k]) => k === ownFp) });
    }
    list.sort((a, b) => order(a.emoji) - order(b.emoji));
    if (list.length) out.set(target, list);
  }
  return out;
}
const order = e => { const i = REACTION_EMOJIS.indexOf(e); return i < 0 ? REACTION_EMOJIS.length : i; };

// Whether own reaction `emoji` is on for `target` (the menu toggles it).
export function ownReactionOn(summary, target, emoji) {
  return !!summary.get(asciiLower(target))?.some(r => r.emoji === emoji && r.mine);
}

// ── delete notices ──────────────────────────────────────────────────────
export const DELETE_HASHES_MAX = 100;
export function buildDelete(hashes) {
  if (!Array.isArray(hashes) || hashes.length === 0 || hashes.length > DELETE_HASHES_MAX || !hashes.every(h => HEX64.test(h))) throw new Error('Invalid delete notice.');
  return JSON.stringify({ type: 'delete', action: 0, hashes });
}
export function parseDelete(text) {
  let j;
  try { j = JSON.parse(cString(text)); } catch { return null; }
  if (!j || typeof j !== 'object' || j.type !== 'delete') return null;
  const action = Number.isInteger(j.action) ? j.action : 0;
  const hashes = Array.isArray(j.hashes) ? j.hashes.filter(h => typeof h === 'string' && HEX64.test(h)).slice(0, DELETE_HASHES_MAX).map(h => h.toLowerCase()) : [];
  return { action, hashes };
}

// Hashes whose message was deleted BY ITS OWN SENDER: a delete notice
// (action 0) applies only to messages its author sent — a contact cannot
// delete, on this device, a message this account wrote. (The app marks by
// hash alone, messenger_transport.c:875-889; this page is stricter.)
// `hashOf(m)` -> the message's hash. Also the hashes hidden on this device
// only (`kind: 'hide'` records, never sent).
export function deletions(records, ownFp, hashOf) {
  const bySender = new Map();                      // hash -> sender fp
  for (const m of records) {
    if (m.kind && m.kind !== 'chat') continue;
    if (m.dir !== 'in' && m.dir !== 'out') continue;
    const h = hashOf(m);
    if (h) bySender.set(h, m.dir === 'out' ? ownFp : m.fp);
  }
  const deleted = new Set(), hidden = new Set();
  for (const m of records) {
    if (m.kind === 'hide' && typeof m.target === 'string' && HEX64.test(m.target)) { hidden.add(m.target.toLowerCase()); continue; }
    if (m.kind !== 'delete') continue;
    const notice = parseDelete(m.text);
    if (!notice || notice.action !== 0) continue;
    const deleter = m.dir === 'out' ? ownFp : m.fp;
    for (const h of notice.hashes) if (bySender.get(h) === deleter) deleted.add(h);
  }
  return { deleted, hidden };
}

// ── payment cards (web 0.1.90; design docs/plans/2026-10-09-connect-nodus-in-chat-design.md) ──
// The app's card (chat_screen.dart :2623-2631). A card is a CLAIM: what it
// says is never shown as fact — transferVerdict decides from this device's
// own address history.
const NATIVE_TOKEN = '0'.repeat(128);
const NODUS_DECIMALS = 8;
const AMOUNT = /^(0|[1-9]\d{0,11})(\.\d{1,8})?$/;
// A NODUS amount as the wallet formats it ("1.5") -> raw units, or null.
export function nodusUnits(amount) {
  if (typeof amount !== 'string' || !AMOUNT.test(amount)) return null;
  const [whole, frac = ''] = amount.split('.');
  return BigInt(whole) * 10n ** BigInt(NODUS_DECIMALS) + BigInt(frac.padEnd(NODUS_DECIMALS, '0'));
}
export function buildTransfer({ amount, wire, to, name = '' }) {
  if (nodusUnits(amount) === null || nodusUnits(amount) === 0n || !HEX128.test(wire) || !HEX128.test(to)) throw new Error('Invalid payment card.');
  return JSON.stringify({ type: 'token_transfer', amount, token: 'NODUS', network: 'Nodus', chain: 'nodus', txHash: wire, recipientAddress: to, recipientName: cardName(name) });
}
// The recipient name is cut at 64 UTF-16 units, never inside a character:
// a cut that would leave the first half of a pair (an emoji) drops it
// (0.1.101, operator 2026-10-12; before, the half went out as a lone
// "\udXXX"). The app does not cut at all (chat_screen.dart:2622-2631).
function cardName(name) {
  const cut = String(name).slice(0, 64);
  return /[\ud800-\udbff]$/.test(cut) ? cut.slice(0, -1) : cut;
}
// Lower case for A-Z only (0.1.102, operator 2026-10-12): the shared C core
// does the same (connect/nc_jsjson.c), and the result no longer depends on
// the browser's Unicode tables. Only the shown chain name of a card of
// another network can differ from a full-Unicode lower case.
export const asciiLower = s => String(s).replace(/[A-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + 32));
// -> { chain, amount, token, wire, to, name } | null (not a card). A card of
// another chain keeps its chain and amount for "cannot be checked here".
export function parseTransfer(text) {
  let j;
  try { j = JSON.parse(cString(text)); } catch { return null; }
  if (!j || typeof j !== 'object' || Array.isArray(j) || j.type !== 'token_transfer') return null;
  const str = v => (typeof v === 'string' ? v : '');
  return { chain: asciiLower(str(j.chain)), amount: str(j.amount), token: str(j.token), wire: asciiLower(str(j.txHash)), to: asciiLower(str(j.recipientAddress)), name: str(j.recipientName) };
}
// A NODUS card this page can check: the token, a 128-hex wire and recipient,
// a well-formed amount. A "nodus" card that is not one is not shown at all.
export function validNodusCard(card) {
  return !!card && card.chain === 'nodus' && card.token === 'NODUS' && HEX128.test(card.wire) && HEX128.test(card.to) && nodusUnits(card.amount) !== null;
}
// The verdict on a card from THIS device's own address history entries
// (src/nodus/history.js parseAddrHistory rows: { h, kind, amount, token,
// peer, wire }). `incoming`: the card arrived from `counterparty` (who must
// have paid this device); else this device sent it to `counterparty`.
//   { state: 'confirmed', height }  the entry matches wire, kind, peer, token, amount
//   { state: 'mismatch' }           an entry with that wire says something else
//   { state: 'pending' }            no entry with that wire (yet)
//   { state: 'unverifiable', chain } not a NODUS card / malformed
export function transferVerdict(card, entries, { incoming, counterparty, ownFp }) {
  if (!card || card.chain !== 'nodus' || card.token !== 'NODUS' || !HEX128.test(card.wire) || nodusUnits(card.amount) === null) return { state: 'unverifiable', chain: card?.chain || '' };
  // The card must name the right recipient: this device when it came in,
  // the contact when this device sent it.
  if (card.to !== (incoming ? ownFp : counterparty)) return { state: 'mismatch' };
  const want = nodusUnits(card.amount);
  const rows = (entries || []).filter(e => e && e.wire === card.wire);
  if (!rows.length) return { state: 'pending' };
  // One row per created coin (change excluded; nodus_witness_addr_index.h
  // ROW DERIVATION): the coins of this item between the two must add up to
  // the card's amount, all in the native token (rows of the same item to
  // someone else are not this card's business).
  const kind = incoming ? 'spend_in' : 'spend_out';
  const own = rows.filter(e => e.kind === kind && e.peer === counterparty);
  if (!own.length || own.some(e => e.token !== NATIVE_TOKEN)) return { state: 'mismatch' };
  const total = own.reduce((s, e) => s + BigInt(e.amount), 0n);
  return total === want ? { state: 'confirmed', height: String(own[0].h) } : { state: 'mismatch' };
}

// One payment, one card (web 0.1.96, BUGS W-06): among the CONFIRMED cards
// of one direction naming one wire, the earliest (local order) is the payment
// and every other is a copy — whatever order they were confirmed in.
// `cards`: [{ key, dir, wire, order (comparable, e.g. BigInt seq), state }]
// -> the keys to mark "duplicate".
export function copyCards(cards) {
  const first = new Map(), copies = [];
  const confirmed = (cards || []).filter(c => c && c.state === 'confirmed').sort((a, b) => (a.order < b.order ? -1 : a.order > b.order ? 1 : 0));
  for (const c of confirmed) {
    const k = `${c.dir}|${c.wire}`;
    if (!first.has(k)) first.set(k, c.key); else copies.push(c.key);
  }
  return copies;
}

// ── replies ─────────────────────────────────────────────────────────────
export const QUOTE_MAX = 100;
// The quote is one line (the app's reader stops it at the first newline):
// newlines become spaces, then at most 100 characters and "...".
export function buildReply(senderLabel, quoted, text) {
  const who = String(senderLabel).replace(/[\r\n]+/g, ' ').trim() || 'them';
  const q = [...String(quoted).replace(/[\r\n]+/g, ' ')];
  const quote = q.length > QUOTE_MAX ? `${q.slice(0, QUOTE_MAX).join('')}...` : q.join('');
  return `↩ Re: ${who}\n> ${quote}\n${text}`;
}
export function parseReply(text) {
  const s = String(text);
  if (!s.startsWith('↩ Re: ')) return null;
  const first = s.indexOf('\n');
  if (first < 0) return null;
  const sender = s.slice(6, first), after = s.slice(first + 1);
  if (!after.startsWith('> ')) return null;
  const second = after.indexOf('\n');
  if (second < 0) return null;
  return { sender, quoted: after.slice(2, second), text: after.slice(second + 1) };
}
