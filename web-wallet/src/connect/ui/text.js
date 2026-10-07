// Nodus Connect Messages UI — pure helpers (package NC-4c; design rev 5 §1.9).
// No DOM, no network, no storage: everything here is a function of its
// arguments, so test/connect-ui.test.js pins it under node --test.

import { chainName } from '../../nodus/names.js';

const HEX128 = /^[0-9a-f]{128}$/;
const U64 = /^(0|[1-9]\d{0,19})$/;

// An ID the user typed or pasted: whitespace removed, lowercased; returns
// the 128-hex ID or throws a plain-words error.
export function parseContactId(value) {
  const id = typeof value === 'string' ? value.replace(/\s+/g, '').toLowerCase() : '';
  if (!HEX128.test(id)) throw new Error('That is not a valid ID. An ID is 128 characters, letters a–f and digits.');
  return id;
}

// What the add-contact box accepts: an ID (parseContactId — tried first, so
// a pasted ID never becomes a name) or an HF-4 chain name, read with the
// wallet's own name rule (src/nodus/names.js chainName: trimmed, A-Z
// lowered, 3..36 of a-z0-9, no ID-like all-hex name of 8+). -> { fp } or
// { name }; anything else throws one plain-words error.
export function parseContactInput(value) {
  try { return { fp: parseContactId(value) }; } catch { /* not an ID: try a name */ }
  const name = chainName(value);
  if (name) return { name };
  throw new Error('That is not a valid ID or chain name. An ID is 128 characters, letters a–f and digits; a chain name is 3 to 36 letters a–z and digits.');
}

// Why a request cannot go to `fp` (the typed ID or a name's owner), or ''
// when it can — the same three answers for both.
export function requestRefusal(fp, { ownFp, isContact = false, isRequested = false } = {}) {
  if (fp === ownFp) return 'That is your own ID.';
  if (isContact) return 'This person is already a contact.';
  if (isRequested) return 'You already sent this person a request.';
  return '';
}

// "ID 1a2b3c4d…9f0e" — the only name-like label an unverified identity gets.
export function shortId(fp) {
  if (typeof fp !== 'string' || !HEX128.test(fp)) return 'ID ?';
  return `ID ${fp.slice(0, 8)}…${fp.slice(-4)}`;
}

// What a contact is called — ONE name, the short ID under it (decision
// docs/plans/decisions/2026-10-03-connect-name-display.md; chain names:
// 2026-10-02-onchain-names.md, design 2026-10-02-onchain-names-design.md
// rev 4 R3).
//   chain    the chain name the node reported (dnac_name_of), '' if none
//   profile  the profile name nc_name_verify proved, '' if none
//   claimed  an unverified name claim, '' if none
// The title is the chain name (verified: true, the verified look), else the
// verified profile name (fromProfile: true — someone else's text, shown
// plain with the unusual-characters marking, never the verified look), else
// the short ID. No second name is shown beside it. `id` is the short ID
// shown under the title ('' when the title already is the short ID), so the
// ID stays visible under every name (ASCII look-alikes, R3). A claim is
// shown only when there is neither a chain nor a profile name.
export function contactNames(fp, { chain = '', profile = '', claimed = '' } = {}) {
  const title = chain || profile || shortId(fp);
  return {
    title,
    verified: !!chain,
    fromProfile: !chain && !!profile,
    id: chain || profile ? shortId(fp) : '',
    claimed: !chain && !profile ? claimed : ''
  };
}

// Text written by someone else (a request note, a claimed name, a message,
// a profile field). Direction controls are removed from what is shown
// (the element is also a <bdi>, see dom.js) and reported; so are invisible
// characters and a mix of look-alike scripts (Latin with Cyrillic or Greek),
// which the UI marks as "unusual characters".
// Direction controls: U+061C, U+200E-200F, U+202A-202E, U+2066-2069.
// Invisible: Unicode's own Default_Ignorable_Code_Point set — every
// character a renderer may draw as nothing (soft hyphen, U+034F, the Hangul
// / Mongolian fillers and selectors, zero-width space/joiners, word joiner
// and invisible operators, deprecated format controls, variation selectors
// U+FE00-FE0F and the supplement U+E0100-E01EF, BOM, U+FFF0-FFF8,
// U+1D173-1D17A, the whole U+E0000-E0FFF tag block, … — Connect RT2 L2 F4)
// — plus the line/paragraph separators U+2028-2029, which are not in it.
// (Removing U+FE0F also drops the emoji-presentation selector of e.g. a red
// heart: such a message is shown with the marker — confusable marking only.)
// Both are written with escapes: a literal U+2028/2029 inside a regex
// literal is turned into a raw line terminator by the bundler, and literal
// invisible characters cannot be reviewed.
const DIRECTION_CONTROLS = /[؜‎‏‪-‮⁦-⁩]/gu;
const INVISIBLE = new RegExp(String.raw`[\p{Default_Ignorable_Code_Point}  ]`, 'gu');
// A letter of a script other than Latin (Common / Inherited letters belong
// to no other script). Used for NAMES only: a Latin name holding one Armenian
// "օ" or a Cherokee / Lisu look-alike is marked (RT2 L2 F4); message text
// keeps the Latin / Cyrillic / Greek rule so mixed-language chat is not
// marked.
const NON_LATIN_LETTER = /(?![\p{Script=Latin}\p{Script=Common}\p{Script=Inherited}])\p{L}/u;
// A name to check carefully (confusable marking only, nothing is refused):
// letters but none of them Latin (a whole-script Cyrillic / Greek / other
// name can copy the look of a Latin one), or any fullwidth Latin letter
// (U+FF21-FF3A, U+FF41-FF5A: Script=Latin, so the mixed-script test above
// does not see it).
const FULLWIDTH_LATIN = /[Ａ-Ｚａ-ｚ]/u;
export function inspectUntrusted(value, { name = false } = {}) {
  const input = typeof value === 'string' ? value : '';
  let unusual = false;
  const text = input.replace(DIRECTION_CONTROLS, () => { unusual = true; return ''; })
    .replace(INVISIBLE, () => { unusual = true; return ''; });
  const scripts = ['Latin', 'Cyrillic', 'Greek'].filter(script => new RegExp(`\\p{Script=${script}}`, 'u').test(text));
  if (scripts.length > 1) unusual = true;
  if (name && /\p{Script=Latin}/u.test(text) && NON_LATIN_LETTER.test(text)) unusual = true;
  const check = name && (FULLWIDTH_LATIN.test(text) || (/\p{L}/u.test(text) && !/\p{Script=Latin}/u.test(text)));
  return { text, unusual, check };
}

// A profile website is shown only as link text of a checked https: URL;
// anything else is shown as plain text (or not at all when empty).
export function httpsLink(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return null;
  return url.href;
}

// A profile picture as an <img> source, or null. The app stores a 128x128
// JPEG (quality 80) as plain base64 (profile_editor_screen.dart:507-513) in
// avatar_base64 (dna_engine.h:377: 20484 bytes with the NUL). Shown only
// when it is canonical-looking base64 within that size whose bytes start
// like a JPEG or a PNG; the type comes from those bytes, never the sender.
export const AVATAR_MAX_B64 = 20480;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
export function avatarSource(b64) {
  if (typeof b64 !== 'string' || b64.length === 0 || b64.length > AVATAR_MAX_B64 || b64.length % 4 !== 0 || !B64.test(b64)) return null;
  if (b64.startsWith('/9j/')) return `data:image/jpeg;base64,${b64}`;         // FF D8 FF
  if (b64.startsWith('iVBORw0KGgo')) return `data:image/png;base64,${b64}`;   // 89 50 4E 47 0D 0A 1A 0A
  return null;
}

// A picture this site uploads stays under the app's own limit (18000
// characters of base64, profile_editor_screen.dart:516); '' removes it.
export const AVATAR_UPLOAD_MAX_B64 = 18000;
export function avatarPatch(b64) {
  if (b64 === '') return { avatar_base64: '' };
  if (typeof b64 !== 'string' || b64.length > AVATAR_UPLOAD_MAX_B64 || !avatarSource(b64)) throw new Error('Invalid profile picture.');
  return { avatar_base64: b64 };
}

// Profile edit (fields the core accepts: nc_profile.c TOP_FIELDS bio,
// location, website — the name is not editable: no name registration in
// the first release). An empty website is allowed; a non-empty one must be
// https:.
export function profilePatch({ bio = '', location = '', website = '' } = {}) {
  for (const value of [bio, location, website]) if (typeof value !== 'string') throw new Error('Invalid profile edit.');
  if (website.trim() !== '' && !httpsLink(website.trim())) throw new Error('A website must start with https://');
  return { bio, location, website: website.trim() };
}

// Plain words for core.profileUpdate statuses (thin-core decision, "Profil
// yazımı": 'taken' is terminal and never retried).
export function profileStatusText(status) {
  switch (status) {
    case 'published': return 'Your profile was saved.';
    case 'wait': return 'Your profile could not be read from the network right now, so nothing was changed. Try again in a minute.';
    case 'taken': return 'Your profile address is already held by someone else. It cannot be changed from here.';
    case 'bad_patch': return 'One of the fields is too long or not allowed.';
    default: return 'Saving failed. Try again later.';
  }
}

// Plain words for core.contactsAdd statuses.
export function contactListStatusText(status) {
  switch (status) {
    case 'published': case 'unchanged': return '';
    case 'wait': return 'Your contact list on the network could not be read right now; this contact is kept on this device and will be added there later.';
    case 'taken': return 'Your contact list address on the network is held by someone else. Contacts are kept on this device only.';
    default: return 'Your contact list could not be updated on the network. It will be tried again.';
  }
}

// Sender's clock label: senderTs is unix seconds as a decimal string, set by
// the sender's device and not checked by anyone (design §1.9).
export function senderClockLabel(senderTs) {
  if (typeof senderTs !== 'string' || !U64.test(senderTs)) return "sender's clock: unknown";
  const ms = Number(senderTs) * 1000;
  // A Date holds at most 8.64e15 ms (ECMAScript time value range); a larger
  // safe integer would make toISOString throw and break the conversation's
  // render (Connect RT2 L2 F5) — any peer can sign such a value.
  if (!Number.isSafeInteger(ms) || ms > 8.64e15) return "sender's clock: unknown";
  return `sender's clock: ${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

// The app's smart sync (transport_offline.c:37, :228-260): when any
// contact's messages were never checked, or the oldest check is more than
// 3 days old, the next check reads the 8 buckets the messages can still be
// in (dht_dm_outbox_sync_full, today-6 .. today+1: the buckets live 7 days,
// DNA_DM_OUTBOX_TTL); otherwise the 3 recent ones.
export const SMART_SYNC_FULL_SECONDS = 3 * 86400;
export function needFullSync(contactFps, dmSync, now) {
  const t = u64OrNull(now);
  if (t === null) throw new Error('Invalid time.');
  return contactFps.some(fp => {
    const last = u64OrNull(dmSync?.[fp]);
    return last === null || last === 0n || t - last > BigInt(SMART_SYNC_FULL_SECONDS);
  });
}
export function fullDays(today) {
  if (typeof today !== 'string' || !U64.test(today)) throw new Error('Invalid day.');
  const d = BigInt(today), out = [];
  for (let k = -6n; k <= 1n; k++) if (d + k >= 0n) out.push(String(d + k));
  return out;
}
const u64OrNull = value => value !== undefined && value !== null && U64.test(String(value)) ? BigInt(String(value)) : null;

// The app keeps a profile 7 days (profile_cache.h:40 PROFILE_CACHE_TTL_SECONDS).
export const PROFILE_CACHE_SECONDS = 7 * 24 * 3600;
export function profileFresh(entry, now) {
  const at = u64OrNull(entry?.at), t = u64OrNull(now);
  return at !== null && t !== null && t >= at && t - at < BigInt(PROFILE_CACHE_SECONDS);
}

// The three day buckets a routine fetch reads (design §1.4 R5,
// DNA_DM_OUTBOX_RECENT_DAYS = 3): yesterday, today, tomorrow.
export function recentDays(today) {
  if (typeof today !== 'string' || !U64.test(today)) throw new Error('Invalid day.');
  const d = BigInt(today);
  return [d > 0n ? d - 1n : null, d, d + 1n].filter(x => x !== null).map(String);
}

// Delivery of own messages (NC-RT2 A). The ACK is one 8-byte watermark per
// contact (dht_ack_value_encode, unix seconds), not a list: it cannot say
// WHICH messages arrived. So an own message is marked delivered only when
//   1. it was in a blob that was successfully published (its `published`
//      flag, set after core.outboxPublish resolved), and that flag was set
//      BEFORE the ACK read was issued (publishedSeqs is the snapshot taken
//      just before core.ackGet), and
//   2. its timestamp is STRICTLY below the ACK value read (RT2 L2 F1: the
//      ACK is in seconds, so a message sent in the ACK's own second may not
//      have been fetched yet).
// A message that was never published stays pending whatever the ACK says.
// The flag is stored in the message record, so the decision is made once
// and kept (isDelivered). Even so the watermark cannot prove receipt (a
// clock step back, an app receiver whose ACK is its own clock), so a
// delivered message stays in the published blob for DELIVERED_GRACE_SECONDS
// more (pendingOutbox): a receiver online at that time fetches every 30 s
// and still gets it. Operator 2026-10-01: one hour.
export function isDelivered(message) { return message?.delivered === true; }

// What the conversation shows next to an own message.
export function messageStatus(message) {
  return isDelivered(message) ? 'delivered' : message?.published === true ? 'sent' : 'waiting to send';
}

// The local seqs of own messages to `fp` already published — taken BEFORE
// the ACK read is issued.
export function publishedSeqs(messages, fp) {
  return new Set(messages.filter(m => m.dir === 'out' && m.fp === fp && m.published === true).map(m => String(m.seq)));
}

// After a successful publish of `set` (the pendingOutbox entries sent):
// copies of the own messages to `fp` in it that were not flagged yet.
export function markPublished(messages, fp, set) {
  const sent = new Set(set.map(m => String(m.seq)));
  return messages.filter(m => m.dir === 'out' && m.fp === fp && m.published !== true && sent.has(String(m.seq)))
    .map(m => ({ ...m, published: true }));
}

// After an ACK read of `ackTs` at `nowSeconds`: copies of the own messages
// to `fp` that become delivered — published before the read
// (`publishedBefore`, from publishedSeqs) and strictly older than the ACK
// value. `deliveredAt` (unix seconds) starts the blob grace (pendingOutbox).
export const DELIVERED_GRACE_SECONDS = 3600n;
export function markDelivered(messages, fp, ackTs, publishedBefore, nowSeconds) {
  if (typeof ackTs !== 'string' || !U64.test(ackTs) || ackTs === '0' || !(publishedBefore instanceof Set)) return [];
  if (typeof nowSeconds !== 'string' || !U64.test(nowSeconds)) throw new Error('Invalid time.');
  const ack = BigInt(ackTs);
  return messages.filter(m => m.dir === 'out' && m.fp === fp && !isDelivered(m) && publishedBefore.has(String(m.seq)) &&
      U64.test(String(m.ts)) && BigInt(m.ts) < ack)
    .map(m => ({ ...m, delivered: true, deliveredAt: nowSeconds }));
}

// Still inside the blob grace after delivery (see the block comment above).
function inGrace(message, now) {
  return isDelivered(message) && U64.test(String(message.deliveredAt)) &&
    BigInt(message.deliveredAt) + DELIVERED_GRACE_SECONDS > now;
}

// The receiver's ACK value for `fp` (G11, NC-RT2 A): the NEWEST sender
// timestamp among the messages from `fp` stored on this device — never this
// device's clock, so the ACK covers nothing that was not received. Returns
// the decimal string to publish, or null when nothing is stored or nothing
// newer than `lastSent` (the value last published) was stored.
export function ackToSend(messages, fp, lastSent) {
  let newest = 0n;
  for (const m of messages) {
    if (m.dir !== 'in' || m.fp !== fp || !U64.test(String(m.senderTs))) continue;
    const ts = BigInt(m.senderTs);
    if (ts > newest) newest = ts;
  }
  if (newest === 0n) return null;
  if (typeof lastSent === 'string' && U64.test(lastSent) && newest <= BigInt(lastSent)) return null;
  return newest.toString();
}

// The WHOLE pending set of own messages to one contact (the blob replaces
// today's previous one, core.outboxPublish): outgoing, not yet delivered
// (isDelivered above) or delivered less than DELIVERED_GRACE_SECONDS ago,
// sent within the 7-day life of an outbox value (the outbox PUT is
// EPHEMERAL, 7 days: design §1.4 R5), in local order; at most OUTBOX_MAX
// = 50, the app's own per-bucket cap (dht_dm_outbox.h
// DNA_DM_OUTBOX_MAX_MESSAGES_PER_BUCKET): one short message is ~6.8 KB in
// the blob and a 4000-character one ~23 KB worst case, so 50 stay far under
// the node's 4 MB value limit, where the old 1000 did not (RT2 follow-up,
// operator 2026-10-01). Like the app's writer (design §1.4 R5: messages.c:624-636
// rebuilds the blob from the pending rows, not only today's), a message whose
// earlier publish failed is carried in today's blob; a message already
// published keeps travelling until it is ACKed (design §1.4 R5, the
// messenger/BUGS.md:27 variant the web may fix). The receiver drops the
// repeats (receivedKey below; the app by content + original timestamp).
export const OUTBOX_MAX = 50;
export const OUTBOX_LIFETIME_SECONDS = 7n * 86400n;
export function pendingOutbox(messages, fp, nowSeconds) {
  if (typeof nowSeconds !== 'string' || !U64.test(nowSeconds)) throw new Error('Invalid time.');
  const now = BigInt(nowSeconds);
  const oldest = now - OUTBOX_LIFETIME_SECONDS;
  const list = messages
    .filter(m => m.dir === 'out' && m.fp === fp && BigInt(m.ts) > oldest && (!isDelivered(m) || inGrace(m, now)))
    .sort(compareLocal)
    .map(m => ({ seq: m.seq, ts: m.ts, text: m.text }));
  // Beyond the limit only the newest are kept.
  return list.length > OUTBOX_MAX ? list.slice(list.length - OUTBOX_MAX) : list;
}

// Own messages to `fp` still waiting for delivery (what makes a contact's
// blob worth publishing on open; grace-period copies alone do not).
export function hasUndelivered(messages, fp, nowSeconds) {
  if (typeof nowSeconds !== 'string' || !U64.test(nowSeconds)) throw new Error('Invalid time.');
  const oldest = BigInt(nowSeconds) - OUTBOX_LIFETIME_SECONDS;
  return messages.some(m => m.dir === 'out' && m.fp === fp && BigInt(m.ts) > oldest && !isDelivered(m));
}

// Local order = local sequence (receive/send order on this device), never the
// sender's clock (§1.9).
export function compareLocal(a, b) {
  const x = BigInt(a.seq), y = BigInt(b.seq);
  return x < y ? -1 : x > y ? 1 : 0;
}

// Identity of a received message for de-duplication: the sender republishes
// its whole pending set until ACKed, so the same message arrives repeatedly.
export function receivedKey(fp, message) {
  return JSON.stringify([fp, String(message.seq), String(message.senderTs), message.text]);
}

// The own contact list read from the network (core.contactsGet 'found')
// merged into the local state: what it has and this device lacks is added;
// a salt this device already holds is kept (design §1.4 R3). An ID the user
// removed on this device (state.removed) is NOT added back: the list on the
// network is merge-only (nc_core.h nc_contactlist_add) and still holds it.
// @return true when the state changed (the caller saves).
export function mergeListedContacts(state, entries, ownFp) {
  const removed = new Set(state.removed);
  let changed = false;
  for (const entry of entries || []) {
    if (!entry || !HEX128.test(entry.fp) || entry.fp === ownFp || removed.has(entry.fp)) continue;
    const local = state.contacts.find(c => c.fp === entry.fp);
    if (!local) { state.contacts.push({ fp: entry.fp, salt: entry.salt || null, listed: true }); changed = true; }
    else {
      if (!local.salt && entry.salt) { local.salt = entry.salt; changed = true; }
      if (!local.listed) { local.listed = true; changed = true; }
    }
  }
  return changed;
}

// Removes a contact on THIS device (the user's "Remove contact"): it leaves
// the contact list, its ID goes on state.removed (so the network list does
// not bring it back), and what was kept to check its messages goes too —
// the check time, the kept profile row index and chain name (the app drops
// its key cache on removal too, dna_engine_contacts.c:253). The messages
// themselves stay on this device (shown again if the person is added again),
// and so do the ACK values (no second ACK of messages already ACKed).
// @return true when the contact was removed.
export function removeContact(state, fp) {
  const index = state.contacts.findIndex(c => c.fp === fp);
  if (index < 0) return false;
  state.contacts.splice(index, 1);
  if (!state.removed.includes(fp)) state.removed.push(fp);
  delete state.dmSync[fp];
  delete state.profileCache[fp];
  delete state.chainNames[fp];
  return true;
}

// The person is a contact again (a request accepted either way): their ID
// leaves state.removed.
export function unremoveContact(state, fp) {
  state.removed = state.removed.filter(r => r !== fp);
}
