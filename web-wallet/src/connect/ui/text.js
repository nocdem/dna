// Nodus Connect Messages UI — pure helpers (package NC-4c; design rev 5 §1.9).
// No DOM, no network, no storage: everything here is a function of its
// arguments, so test/connect-ui.test.js pins it under node --test.

const HEX128 = /^[0-9a-f]{128}$/;
const U64 = /^(0|[1-9]\d{0,19})$/;

// An ID the user typed or pasted: whitespace removed, lowercased; returns
// the 128-hex ID or throws a plain-words error.
export function parseContactId(value) {
  const id = typeof value === 'string' ? value.replace(/\s+/g, '').toLowerCase() : '';
  if (!HEX128.test(id)) throw new Error('That is not a valid ID. An ID is 128 characters, letters a–f and digits.');
  return id;
}

// "ID 1a2b3c4d…9f0e" — the only name-like label an unverified identity gets.
export function shortId(fp) {
  if (typeof fp !== 'string' || !HEX128.test(fp)) return 'ID ?';
  return `ID ${fp.slice(0, 8)}…${fp.slice(-4)}`;
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
//   2. its timestamp is <= the ACK value read.
// A message that was never published stays pending whatever the ACK says.
// The flag is stored in the message record, so the decision is made once
// and kept (isDelivered).
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

// After an ACK read of `ackTs`: copies of the own messages to `fp` that
// become delivered — published before the read (`publishedBefore`, from
// publishedSeqs) and not later than the ACK value.
export function markDelivered(messages, fp, ackTs, publishedBefore) {
  if (typeof ackTs !== 'string' || !U64.test(ackTs) || ackTs === '0' || !(publishedBefore instanceof Set)) return [];
  const ack = BigInt(ackTs);
  return messages.filter(m => m.dir === 'out' && m.fp === fp && !isDelivered(m) && publishedBefore.has(String(m.seq)) &&
      U64.test(String(m.ts)) && BigInt(m.ts) <= ack)
    .map(m => ({ ...m, delivered: true }));
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
// (isDelivered above), sent within the 7-day life of an outbox value (the outbox
// PUT is EPHEMERAL, 7 days: design §1.4 R5), in local order; at most the
// core's 1000. Like the app's writer (design §1.4 R5: messages.c:624-636
// rebuilds the blob from the pending rows, not only today's), a message whose
// earlier publish failed is carried in today's blob; a message already
// published keeps travelling until it is ACKed (design §1.4 R5, the
// messenger/BUGS.md:27 variant the web may fix). The receiver drops the
// repeats (receivedKey below; the app by content + original timestamp).
export const OUTBOX_MAX = 1000;
export const OUTBOX_LIFETIME_SECONDS = 7n * 86400n;
export function pendingOutbox(messages, fp, nowSeconds) {
  if (typeof nowSeconds !== 'string' || !U64.test(nowSeconds)) throw new Error('Invalid time.');
  const oldest = BigInt(nowSeconds) - OUTBOX_LIFETIME_SECONDS;
  const list = messages
    .filter(m => m.dir === 'out' && m.fp === fp && BigInt(m.ts) > oldest && !isDelivered(m))
    .sort(compareLocal)
    .map(m => ({ seq: m.seq, ts: m.ts, text: m.text }));
  // Beyond the limit only the newest are kept.
  return list.length > OUTBOX_MAX ? list.slice(list.length - OUTBOX_MAX) : list;
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
