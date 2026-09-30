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
const DIRECTION_CONTROLS = /[؜‎‏‪-‮⁦-⁩]/gu;
const INVISIBLE = /[­ᅟᅠ᠎​-‍⁠-⁤ㅤ﻿ﾠ]/gu;
export function inspectUntrusted(value) {
  const input = typeof value === 'string' ? value : '';
  let unusual = false;
  const text = input.replace(DIRECTION_CONTROLS, () => { unusual = true; return ''; })
    .replace(INVISIBLE, () => { unusual = true; return ''; });
  const scripts = ['Latin', 'Cyrillic', 'Greek'].filter(name => new RegExp(`\\p{Script=${name}}`, 'u').test(text));
  if (scripts.length > 1) unusual = true;
  return { text, unusual };
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
  if (!Number.isSafeInteger(ms)) return "sender's clock: unknown";
  return `sender's clock: ${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

// The three day buckets a routine fetch reads (design §1.4 R5,
// DNA_DM_OUTBOX_RECENT_DAYS = 3): yesterday, today, tomorrow.
export function recentDays(today) {
  if (typeof today !== 'string' || !U64.test(today)) throw new Error('Invalid day.');
  const d = BigInt(today);
  return [d > 0n ? d - 1n : null, d, d + 1n].filter(x => x !== null).map(String);
}

// Whether an own message counts as delivered: the contact's ACK time covers
// its send time (both unix seconds, decimal strings).
export function isDelivered(message, ackTs) {
  if (typeof ackTs !== 'string' || !U64.test(ackTs) || ackTs === '0') return false;
  return BigInt(message.ts) <= BigInt(ackTs);
}

// The WHOLE pending set of own messages to one contact (the blob replaces
// today's previous one, core.outboxPublish): outgoing, not yet covered by the
// contact's ACK, sent within the 7-day life of an outbox value (the outbox
// PUT is EPHEMERAL, 7 days: design §1.4 R5), in local order; at most the
// core's 1000. Like the app's writer (design §1.4 R5: messages.c:624-636
// rebuilds the blob from the pending rows, not only today's), a message whose
// earlier publish failed is carried in today's blob; a message already
// published keeps travelling until it is ACKed (design §1.4 R5, the
// messenger/BUGS.md:27 variant the web may fix). The receiver drops the
// repeats (receivedKey below; the app by content + original timestamp).
export const OUTBOX_MAX = 1000;
export const OUTBOX_LIFETIME_SECONDS = 7n * 86400n;
export function pendingOutbox(messages, fp, nowSeconds, ackTs) {
  if (typeof nowSeconds !== 'string' || !U64.test(nowSeconds)) throw new Error('Invalid time.');
  const oldest = BigInt(nowSeconds) - OUTBOX_LIFETIME_SECONDS;
  const list = messages
    .filter(m => m.dir === 'out' && m.fp === fp && BigInt(m.ts) > oldest && !isDelivered(m, ackTs))
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
