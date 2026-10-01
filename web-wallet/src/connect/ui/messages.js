// Nodus Connect — Messages (contacts, requests, 1:1 text, own profile).
//
// Governing records: docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md
// (first stage, Ek 2: contact list, send/accept contact requests, 1:1 text
// messages, own profile edit — no groups, media or calls; Q1: only words
// generated in this session are "fresh"; S8: history store = vault id),
// 2026-09-30-connect-history-at-rest.md rev 2 (src/connect/store.js) and
// 2026-10-01-connect-own-origin.md (Messages lives in the Nodus Connect site,
// together with the wallet, on ONE unlock).
//
// HOST-DRIVEN. This module never asks for words, never creates or unlocks a
// NODUS client, never takes the single-tab Web Lock and has no idle timer:
// its host does all of that and hands over an unlocked client.
//   - Nodus Connect page (src/connect-main.js): the wallet itself is the host
//     (src/app.js raises the events of src/wallet-extensions.js; this file's
//     `walletExtension` answers them). Messages opens on the wallet's one
//     client (one send.wasm module, one tier-2 session — NC-4b) as soon as
//     the wallet's NODUS client is ready; the wallet's Lock, idle lock,
//     pagehide, single-tab and cross-site rules close it.
//   - Messages preview page (/preview/, src/connect/ui/standalone.js): its
//     own unlock screens are the host.
//
// Lock order (design rev 5 §1.8): the host calls closeMessages /
// resetMessages BEFORE it locks the client: sync stops -> core.lock()
// (Messages keys wiped, nc_lock) -> history store closed -> in-page data
// dropped. core.lock() is terminal for the module instance: Messages opens
// again only after the wallet is locked and opened again.
//
// Network calls: each is awaited before the next one is queued (design §6.4
// F7), so a wallet operation queued meanwhile waits at most one step.
// An error text coming from the core is never shown: it can carry technical
// terms; the page shows its own plain words.
//
// Rendering (design rev 5 §1.9): every text through textContent (dom.js el);
// text written by someone else (names, notes, messages, profile fields) in a
// <bdi> with the "unusual characters" marker (dom.js untrusted); a website
// only as a checked https: link; no innerHTML, no inline style attribute.
import { createNodusConnectCore, acceptanceMayAutoApprove } from '../core.js';
import { openHistoryStore, memoryHistoryStore, StorageError } from '../store.js';
import {
  parseContactId, shortId, profilePatch, profileStatusText, contactListStatusText, senderClockLabel,
  recentDays, pendingOutbox, hasUndelivered, compareLocal, receivedKey,
  publishedSeqs, markPublished, markDelivered, ackToSend, messageStatus
} from './text.js';
import { el, untrusted, button, website } from './dom.js';

const SYNC_MS = 30000;                   // how often requests and messages are checked
const HEX128 = /^[0-9a-f]{128}$/;
const TEXT_MAX = 4000;                   // one message, characters (the composer's maxlength)
const COMPOSER_ROWS = 5;                 // the composer grows up to this many lines
const STATUS_MARK = { 'waiting to send': '○', sent: '✓', delivered: '✓✓' };
const WAITING_TEXT = 'Messages opens when your wallet is connected to the Nodus network.';
const UNAVAILABLE_TEXT = 'Messages needs the Nodus network connection, which is unavailable right now. Lock and open your wallet again to retry.';

// ── session state (all dropped by close / reset) ───────────────────────
let core, store, state, messages = [], ownFp, ownProfile, fresh = false, vaultId = null;
let generation = 0, syncTimer, syncing = false;
let requests = [], selectedFp, eraseArmed = false, profileTaken = false;
const profiles = new Map();              // fp -> verified profile, this session
const received = new Set();              // receivedKey of every stored incoming message
const unpublished = new Set();           // contacts whose pending set must be (re)published
const saltChecked = new Set();           // contacts whose salt was reconciled this session
const dropped = new Map();               // fp -> messages that did not verify, this session
const others = new Map();                // fp -> authentic items that are not text (reactions, calls, …), last check
const lastRead = new Map();              // fp -> highest local seq shown to the user (this session only)

// ── view state ─────────────────────────────────────────────────────────
let ui, host = {};
let phase = 'waiting';                   // 'waiting' | 'opening' | 'open' | 'closed'
let pane = 'empty';                      // right side: 'empty' | 'conversation' | 'add' | 'requests' | 'profile'
let narrow = 'list';                     // ≤ 700 px: 'list' (contacts) or 'main' (the right side)

function isOpen() { return !!core && !!state && phase === 'open'; }

// ── close / reset ──────────────────────────────────────────────────────
// Stops everything Messages runs and drops every in-page secret. Never
// touches the NODUS client (the host locks it afterwards).
function wipe() {
  generation++;
  clearInterval(syncTimer); syncTimer = undefined; syncing = false;
  const c = core; core = undefined;
  try { c?.lock(); } catch { /* the rest must still run */ }
  try { store?.close(); } catch { /* same */ }
  store = undefined; state = undefined; messages = []; ownFp = undefined; ownProfile = undefined;
  fresh = false; vaultId = null; requests = []; selectedFp = undefined;
  eraseArmed = false; profileTaken = false;
  for (const set of [profiles, received, unpublished, saltChecked, dropped, others, lastRead]) set.clear();
  if (!ui) return;
  for (const control of [ui.addId, ui.addNote, ui.composer, ui.bio, ui.location, ui.website]) control.value = '';
  ui.composer.rows = 1; ui.counter.textContent = '';
  for (const line of [ui.addStatus, ui.sendStatus, ui.profileStatus, ui.copyStatus, ui.emptyCopyStatus, ui.requestsStatus, ui.sync, ui.ownId, ui.profileName]) line.textContent = '';
  ui.messageList.replaceChildren(); ui.requestList.replaceChildren(); ui.outgoingList.replaceChildren();
  ui.contactList.replaceChildren(); ui.convTitle.textContent = ''; ui.convClaim.replaceChildren(); ui.convNote.textContent = '';
  ui.erase.textContent = 'Delete message history on this device';
  pane = 'empty'; narrow = 'list';
}

// Messages is closed with a reason (an error, the connection, a deleted
// history). `retry`: the identity is open and only reading failed.
export function closeMessages(reason, { retry = false } = {}) {
  if (!retry) wipe();
  phase = 'closed';
  showState('Messages is closed', reason, retry);
}

// Back to the start (the wallet was locked, or is reconnecting).
export function resetMessages(text = WAITING_TEXT) {
  wipe();
  phase = 'waiting';
  showState('Messages', text, false);
}

// ── open ───────────────────────────────────────────────────────────────
class Closed extends Error {}

// client: an unlocked NODUS client (state 'ready', module with the Messages
// exports); phrase: the normalised recovery phrase; vaultId: the saved
// wallet's id or null (memory only: nothing is kept after lock and no
// delivery confirmation is sent); fresh: words generated in this tab (Q1).
export async function openMessages({ client, phrase, vaultId: id = null, fresh: isFresh = false }) {
  wipe();
  const gen = generation;
  phase = 'opening';
  showState('Opening Messages', 'Opening Messages…', false);
  let words, created;
  // A close / reset or a newer open ran meanwhile: lock what THIS open built
  // unless it is still the current one (idempotent).
  const superseded = () => {
    if (gen === generation) return false;
    if (created && created !== core) { try { created.lock(); } catch { /* nothing left to do */ } }
    return true;
  };
  try {
    if (typeof phrase !== 'string' || !phrase) throw new Closed(UNAVAILABLE_TEXT);
    created = createNodusConnectCore({ nodus: client });
    core = created;
    words = new TextEncoder().encode(phrase);
    const unlocked = await created.unlock({ words, fresh: isFresh === true });
    if (superseded()) return;
    ownFp = unlocked.fingerprint; fresh = unlocked.fresh === true; vaultId = id || null;
    await finishOpen(gen);
  } catch (error) {
    if (superseded()) return;
    // Before the identity is open: Messages stays closed until the wallet is
    // opened again (core.lock is terminal). After it: retry the reads.
    if (!ownFp) { closeMessages(explain(error, 'Messages could not open right now. Lock and open your wallet again to retry.')); return; }
    closeMessages(explain(error, 'Messages could not connect to the network right now. Try again in a minute.'), { retry: true });
  } finally { words?.fill(0); }
}

// Our own plain-words errors (Closed, a storage failure) are shown as they
// are; anything else gets the caller's plain-words fallback.
function explain(error, fallback) { return error instanceof Closed || error instanceof StorageError ? error.message : fallback; }

// Messages opens only after the own profile was read (or, for a fresh
// account, created) and the history was loaded. Any failure keeps it closed
// and writes nothing (design §1.7, §7 Q1 (iii)).
async function finishOpen(gen) {
  phase = 'opening';
  showState('Opening Messages', 'Reading your account…', false);
  const own = await core.profileGet(ownFp);
  if (gen !== generation) return;
  if (own.outcome === 'found') ownProfile = own.profile;
  else if (own.outcome === 'empty' && fresh) {
    const made = await core.profileUpdate({});
    if (gen !== generation) return;
    if (made.status !== 'published') throw new Closed(profileStatusText(made.status));
    ownProfile = null;
  } else throw new Closed('Your account could not be read from the network right now. Nothing was changed. Try again in a minute.');

  if (!store) {
    showState('Opening Messages', 'Loading your messages…', false);
    // A saved wallet keeps its history (S8); typed words and a new account
    // keep nothing.
    const opened = vaultId ? await openHistoryStore({ core, vaultId }) : memoryHistoryStore();
    if (gen !== generation) { opened.close(); return; }
    store = opened;
    state = structuredClone(store.state);
    messages = [...store.messages];
    for (const m of messages) if (m.dir === 'in') received.add(receivedKey(m.fp, { seq: m.remoteSeq, senderTs: m.senderTs, text: m.text }));
    const now = nowSeconds();
    for (const contact of state.contacts) if (hasUndelivered(messages, contact.fp, now)) unpublished.add(contact.fp);
    // History from earlier sessions is not "new".
    for (const contact of state.contacts) markRead(contact.fp);
  }
  await mergeContactList(gen);
  if (gen !== generation) return;

  ui.ownId.textContent = ownFp;
  ui.memoryNote.hidden = store.persistent;
  ui.erase.hidden = !store.persistent;
  fillProfile();
  phase = 'open';
  pane = 'empty';
  render();
  clearInterval(syncTimer);
  syncTimer = setInterval(() => { void sync(); }, SYNC_MS);
  void sync();
}

// ── state helpers ──────────────────────────────────────────────────────
const nowSeconds = () => String(Math.floor(Date.now() / 1000));
// A u64 from a core result (decimal string or small number); anything else is 0.
const u64 = value => /^(0|[1-9]\d{0,19})$/.test(String(value)) ? BigInt(String(value)) : 0n;
const contactOf = fp => state.contacts.find(c => c.fp === fp);
function takeSeq() { const seq = state.nextSeq; state.nextSeq = String(BigInt(seq) + 1n); return seq; }
async function persist(newMessages = []) { await store.save(state, newMessages); }
// Changed copies of stored messages (published / delivered flags): saved
// first, then put in place of the in-page ones (by local seq).
async function saveUpdated(updated) {
  if (!updated.length) return;
  await persist(updated);
  for (const u of updated) { const i = messages.findIndex(m => m.seq === u.seq); if (i >= 0) messages[i] = u; }
}

function addContactLocal(fp, salt) {
  let contact = contactOf(fp);
  if (!contact) { contact = { fp, salt: salt || null, listed: false }; state.contacts.push(contact); }
  else if (!contact.salt && salt) contact.salt = salt;
  state.outgoing = state.outgoing.filter(o => o.fp !== fp);
  state.declined = state.declined.filter(d => d !== fp);
  return contact;
}

// The own list on the network: add what it has and this device lacks. A
// salt this device already holds is kept (the agreement comes first, the
// list second — design §1.4 R3).
async function mergeContactList(gen) {
  const list = await core.contactsGet();
  if (gen !== generation || list.outcome !== 'found') return;
  let changed = false;
  for (const entry of list.contacts || []) {
    if (!entry || !HEX128.test(entry.fp) || entry.fp === ownFp) continue;
    const local = contactOf(entry.fp);
    if (!local) { state.contacts.push({ fp: entry.fp, salt: entry.salt || null, listed: true }); changed = true; }
    else {
      if (!local.salt && entry.salt) { local.salt = entry.salt; changed = true; }
      if (!local.listed) { local.listed = true; changed = true; }
    }
  }
  if (changed) await persist();
}

// Contacts this device has that the network list may lack: merge-only add
// (core.contactsAdd). 'wait' is retried on the next check; 'taken' stops.
async function publishContacts(gen) {
  if (state.listTaken) return;
  const missing = state.contacts.filter(c => !c.listed);
  if (!missing.length) return;
  const result = await core.contactsAdd(missing.map(c => ({ fp: c.fp, salt: c.salt || undefined })));
  if (gen !== generation) return;
  if (result.status === 'published' || result.status === 'unchanged') { for (const c of missing) c.listed = true; await persist(); }
  else if (result.status === 'taken') { state.listTaken = true; await persist(); }
  const note = contactListStatusText(result.status);
  if (note && gen === generation) ui.addStatus.textContent = note;
}

async function ensureProfile(fp) {
  if (profiles.has(fp)) return true;
  const result = await core.profileGet(fp);
  if (result.outcome !== 'found') return false;
  profiles.set(fp, result.profile);
  return true;
}

// ── sync ───────────────────────────────────────────────────────────────
async function sync() {
  if (syncing || !isOpen()) return;
  syncing = true;
  const gen = generation;
  try {
    await syncRequests(gen);
    if (gen !== generation) return;
    await publishContacts(gen);
    for (const contact of [...state.contacts]) {
      if (gen !== generation) return;
      await syncContact(contact, gen);
    }
    if (gen === generation) { ui.sync.textContent = `Last checked ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}. New messages are checked every 30 seconds.`; render(); }
  } catch (error) {
    if (gen === generation) ui.sync.textContent = explain(error, 'The network could not be reached. Checking again automatically.');
  } finally { if (gen === generation) syncing = false; }
}

async function syncRequests(gen) {
  const result = await core.requestsFetch();
  if (gen !== generation) return;
  const pending = new Set(state.outgoing.map(o => o.fp));
  const latest = new Map();
  for (const request of result.requests || []) {
    if (!request || !HEX128.test(request.sender) || request.sender === ownFp) continue;
    if (acceptanceMayAutoApprove(request, pending)) { await completeOutgoing(request, gen); if (gen !== generation) return; continue; }
    // An acceptance without our own pending request is ignored (the app's
    // HIGH-7 rule, dna_engine_contacts.c:555-562).
    if (request.acceptance === true) continue;
    if (contactOf(request.sender) || state.declined.includes(request.sender)) continue;
    const seen = latest.get(request.sender);
    if (!seen || u64(request.timestamp) > u64(seen.timestamp)) latest.set(request.sender, request);
  }
  requests = [...latest.values()];
}

// They accepted our request: the contact uses the salt WE offered, and our
// request is withdrawn as the app does after an auto-approve (nc_core.h
// nc_request_cancel, dna_engine_contacts.c:580).
async function completeOutgoing(request, gen) {
  const mine = state.outgoing.find(o => o.fp === request.sender);
  addContactLocal(request.sender, mine?.salt || request.salt || null);
  await persist();
  if (gen !== generation) return;
  try { await core.requestCancel(request.sender); } catch { /* the request expires on its own */ }
}

async function syncContact(contact, gen) {
  const fp = contact.fp;
  if (!await ensureProfile(fp) || gen !== generation) return;
  if (!saltChecked.has(fp)) {
    const result = await core.saltReconcile(fp, contact.salt || null);
    if (gen !== generation) return;
    if (result.status !== 'wait') {
      saltChecked.add(fp);
      if (result.salt && result.salt !== contact.salt) { contact.salt = result.salt; await persist(); unpublished.add(fp); }
    }
  }
  if (!contact.salt) return;
  const salt = contact.salt;

  // Delivery (NC-RT2 A, text.js markDelivered): which own messages were
  // published is taken BEFORE the ACK read is issued; a publish finishing
  // meanwhile (send()) does not count for this read.
  const publishedBefore = publishedSeqs(messages, fp);
  const ack = await core.ackGet(fp, salt);
  if (gen !== generation) return;
  const ackValue = ack.outcome === 'found' && ack.ack_ts !== undefined && ack.ack_ts !== null ? String(ack.ack_ts) : null;
  if (ackValue !== null && /^(0|[1-9]\d{0,19})$/.test(ackValue)) {
    const delivered = markDelivered(messages, fp, ackValue, publishedBefore, nowSeconds());
    if (delivered.length || state.acks[fp] !== ackValue) {
      state.acks[fp] = ackValue;           // the last ACK value read
      await saveUpdated(delivered);
      if (!delivered.length) await persist();
      if (gen !== generation) return;
    }
  }

  if (unpublished.has(fp)) await publishOutbox(contact, gen);
  if (gen !== generation) return;

  const arrived = []; let lost = 0, other = 0;
  for (const day of recentDays(core.dayToday())) {
    const result = await core.outboxFetchDay(fp, salt, day);
    if (gen !== generation) return;
    lost += Number(result.dropped || 0);
    other += Number(result.other || 0);
    for (const m of result.messages || []) {
      const key = receivedKey(fp, m);
      if (received.has(key)) continue;
      received.add(key);
      arrived.push({ fp, dir: 'in', text: String(m.text), senderTs: String(m.senderTs), remoteSeq: String(m.seq), at: Date.now() });
    }
  }
  if (lost) dropped.set(fp, lost);
  if (other) others.set(fp, other); else others.delete(fp);
  if (arrived.length) {
    for (const m of arrived) m.seq = takeSeq();
    try { await persist(arrived); }
    catch (error) { for (const m of arrived) received.delete(receivedKey(fp, { seq: m.remoteSeq, senderTs: m.senderTs, text: m.text })); throw error; }
    if (gen !== generation) return;
    messages.push(...arrived);
  }
  // G11 + NC-RT2 A: ACK only what is durably stored (the save above resolved
  // on the transaction's oncomplete), with the NEWEST stored sender
  // timestamp of this contact as the value (never this device's clock), not
  // at all when a message of this check could not be verified (it would be
  // covered without being stored), and not again unless something newer was
  // stored than the value last published (state.ackSent, kept across
  // sessions). An unsaved wallet keeps nothing, so it never ACKs: the sender
  // keeps the messages for next time. Items that are not text (`other`) are
  // not stored and never raise the value.
  if (store.persistent && !lost) {
    const value = ackToSend(messages, fp, state.ackSent[fp]);
    if (value) {
      await core.ackPublish(fp, salt, value);
      if (gen !== generation) return;
      state.ackSent[fp] = value;
      await persist();
    }
  }
}

// Publishes the whole pending set; after the PUT succeeded, the messages in
// it are flagged `published` (saved) — only those can later count as
// delivered (text.js markDelivered).
async function publishOutbox(contact, gen) {
  const set = pendingOutbox(messages, contact.fp, nowSeconds());
  if (!set.length) { unpublished.delete(contact.fp); return; }
  if (!contact.salt || !await ensureProfile(contact.fp) || gen !== generation) return;
  await core.outboxPublish(contact.fp, contact.salt, set);
  if (gen !== generation) return;
  unpublished.delete(contact.fp);
  await saveUpdated(markPublished(messages, contact.fp, set));
}

// ── read marks (UI only, this session; nothing is stored) ──────────────
function newestSeq(fp) {
  let newest = -1n;
  for (const m of messages) if (m.fp === fp && BigInt(m.seq) > newest) newest = BigInt(m.seq);
  return newest;
}
function markRead(fp) { lastRead.set(fp, newestSeq(fp)); }
function unreadCount(fp) {
  const seen = lastRead.get(fp) ?? -1n;
  return messages.filter(m => m.fp === fp && m.dir === 'in' && BigInt(m.seq) > seen).length;
}
function lastMessage(fp) {
  let last;
  for (const m of messages) if (m.fp === fp && (!last || compareLocal(m, last) > 0)) last = m;
  return last;
}

// ── view: building blocks ──────────────────────────────────────────────
function setAttrs(node, attrs) { for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value); return node; }
function input(tag, attrs) { return setAttrs(document.createElement(tag), attrs); }
function field(id, labelText, control) { return [setAttrs(el('label', { text: labelText }), { for: id }), control]; }
function statusLine(className = 'hint') { return setAttrs(el('p', { className }), { role: 'status', 'aria-live': 'polite' }); }

// A circle with two hex digits of the ID: an ID-derived mark, never a name
// (a claimed name is unverified, G9). The colour class is a pure function of
// the ID, so the same contact keeps its colour.
function avatar(fp, extra = '') {
  const node = el('span', { className: `contact-avatar avatar-${parseInt(fp[0], 16) % 6}${extra}`, text: fp.slice(0, 2).toUpperCase() });
  node.setAttribute('aria-hidden', 'true');
  return node;
}

function claimedNameHint(fp, prefix = 'claims the name ') {
  const name = profiles.get(fp)?.claimed_name;
  return name ? el('span', { className: 'contact-claim' }, prefix, untrusted(name, undefined, { name: true })) : null;
}

function backButton() {
  const node = button('← Contacts', () => { narrow = 'list'; renderLayout(); ui.sidebar.querySelector('.contact-row[aria-current="true"], .contact-row')?.focus(); }, 'secondary small messenger-back');
  node.setAttribute('aria-label', 'Back to contacts');
  return node;
}

function viewHead(title, ...extra) {
  const heading = el('h4', { text: title });
  heading.tabIndex = -1;
  return { heading, head: el('div', { className: 'messenger-view-head' }, backButton(), heading, ...extra) };
}

const sameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
function shortWhen(at) {
  const date = new Date(at), now = new Date();
  return sameDay(date, now) ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}
function dayLabel(date) {
  const now = new Date(), yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
  if (sameDay(date, now)) return 'Today';
  if (sameDay(date, yesterday)) return 'Yesterday';
  return date.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: date.getFullYear() === now.getFullYear() ? undefined : 'numeric' });
}

async function copyOwnId(statusNode) {
  if (!ownFp) return;
  try { await navigator.clipboard.writeText(ownFp); statusNode.textContent = 'Your ID was copied.'; }
  catch { statusNode.textContent = 'Copy is unavailable. Select your ID and copy it.'; }
}

// ── view: the one-time DOM ─────────────────────────────────────────────
// root: an empty element of the host page. host.onUnread(n): optional, the
// total of unread messages (e.g. for a navigation badge).
export function mountMessages(root, options = {}) {
  host = options;
  const u = {};
  u.stateTitle = el('h4', { text: 'Messages' });
  u.stateText = statusLine('hint');
  u.retry = button('Try again', () => {
    if (!core || !ownFp) return;
    const gen = generation;
    finishOpen(gen).catch(error => { if (gen === generation) closeMessages(explain(error, 'Messages could not connect to the network right now. Try again in a minute.'), { retry: true }); });
  }, 'secondary small');
  u.stateView = el('div', { className: 'messenger-view messenger-state' }, el('span', { className: 'messenger-state-mark' }), u.stateTitle, u.stateText, u.retry);
  u.stateView.querySelector('.messenger-state-mark').setAttribute('aria-hidden', 'true');

  // Sidebar: actions, the requests entry, the contact list.
  u.addButton = button('＋ Add contact', () => showPane('add'), 'small');
  u.profileButton = button('Your ID & profile', () => showPane('profile'), 'secondary small');
  u.requestCount = el('span', { className: 'count-badge' });
  u.requestsButton = button('', () => showPane('requests'), 'contact-row requests-row');
  const requestsIcon = el('span', { className: 'contact-avatar requests-avatar', text: '⇄' });
  requestsIcon.setAttribute('aria-hidden', 'true');
  u.requestsText = el('small', { text: '' });
  u.requestsButton.append(requestsIcon, el('span', { className: 'contact-main' }, el('strong', { text: 'Contact requests' }), u.requestsText), el('span', { className: 'contact-side' }, u.requestCount));
  u.contactList = setAttrs(el('ul', { className: 'contact-list' }), { 'aria-label': 'Conversations' });
  u.sidebar = setAttrs(el('div', { className: 'messenger-sidebar' }, el('div', { className: 'messenger-actions' }, u.addButton, u.profileButton), u.requestsButton, u.contactList), { role: 'navigation', 'aria-label': 'Contacts' });

  // Empty pane.
  u.emptyTitle = el('h4');
  u.emptyText = el('p', { className: 'hint' });
  u.emptyCopyStatus = statusLine();
  u.emptyActions = el('div', { className: 'messenger-empty-actions' },
    button('＋ Add contact', () => showPane('add'), 'small'),
    button('Copy your ID', () => void copyOwnId(u.emptyCopyStatus), 'secondary small'));
  u.emptyView = el('div', { className: 'messenger-view messenger-empty' }, el('span', { className: 'messenger-empty-mark', text: '✉' }), u.emptyTitle, u.emptyText, u.emptyActions, u.emptyCopyStatus);
  u.emptyView.querySelector('.messenger-empty-mark').setAttribute('aria-hidden', 'true');

  // Conversation pane.
  u.convAvatar = el('span');
  u.convTitle = el('h4');
  u.convTitle.tabIndex = -1;
  u.convClaim = el('span', { className: 'contact-claim' });
  u.convHead = el('div', { className: 'messenger-view-head conversation-head' }, backButton(), u.convAvatar, el('div', { className: 'conversation-title' }, u.convTitle, u.convClaim));
  u.convNote = el('p', { className: 'notice conversation-note' });
  u.messageList = setAttrs(el('ol', { className: 'message-list' }), { 'aria-label': 'Messages', 'aria-live': 'polite' });
  u.composer = input('textarea', { id: 'nc-send-text', rows: '1', maxlength: String(TEXT_MAX), placeholder: 'Write a message', 'aria-label': 'Message', autocomplete: 'off' });
  u.sendButton = el('button', { text: 'Send' }); u.sendButton.type = 'submit';
  u.counter = el('small', { className: 'composer-counter' });
  u.sendStatus = statusLine('hint composer-status');
  u.sendForm = el('form', { className: 'composer' }, el('div', { className: 'composer-row' }, u.composer, u.sendButton), el('div', { className: 'composer-foot' }, el('small', { className: 'composer-hint', text: 'Enter to send · Shift+Enter for a new line' }), u.counter), u.sendStatus);
  u.sendForm.id = 'nc-send-form';
  u.notReady = el('p', { className: 'hint composer-closed', text: 'Messaging with this contact is not ready yet. It is checked again automatically.' });
  u.conversationView = el('div', { className: 'messenger-view messenger-conversation' }, u.convHead, u.convNote, u.messageList, u.sendForm, u.notReady);

  // Add-contact pane.
  const add = viewHead('Add a contact');
  u.addHeading = add.heading;
  u.addId = input('input', { id: 'nc-add-id', type: 'text', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', maxlength: '256', required: '' });
  u.addNote = input('input', { id: 'nc-add-note', type: 'text', maxlength: '200', autocomplete: 'off' });
  u.addStatus = statusLine();
  const addSubmit = el('button', { text: 'Send contact request' }); addSubmit.type = 'submit';
  u.addForm = el('form', { className: 'messenger-form' },
    ...field('nc-add-id', 'Their ID', u.addId),
    el('p', { className: 'hint', text: 'An ID is 128 characters, letters a–f and digits. Ask them to copy it from “Your ID & profile”.' }),
    ...field('nc-add-note', 'Note (optional, they see it with your request)', u.addNote),
    addSubmit, u.addStatus);
  u.addForm.id = 'nc-add-form';
  u.addView = el('div', { className: 'messenger-view messenger-scroll' }, add.head, u.addForm);

  // Requests pane.
  const req = viewHead('Contact requests');
  u.requestsHeading = req.heading;
  u.requestList = el('ul', { className: 'request-list' });
  u.outgoingList = el('ul', { className: 'request-list' });
  u.requestsStatus = statusLine();
  u.requestsView = el('div', { className: 'messenger-view messenger-scroll' }, req.head,
    el('h5', { text: 'Waiting for you' }), u.requestList,
    el('h5', { text: 'Sent by you' }), u.outgoingList, u.requestsStatus);

  // Profile pane.
  const prof = viewHead('Your ID & profile');
  u.profileHeading = prof.heading;
  u.ownId = el('code', { className: 'own-id' });
  u.ownId.id = 'nc-own-id';
  u.copyStatus = statusLine();
  u.profileName = el('p', { className: 'hint' });
  u.bio = input('textarea', { id: 'nc-bio', rows: '3' });
  u.location = input('input', { id: 'nc-location', type: 'text', autocomplete: 'off' });
  u.website = input('input', { id: 'nc-website', type: 'url', autocomplete: 'off' });
  u.profileStatus = statusLine();
  const profileSubmit = el('button', { text: 'Save profile' }); profileSubmit.type = 'submit';
  u.profileForm = el('form', { className: 'messenger-form' },
    ...field('nc-bio', 'About you', u.bio), ...field('nc-location', 'Location', u.location),
    ...field('nc-website', 'Website (https:// only)', u.website), profileSubmit, u.profileStatus);
  u.profileForm.id = 'nc-profile-form';
  u.memoryNote = el('p', { className: 'notice', text: 'This wallet is not saved on this device: messages are not kept after you lock, and senders are not told their messages arrived. Save the wallet in Device & settings, then lock and open it again to keep messages.' });
  u.memoryNote.hidden = true;
  u.erase = button('Delete message history on this device', () => void erase(), 'secondary small messenger-erase');
  u.erase.hidden = true;
  u.profileView = el('div', { className: 'messenger-view messenger-scroll' }, prof.head,
    el('div', { className: 'own-id-box' }, el('span', { className: 'own-id-label', text: 'Your ID — share it so others can add you' }), u.ownId,
      button('Copy your ID', () => void copyOwnId(u.copyStatus), 'secondary small'), u.copyStatus),
    el('h5', { text: 'Your profile' }),
    el('p', { className: 'hint', text: 'Everyone can read your profile. A name cannot be chosen here yet.' }),
    u.profileName, u.profileForm, u.memoryNote, u.erase);

  u.main = el('div', { className: 'messenger-main' }, u.stateView, u.emptyView, u.conversationView, u.addView, u.requestsView, u.profileView);
  u.layout = el('div', { className: 'messenger' }, u.sidebar, u.main);
  u.sync = el('p', { className: 'messenger-sync' });
  u.sync.setAttribute('role', 'status');
  root.replaceChildren(u.layout, u.sync);
  ui = u;

  u.addForm.onsubmit = event => void addContact(event);
  u.sendForm.onsubmit = event => void send(event);
  u.profileForm.onsubmit = event => void saveProfile(event);
  u.composer.addEventListener('input', growComposer);
  u.composer.addEventListener('keydown', event => {
    // Enter sends, Shift+Enter is a new line; never while an IME composes.
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing || event.keyCode === 229) return;
    event.preventDefault();
    u.sendForm.requestSubmit();
  });
  resetMessages();
}

function growComposer() {
  const text = ui.composer.value;
  const lines = text.split('\n').length + Math.floor(text.length / 60);
  ui.composer.rows = Math.max(1, Math.min(COMPOSER_ROWS, lines));
  ui.counter.textContent = text.length > TEXT_MAX - 500 ? `${text.length} / ${TEXT_MAX}` : '';
}

// ── view: what is shown ────────────────────────────────────────────────
function showState(title, text, retry) {
  if (!ui) return;
  ui.stateTitle.textContent = title;
  ui.stateText.textContent = text;
  ui.retry.hidden = !retry;
  ui.stateView.dataset.kind = phase;
  ui.sync.textContent = phase === 'open' ? ui.sync.textContent : '';
  render();
}

function showPane(next) {
  if (!isOpen()) return;
  pane = next;
  if (next !== 'conversation') selectedFp = undefined;
  narrow = 'main';
  if (next === 'requests') ui.requestsStatus.textContent = '';
  render();
  const focus = { add: ui.addId, requests: ui.requestsHeading, profile: ui.profileHeading }[next];
  focus?.focus({ preventScroll: true });
}

function selectContact(fp) {
  selectedFp = fp; pane = 'conversation'; narrow = 'main';
  ui.sendStatus.textContent = '';
  markRead(fp);
  render({ scroll: true });
  if (contactOf(fp)?.salt) ui.composer.focus({ preventScroll: true });
}

// data-view drives the ≤ 700 px layout (messenger.css): 'list', 'main', or
// 'state' while Messages is not open (its status is the only thing shown).
function renderLayout() {
  ui.layout.dataset.view = isOpen() ? narrow : 'state';
}

function render({ scroll = false } = {}) {
  if (!ui) return;
  const open = isOpen();
  for (const control of [ui.addButton, ui.profileButton, ui.requestsButton]) control.disabled = !open;
  if (open && pane === 'conversation' && selectedFp && !contactOf(selectedFp)) { pane = 'empty'; selectedFp = undefined; }
  const active = !open ? 'state' : pane;
  const views = { state: ui.stateView, empty: ui.emptyView, conversation: ui.conversationView, add: ui.addView, requests: ui.requestsView, profile: ui.profileView };
  for (const [name, node] of Object.entries(views)) node.hidden = name !== active;
  renderLayout();
  renderSidebar(open);
  if (!open) { host.onUnread?.(0); return; }
  if (pane === 'conversation' && selectedFp) markRead(selectedFp);
  if (pane === 'empty') renderEmpty();
  if (pane === 'requests') renderRequests();
  if (pane === 'conversation') renderConversation(scroll);
  host.onUnread?.(state.contacts.reduce((sum, c) => sum + unreadCount(c.fp), 0));
}

function renderSidebar(open) {
  ui.requestCount.textContent = open && requests.length ? String(requests.length) : '';
  ui.requestCount.hidden = !(open && requests.length);
  ui.requestsText.textContent = !open ? '' : requests.length ? `${requests.length} waiting for you` : state.outgoing.length ? `${state.outgoing.length} sent, waiting for an answer` : 'None waiting';
  ui.requestsButton.setAttribute('aria-current', String(open && pane === 'requests'));
  if (!open) {
    ui.contactList.replaceChildren(el('li', { className: 'contact-empty', text: phase === 'opening' ? 'Loading your contacts…' : 'Your contacts appear here once Messages is open.' }));
    return;
  }
  if (!state.contacts.length) {
    ui.contactList.replaceChildren(el('li', { className: 'contact-empty', text: 'No contacts yet. Add one with their ID.' }));
    return;
  }
  // Most recent conversation first (local order), then contacts without
  // messages in list order; ties keep the list order (stable sort).
  const ordered = state.contacts.map((c, index) => ({ c, index, last: lastMessage(c.fp) }))
    .sort((a, b) => (a.last && b.last ? compareLocal(b.last, a.last) : a.last ? -1 : b.last ? 1 : 0) || a.index - b.index);
  ui.contactList.replaceChildren(...ordered.map(({ c, last }) => {
    const unread = unreadCount(c.fp);
    const row = el('button', { className: `contact-row${unread ? ' has-unread' : ''}` });
    row.type = 'button';
    row.setAttribute('aria-current', String(pane === 'conversation' && c.fp === selectedFp));
    const preview = el('span', { className: 'contact-preview' });
    if (last) preview.append(last.dir === 'out' ? 'You: ' : '', untrusted(last.text));
    else preview.textContent = c.salt ? 'No messages yet' : 'Messaging is not ready yet';
    const side = el('span', { className: 'contact-side' });
    if (last) { const when = el('time', { text: shortWhen(last.at) }); when.dateTime = new Date(last.at).toISOString(); side.append(when); }
    if (unread) side.append(setAttrs(el('span', { className: 'count-badge', text: String(unread) }), { 'aria-label': `${unread} new` }));
    row.append(avatar(c.fp), el('span', { className: 'contact-main' }, el('span', { className: 'contact-name' }, el('strong', { text: shortId(c.fp) }), claimedNameHint(c.fp)), preview), side);
    row.onclick = () => selectContact(c.fp);
    return el('li', {}, row);
  }));
}

function renderEmpty() {
  const none = state.contacts.length === 0;
  ui.emptyTitle.textContent = none ? 'No contacts yet' : 'Choose a conversation';
  ui.emptyText.textContent = none
    ? 'Add a contact with their ID — a 128-character code they copy from “Your ID & profile”. Share your ID the same way so others can add you. Once they accept, you can write to each other.'
    : 'Pick a contact on the left, or add a new one with their ID.';
}

function renderRequests() {
  ui.requestList.replaceChildren(...(requests.length ? requests.map(request => el('li', { className: 'request-row' },
    avatar(request.sender),
    el('div', { className: 'request-main' },
      el('span', { className: 'contact-name' }, el('span', { className: 'request-label', text: 'Not a contact' }), el('strong', { text: shortId(request.sender) })),
      request.claimed_name ? el('span', { className: 'contact-claim' }, 'says their name is ', untrusted(request.claimed_name, undefined, { name: true })) : null,
      request.message ? el('p', { className: 'request-note' }, untrusted(request.message)) : null,
      el('div', { className: 'request-actions' }, button('Accept', () => void accept(request), 'small'), button('Decline', () => void decline(request), 'secondary small')))
  )) : [el('li', { className: 'contact-empty', text: 'No new requests.' })]));

  ui.outgoingList.replaceChildren(...(state.outgoing.length ? state.outgoing.map(o => el('li', { className: 'request-row' },
    avatar(o.fp),
    el('div', { className: 'request-main' },
      el('span', { className: 'contact-name' }, el('strong', { text: shortId(o.fp) })),
      el('span', { className: 'contact-claim', text: 'waiting for them to accept' }),
      el('div', { className: 'request-actions' }, button('Withdraw', () => void withdraw(o.fp), 'secondary small')))
  )) : [el('li', { className: 'contact-empty', text: 'None.' })]));
}

function renderConversation(scroll) {
  const contact = contactOf(selectedFp);
  const list = ui.messageList;
  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
  ui.convAvatar.replaceWith(ui.convAvatar = avatar(contact.fp, ' conversation-avatar'));
  ui.convTitle.textContent = shortId(contact.fp);
  const claim = claimedNameHint(contact.fp);
  ui.convClaim.replaceChildren(...(claim ? claim.childNodes : []));
  const lost = dropped.get(contact.fp), other = others.get(contact.fp);
  ui.convNote.textContent = [
    lost ? 'Some messages from this contact could not be checked and are not shown.' : '',
    other ? 'This contact also sent items this page cannot show yet (for example reactions, pictures or calls).' : ''
  ].filter(Boolean).join(' ');
  ui.convNote.hidden = !ui.convNote.textContent;
  ui.sendForm.hidden = !contact.salt;
  ui.notReady.hidden = !!contact.salt;

  const items = [];
  let day;
  for (const m of messages.filter(x => x.fp === contact.fp).sort(compareLocal)) {
    const at = new Date(m.at);
    if (!day || !sameDay(day, at)) { day = at; items.push(el('li', { className: 'message-day', text: dayLabel(at) })); }
    const mine = m.dir === 'out';
    const when = el('time', { text: at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
    when.dateTime = at.toISOString();
    const meta = el('div', { className: 'message-meta' }, when);
    if (mine) {
      const status = messageStatus(m);
      meta.append(el('span', { className: `message-status message-${status.replace(/ /g, '-')}`, text: `${STATUS_MARK[status] || ''} ${status}` }));
    } else meta.append(el('span', { className: 'message-clock', text: senderClockLabel(m.senderTs) }));
    // The message body lives only inside the bubble (§1.9).
    items.push(el('li', { className: mine ? 'message message-out' : 'message message-in' }, el('div', { className: 'message-bubble' }, untrusted(m.text)), meta));
  }
  if (!items.length) items.push(el('li', { className: 'message-none', text: contact.salt ? 'No messages yet. Say hello.' : 'No messages yet.' }));
  list.replaceChildren(...items);
  if (scroll || atBottom) list.scrollTop = list.scrollHeight;
}

function fillProfile() {
  const p = ownProfile || {};
  ui.bio.value = p.bio || ''; ui.location.value = p.location || ''; ui.website.value = p.website || '';
  const line = ui.profileName;
  line.replaceChildren();
  if (p.claimed_name) line.append('Name on your profile (not checked here): ', untrusted(p.claimed_name, undefined, { name: true }));
  else line.textContent = 'Your profile has no name.';
  if (p.website) { const link = website(p.website); if (link) line.append(el('br'), 'Website: ', link); }
}

// ── actions ────────────────────────────────────────────────────────────
async function accept(request) {
  const gen = generation;
  ui.requestsStatus.textContent = 'Accepting…';
  try {
    if (!await ensureProfile(request.sender)) { if (gen === generation) ui.requestsStatus.textContent = "This person's account could not be read right now. Try again in a minute."; return; }
    if (gen !== generation) return;
    await core.requestAccept(request.sender, request.salt || null);
    if (gen !== generation) return;
    addContactLocal(request.sender, request.salt || null);
    requests = requests.filter(r => r.sender !== request.sender);
    await persist();
    if (gen !== generation) return;
    ui.requestsStatus.textContent = 'Contact added.';
    markRead(request.sender);
    render();
    await publishContacts(gen);
  } catch (error) { if (gen === generation) ui.requestsStatus.textContent = explain(error, 'Accepting failed. Try again in a minute.'); }
}

async function decline(request) {
  // Local only: the request is hidden on this device and expires on the network.
  state.declined.push(request.sender);
  requests = requests.filter(r => r.sender !== request.sender);
  render();
  try { await persist(); } catch (error) { ui.requestsStatus.textContent = error.message; }
}

async function withdraw(fp) {
  const gen = generation;
  try {
    await core.requestCancel(fp);
    if (gen !== generation) return;
    state.outgoing = state.outgoing.filter(o => o.fp !== fp);
    await persist();
    if (gen === generation) { ui.requestsStatus.textContent = 'Request withdrawn.'; render(); }
  } catch (error) { if (gen === generation) ui.requestsStatus.textContent = explain(error, 'Withdrawing failed. Try again in a minute.'); }
}

async function addContact(event) {
  event.preventDefault();
  const gen = generation;
  try {
    const fp = parseContactId(ui.addId.value);
    if (fp === ownFp) throw new Error('That is your own ID.');
    if (contactOf(fp)) throw new Error('This person is already a contact.');
    if (state.outgoing.some(o => o.fp === fp)) throw new Error('You already sent this person a request.');
    const note = ui.addNote.value;
    ui.addStatus.textContent = 'Sending request…';
    let result;
    try { result = await core.requestSend(fp, note); }
    catch { throw new Error(new TextEncoder().encode(note).length > 255 ? 'The note is too long.' : 'The request could not be sent. Try again in a minute.'); }
    if (gen !== generation) return;
    // The offered salt is kept until they accept (core.js requestSend).
    state.outgoing.push({ fp, salt: result.salt, at: nowSeconds() });
    await persist();
    if (gen !== generation) return;
    ui.addId.value = ''; ui.addNote.value = '';
    ui.addStatus.textContent = 'Request sent. They appear in your contacts once they accept.';
    render();
  } catch (error) { if (gen === generation) ui.addStatus.textContent = error.message; }
}

async function send(event) {
  event.preventDefault();
  const gen = generation, contact = selectedFp && contactOf(selectedFp);
  const text = ui.composer.value;
  if (!contact || !contact.salt || !text.trim()) return;
  if (text.length > TEXT_MAX) { ui.sendStatus.textContent = `A message can be at most ${TEXT_MAX} characters.`; return; }
  try {
    const message = { seq: takeSeq(), fp: contact.fp, dir: 'out', text, ts: nowSeconds(), at: Date.now() };
    await persist([message]);
    if (gen !== generation) return;
    messages.push(message); unpublished.add(contact.fp);
    ui.composer.value = ''; growComposer();
    render({ scroll: true });
    try { await publishOutbox(contact, gen); if (gen === generation) ui.sendStatus.textContent = ''; }
    catch { if (gen === generation) ui.sendStatus.textContent = 'Not sent yet. It is tried again automatically.'; }
    if (gen === generation) render();
  } catch (error) { if (gen === generation) ui.sendStatus.textContent = error.message; }
}

async function saveProfile(event) {
  event.preventDefault();
  const gen = generation;
  if (profileTaken) return;
  try {
    const patch = profilePatch({ bio: ui.bio.value, location: ui.location.value, website: ui.website.value });
    ui.profileStatus.textContent = 'Saving…';
    const result = await core.profileUpdate(patch);
    if (gen !== generation) return;
    ui.profileStatus.textContent = profileStatusText(result.status);
    if (result.status === 'published') { ownProfile = { ...(ownProfile || {}), ...patch }; fillProfile(); }
    if (result.status === 'taken') profileTaken = true;
  } catch (error) { if (gen === generation) ui.profileStatus.textContent = /https|Invalid profile/.test(error.message) ? error.message : 'Saving failed. Try again later.'; }
}

async function erase() {
  if (!store?.persistent) return;
  if (!eraseArmed) { eraseArmed = true; ui.erase.textContent = 'Confirm: delete all messages on this device'; return; }
  const target = store;
  try { await target.erase(); closeMessages('Message history deleted from this device. Lock and open your wallet again to use Messages.'); }
  catch (error) { closeMessages(error.message); }
}

// ── the wallet as host (src/wallet-extensions.js events) ───────────────
// Registered only by the Nodus Connect page (src/connect-main.js).
export const walletExtension = {
  nodusReady(detail) { void openMessages(detail); },
  // reason: the connection was lost (Messages stays closed until the wallet
  // is opened again); none: the wallet is locking or reconnecting.
  nodusClosing({ reason } = {}) { if (reason) closeMessages(reason); else resetMessages(); },
  nodusUnavailable() { closeMessages(UNAVAILABLE_TEXT); },
  // The saved wallet (and with it this history, src/app.js vault-delete) is
  // being deleted: the open store must not hold the database.
  vaultDeleting() { if (store?.persistent) closeMessages('The saved wallet and its message history were deleted from this device. Lock and open your wallet again to use Messages.'); },
  locked() { resetMessages(); }
};
