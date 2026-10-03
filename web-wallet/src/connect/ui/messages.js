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
  parseContactId, profilePatch, profileStatusText, contactListStatusText, senderClockLabel,
  recentDays, pendingOutbox, hasUndelivered, compareLocal, receivedKey,
  publishedSeqs, markPublished, markDelivered, ackToSend, messageStatus, avatarPatch, AVATAR_UPLOAD_MAX_B64,
  needFullSync, fullDays, profileFresh, contactNames
} from './text.js';
import { el, untrusted, button, website, fillAvatar } from './dom.js';
import { chainNameOk, parseNameOf } from '../../nodus/names.js';

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
const kept = new Map();                  // fp -> { id, record }: kept profile rows (saved wallet, state.profileCache)
const blobs = new Map();                 // 'fp|day' -> { blob, other }: day buckets already stored, this session
const received = new Set();              // receivedKey of every stored incoming message
const unpublished = new Set();           // contacts whose pending set must be (re)published
const saltChecked = new Set();           // contacts whose salt was reconciled this session
const dropped = new Map();               // fp -> messages that did not verify, this session
const others = new Map();                // fp -> authentic items that are not text (reactions, calls, …), last check
const lastRead = new Map();              // fp -> highest local seq shown to the user (this session only)
const vaultRecs = new Map();             // vault address -> { id, value }: shared vaults kept (state.vaults, src/vaults/)
// HF-4 chain names: fp -> the chain name ('' = none, or not answered), this
// session; kept across sessions only for a saved wallet (state.chainNames).
const chainNames = new Map();
let nodusClient;                         // the wallet's client (nameOf), this session

// ── view state ─────────────────────────────────────────────────────────
// The screens follow the DNA Connect app (messenger/dna_messenger_flutter):
// 'list' = Chats (screens/messages/messages_screen.dart), 'conversation' =
// the chat opened on its own (screens/chat/chat_screen.dart), 'contacts' =
// the contacts hub with its Contacts / Requests tabs
// (screens/contacts/contacts_hub_screen.dart), 'profile' = your ID and
// profile. Add contact is a dialog (screens/contacts/add_contact_dialog.dart).
let ui, host = {};
let phase = 'waiting';                   // 'waiting' | 'opening' | 'open' | 'closed'
let screen = 'list';                     // 'list' | 'conversation' | 'contacts' | 'profile'
let hubTab = 'contacts';                 // the contacts screen's tab: 'contacts' | 'requests'
let filter = 'all';                      // the Chats filter chip: 'all' | 'unread' | 'chats'
let notifiedScreen, notifiedId;          // last values handed to host.onScreen / host.onIdentity

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
  fresh = false; vaultId = null; requests = []; selectedFp = undefined; nodusClient = undefined;
  eraseArmed = false; profileTaken = false;
  for (const set of [profiles, kept, blobs, received, unpublished, saltChecked, dropped, others, lastRead, chainNames, vaultRecs]) set.clear();
  notifyVaultHost();
  if (!ui) return;
  for (const control of [ui.addId, ui.addNote, ui.composer, ui.bio, ui.location, ui.website]) control.value = '';
  ui.composer.rows = 1; ui.counter.textContent = '';
  for (const line of [ui.addStatus, ui.sendStatus, ui.profileStatus, ui.copyStatus, ui.emptyCopyStatus, ui.requestsStatus, ui.sync, ui.ownId, ui.profileName, ui.avatarStatus, ui.ownAvatar]) line.textContent = '';
  ui.messageList.replaceChildren(); ui.requestList.replaceChildren(); ui.outgoingList.replaceChildren();
  ui.contactList.replaceChildren(); ui.hubList.replaceChildren(); ui.convTitle.textContent = ''; ui.convClaim.replaceChildren(); ui.convNote.textContent = '';
  ui.erase.textContent = 'Delete message history on this device';
  ui.avatarChange.disabled = ui.avatarRemove.disabled = false;
  if (ui.addDialog.open) ui.addDialog.close();
  screen = 'list'; hubTab = 'contacts'; filter = 'all';
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
    nodusClient = client;
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
    for (const p of store.profiles) kept.set(p.fp, { id: p.id, record: p.record });
    for (const v of store.vaults || []) vaultRecs.set(v.address, { id: v.id, value: v.value });
    for (const m of messages) if (m.dir === 'in') received.add(receivedKey(m.fp, { seq: m.remoteSeq, senderTs: m.senderTs, text: m.text }));
    const now = nowSeconds();
    for (const contact of state.contacts) if (hasUndelivered(messages, contact.fp, now)) unpublished.add(contact.fp);
    // History from earlier sessions is not "new".
    for (const contact of state.contacts) markRead(contact.fp);
  }
  await mergeContactList(gen);
  if (gen !== generation) return;
  // Kept profiles younger than 7 days are in place before the first screen
  // (no network: core.profileLoad), so names and pictures show at once.
  for (const contact of state.contacts) {
    const entry = state.profileCache[contact.fp], row = kept.get(contact.fp);
    if (profiles.has(contact.fp) || !entry || row?.id !== entry.id || !profileFresh(entry, nowSeconds())) continue;
    try { profiles.set(contact.fp, (await core.profileLoad(contact.fp, row.record, entry.name)).profile); }
    catch { /* read from the network by the first check */ }
    if (gen !== generation) return;
  }
  // Kept chain names younger than 7 days, likewise (no network).
  for (const fp of [ownFp, ...state.contacts.map(c => c.fp)]) keptChainName(fp);

  ui.ownId.textContent = ownFp;
  ui.memoryNote.hidden = store.persistent;
  ui.erase.hidden = !store.persistent;
  fillProfile();
  phase = 'open';
  screen = 'list';
  render();
  clearInterval(syncTimer);
  syncTimer = setInterval(() => { void sync(); }, SYNC_MS);
  notifyVaultHost();
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

// A profile once per session — for a contact of a saved wallet from the
// kept row while it is younger than 7 days, as the app does
// (profile_manager.c:58-130, profile_cache.h:40): the core checks the kept
// row again (signature, fingerprint) before its keys are used. An older
// kept row is read again from the network and replaced; if the network
// cannot give it, the older row is used ("stale fallback"), unless the
// network row failed its checks (then the kept row is dropped, as the app
// deletes it). `keep`: a contact's profile (not a stranger's request) is
// kept for the next session.
const CHECK_FAILED = new Set(['bad_record', 'bad_signature']);
async function ensureProfile(fp, keep = false) {
  if (profiles.has(fp)) return true;
  const entry = state.profileCache[fp], row = kept.get(fp);
  const fromKept = async () => {
    try { profiles.set(fp, (await core.profileLoad(fp, row.record, entry.name)).profile); return true; }
    catch { return false; }
  };
  const usable = entry && row && row.id === entry.id;
  if (usable && profileFresh(entry, nowSeconds()) && await fromKept()) return true;
  const result = await core.profileGet(fp);
  if (result.outcome === 'found') {
    profiles.set(fp, result.profile);
    if (keep) await keepProfile(fp, result);
    return true;
  }
  if (result.outcome === 'unreadable' && CHECK_FAILED.has(result.why)) { await forgetProfile(fp); return false; }
  return usable ? fromKept() : false;
}

// Saved wallets only; a row too large for one stored record is not kept.
const PROFILE_KEEP_MAX = 60000;
async function keepProfile(fp, result) {
  if (!store?.persistent || typeof result.record !== 'string' || result.record.length > PROFILE_KEEP_MAX) return;
  const before = state.profileCache[fp];
  const id = before?.id || `p${takeSeq().padStart(20, '0')}`;
  state.profileCache[fp] = { id, at: nowSeconds(), name: typeof result.profile.name === 'string' ? result.profile.name : '' };
  try {
    await store.save(state, [], [{ id, fp, record: result.record }]);
    kept.set(fp, { id, record: result.record });
  } catch {
    // not kept: read from the network next time
    if (before) state.profileCache[fp] = before; else delete state.profileCache[fp];
  }
}
async function forgetProfile(fp) {
  if (!state.profileCache[fp]) return;
  delete state.profileCache[fp]; kept.delete(fp);
  try { await persist(); } catch { /* the entry is gone from this session */ }
}

// HF-4 chain names (design docs/plans/2026-10-02-onchain-names-design.md
// rev 4 §2 "Clients", R3/R6): the name an ID registered on the chain, from
// ONE node's committed state (dnac_name_of; decision
// 2026-10-02-onchain-names.md item 9). Asked once per session per ID; a
// found name is kept for a saved wallet like a profile (state.chainNames,
// 7 days — decision 2026-10-02-device-cache-only-when-saved: an unsaved
// wallet's state lives in memory only). An older node, a failed read or a
// module without names: no chain name is shown and nothing is kept.
function keptChainName(fp) {
  const entry = state.chainNames[fp];
  if (!chainNames.has(fp) && entry && chainNameOk(entry.name) && profileFresh(entry, nowSeconds())) chainNames.set(fp, entry.name);
}
// `keep`: this ID's or a contact's name (a stranger's request is not kept,
// as ensureProfile). @return true when state.chainNames changed (the caller
// saves once).
async function ensureChainName(fp, keep = false) {
  keptChainName(fp);
  if (chainNames.has(fp) || !nodusClient?.nameable) return false;
  let found;
  try { found = parseNameOf(await nodusClient.nameOf({ owner: fp })); }
  catch { chainNames.set(fp, ''); return false; }
  chainNames.set(fp, found.found ? found.name : '');
  if (found.found && keep) { state.chainNames[fp] = { name: found.name, at: nowSeconds() }; return true; }
  if (!found.found && state.chainNames[fp]) { delete state.chainNames[fp]; return true; }
  return false;
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
    // Smart sync (text.js needFullSync): 8 day buckets when any contact was
    // never checked or the oldest check is over 3 days old, else 3. The
    // check time of each contact whose buckets were all read is kept
    // (state.dmSync) — saved only when it moved by an hour or more, so a
    // 30-second check does not rewrite the state every time.
    const startedAt = nowSeconds(), today = core.dayToday();
    const days = needFullSync(state.contacts.map(c => c.fp), state.dmSync, startedAt) ? fullDays(today) : recentDays(today);
    let syncMoved = false;
    for (const contact of [...state.contacts]) {
      if (gen !== generation) return;
      if (await syncContact(contact, gen, days) && gen === generation) {
        const last = state.dmSync[contact.fp];
        if (!last || BigInt(startedAt) - BigInt(last) >= 3600n) syncMoved = true;
        state.dmSync[contact.fp] = startedAt;
      }
    }
    if (syncMoved && gen === generation) await persist();
    // Names for the request screens: the profiles of the people we asked
    // and of those asking us (read once per session — ensureProfile caches;
    // a name shows only after nc_name_verify proved it).
    for (const fp of new Set([...state.outgoing.map(o => o.fp), ...requests.map(r => r.sender)])) {
      if (gen !== generation) return;
      await ensureProfile(fp);
    }
    // Chain names (HF-4) of this ID, the contacts and the request screens:
    // one read per ID per session (ensureChainName).
    let namesMoved = false;
    for (const fp of new Set([ownFp, ...state.contacts.map(c => c.fp), ...state.outgoing.map(o => o.fp), ...requests.map(r => r.sender)])) {
      if (gen !== generation) return;
      if (await ensureChainName(fp, fp === ownFp || !!contactOf(fp))) namesMoved = true;
    }
    if (namesMoved && gen === generation) await persist();
    if (gen === generation) { fillOwnAvatar(); fillNameLine(); }
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

// True when every bucket of `days` was read (the contact's check time may
// move, sync above).
async function syncContact(contact, gen, days) {
  const fp = contact.fp;
  if (!await ensureProfile(fp, true) || gen !== generation) return false;
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

  // Each bucket is passed the hash of the same bucket this session already
  // stored (blobs); an unchanged bucket is not decoded again (the app's
  // blob cache, dht_dm_outbox.c:30-80) and its non-text count is reused.
  // A hash is remembered only after the bucket's messages were stored, and
  // never for a bucket with a message that did not verify (it stays
  // counted in `dropped` and keeps the ACK back).
  const arrived = [], seen = []; let lost = 0, other = 0, complete = true;
  for (const day of days) {
    const key = `${fp}|${day}`, before = blobs.get(key);
    const result = await core.outboxFetchDay(fp, salt, day, before?.blob || '');
    if (gen !== generation) return false;
    if (result.outcome === 'unreadable') complete = false;
    if (result.unchanged && before) { other += before.other; continue; }
    const dayLost = Number(result.dropped || 0), dayOther = Number(result.other || 0);
    lost += dayLost;
    other += dayOther;
    if (result.outcome === 'found' && typeof result.blob === 'string' && !dayLost) seen.push([key, { blob: result.blob, other: dayOther }]);
    else blobs.delete(key);
    for (const m of result.messages || []) {
      const k = receivedKey(fp, m);
      if (received.has(k)) continue;
      received.add(k);
      arrived.push({ fp, dir: 'in', text: String(m.text), senderTs: String(m.senderTs), remoteSeq: String(m.seq), at: Date.now() });
    }
  }
  if (lost) dropped.set(fp, lost);
  if (other) others.set(fp, other); else others.delete(fp);
  if (arrived.length) {
    for (const m of arrived) m.seq = takeSeq();
    try { await persist(arrived); }
    catch (error) { for (const m of arrived) received.delete(receivedKey(fp, { seq: m.remoteSeq, senderTs: m.senderTs, text: m.text })); throw error; }
    if (gen !== generation) return false;
    messages.push(...arrived);
    notifyVaultHost();
  }
  for (const [key, value] of seen) blobs.set(key, value);
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
      if (gen !== generation) return false;
      state.ackSent[fp] = value;
      await persist();
    }
  }
  // Stricter than the app, which moves the check time even when a bucket
  // read failed: a contact counts as checked only when no bucket was
  // unreadable, so a failed read leads to the 8-bucket check, not a gap.
  return complete;
}

// Publishes the whole pending set; after the PUT succeeded, the messages in
// it are flagged `published` (saved) — only those can later count as
// delivered (text.js markDelivered).
async function publishOutbox(contact, gen) {
  const set = pendingOutbox(messages, contact.fp, nowSeconds());
  if (!set.length) { unpublished.delete(contact.fp); return; }
  if (!contact.salt || !await ensureProfile(contact.fp, true) || gen !== generation) return;
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

// Avatar colour classes are a pure function of the ID, so the same contact
// keeps its colour; a claimed name is never used (it is unverified, G9).
// A registered PROFILE name the core verified (nc_name_verify:
// "<name>:lookup" written by this identity points back to it — design
// §1.9 G9), else ''. Since HF-4 it is shown only labelled "profile name"
// (text.js contactNames): the chain name is the one shown as THE name.
function profileName(fp) {
  const name = profiles.get(fp)?.name;
  return typeof name === 'string' ? name : '';
}
// The chain name of `fp` this session ('' = none or not known).
function chainNameOf(fp) {
  const name = chainNames.get(fp);
  return typeof name === 'string' ? name : '';
}
function namesOf(fp, claimed = profiles.get(fp)?.claimed_name) {
  return contactNames(fp, { chain: chainNameOf(fp), profile: profileName(fp), claimed: typeof claimed === 'string' ? claimed : '' });
}
// What a contact is called: the chain name, else the short ID.
function displayName(fp) { return namesOf(fp).title; }
// The bold line: a chain name gets the verified look (class chain-name and
// a "chain name" label), anything else is the plain short ID.
function nameTitle(fp) {
  const n = namesOf(fp);
  return n.verified
    ? el('strong', { className: 'chain-name', text: n.title })
    : el('strong', { text: n.title });
}

// The two letters shown when there is no picture: of the chain name, else
// of the ID.
export function initials(fp, name) { return (name ? [...name].slice(0, 2).join('') : fp.slice(0, 2)).toUpperCase(); }

// The profile picture (avatar_base64 of the signature-checked profile,
// dom.js fillAvatar), else the initials.
function avatar(fp, extra = '') {
  const node = el('span', { className: `contact-avatar avatar-${parseInt(fp[0], 16) % 6}${extra}` });
  node.setAttribute('aria-hidden', 'true');
  return fillAvatar(node, initials(fp, chainNameOf(fp)), profiles.get(fp)?.avatar_base64);
}

// The line beside the title (design R3/R6): under a chain name the label
// "chain name" and the short ID; a profile name only as "profile name …";
// an unverified claim only when nothing better is known. null = nothing.
function nameHint(fp, { claimed, prefix = 'claims the name ' } = {}) {
  const n = namesOf(fp, claimed);
  const parts = [];
  if (n.verified) parts.push(el('span', { className: 'name-kind', text: 'chain name' }), ` ${n.id}`);
  if (n.profile) parts.push(parts.length ? ' · profile name ' : 'profile name ', untrusted(n.profile, undefined, { name: true }));
  if (n.claimed) parts.push(prefix, untrusted(n.claimed, undefined, { name: true }));
  return parts.length ? el('span', { className: 'contact-claim' }, ...parts) : null;
}

// Line icons (stroke only, styled by messenger.css .nc-icon), built with
// createElementNS: no markup is parsed.
const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  back: ['M15 5l-7 7 7 7'],
  chevron: ['M9 6l6 6-6 6'],
  send: ['M4 12L20 4l-5 16-3-7z', 'M12 13l8-9'],
  userPlus: ['M3 19c0-3 2.5-5 6-5s6 2 6 5', 'M9 11a3.5 3.5 0 1 0 0-7a3.5 3.5 0 1 0 0 7z', 'M19 8v6', 'M16 11h6'],
  requests: ['M4 8h13', 'M14 5l3 3-3 3', 'M20 16H7', 'M10 13l-3 3 3 3'],
  id: ['M4 6h16v12H4z', 'M9 12a2 2 0 1 0 0-4a2 2 0 1 0 0 4z', 'M6 16c.5-1.5 1.5-2.2 3-2.2s2.5.7 3 2.2', 'M14 10h3', 'M14 13h3']
};
function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  for (const [attr, value] of Object.entries({ viewBox: '0 0 24 24', width: '20', height: '20', class: 'nc-icon', 'aria-hidden': 'true', focusable: 'false' })) svg.setAttribute(attr, value);
  for (const d of ICONS[name]) { const path = document.createElementNS(SVG_NS, 'path'); path.setAttribute('d', d); svg.append(path); }
  return svg;
}
function iconButton(name, label, onClick, className = '') {
  const node = button('', onClick, `nc-icon-button ${className}`.trim());
  node.setAttribute('aria-label', label);
  node.title = label;
  node.append(icon(name));
  return node;
}

// A screen's top bar (design_system/navigation/dna_app_bar.dart): an
// optional back arrow, the title, actions on the right.
function appBar(title, { back = false, actions = [] } = {}) {
  const heading = el('h2', { className: 'nc-bar-title', text: title });
  heading.tabIndex = -1;
  const bar = el('div', { className: 'nc-bar' }, back ? backButton() : null, heading, actions.length ? el('div', { className: 'nc-bar-actions' }, ...actions) : null);
  return { bar, heading };
}

function backButton() { return iconButton('back', 'Back', goBack, 'nc-back'); }

// Back from a screen opened on its own: Messages returns to Chats; the host
// (the Nodus Connect app) may then show the tab the screen was opened from.
function goBack() {
  const from = screen, fp = selectedFp;
  const handled = host.onBack?.(from);
  show('list');
  if (handled) return;
  const row = fp && [...ui.contactList.querySelectorAll('.contact-row')].find(node => node.dataset.fp === fp);
  (row || ui.listHeading).focus({ preventScroll: true });
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
// root: an empty element of the host page. Every host callback is optional:
//   onUnread(n)      the total of unread messages (a navigation badge);
//   onRequests(n)    contact requests waiting for an answer;
//   onIdentity(fp, name, avatarBase64)   the own ID while Messages is open,
//                    else null; with the own verified name and picture ('' if none);
//   onScreen(name)   the screen shown changed ('list', 'conversation',
//                    'contacts', 'profile');
//   onBack(from)     Back was pressed on a screen opened on its own (called
//                    before Messages returns to Chats); a truthy return
//                    means the host moved the user elsewhere (focus is its).
export function mountMessages(root, options = {}) {
  host = options;
  const u = {};
  u.stateTitle = el('h3', { text: 'Messages' });
  u.stateText = statusLine('hint');
  u.retry = button('Try again', () => {
    if (!core || !ownFp) return;
    const gen = generation;
    finishOpen(gen).catch(error => { if (gen === generation) closeMessages(explain(error, 'Messages could not connect to the network right now. Try again in a minute.'), { retry: true }); });
  }, 'secondary small');
  u.stateView = el('div', { className: 'messenger-view messenger-state' }, el('span', { className: 'messenger-state-mark' }), u.stateTitle, u.stateText, u.retry);
  u.stateView.querySelector('.messenger-state-mark').setAttribute('aria-hidden', 'true');

  // Chats (messages_screen.dart): the bar with the requests and ID actions,
  // the filter chips, an entry while contact requests are waiting, the list,
  // and the add-contact button (contacts_screen.dart's floating button).
  u.requestCount = el('span', { className: 'count-badge nc-icon-badge' });
  u.requestsAction = iconButton('requests', 'Contact requests', () => show('contacts', { tab: 'requests' }));
  u.requestsAction.append(u.requestCount);
  u.profileAction = iconButton('id', 'Your ID & profile', () => show('profile'));
  const chats = appBar('Chats', { actions: [u.requestsAction, u.profileAction] });
  u.listHeading = chats.heading;
  const chip = (name, label) => {
    const node = button('', () => { filter = name; render(); }, 'nc-chip');
    node.dataset.filter = name;
    node.append(el('span', { text: label }));
    return node;
  };
  u.chipAll = chip('all', 'All'); u.chipUnread = chip('unread', 'Unread'); u.chipChats = chip('chats', 'Chats');
  u.chipUnreadCount = el('span', { className: 'count-badge' }); u.chipUnread.append(u.chipUnreadCount);
  u.chipChatsCount = el('span', { className: 'count-badge' }); u.chipChats.append(u.chipChatsCount);
  u.chipRow = setAttrs(el('div', { className: 'nc-chips' }, u.chipAll, u.chipUnread, u.chipChats), { role: 'group', 'aria-label': 'Show' });
  u.requestsBannerText = el('span', { className: 'nc-banner-text' });
  u.requestsBanner = button('', () => show('contacts', { tab: 'requests' }), 'nc-banner');
  u.requestsBanner.append(icon('requests'), u.requestsBannerText, icon('chevron'));
  u.contactList = setAttrs(el('ul', { className: 'contact-list' }), { 'aria-label': 'Conversations' });
  u.chatsBody = el('div', { className: 'nc-chats-body' }, u.chipRow, u.requestsBanner, u.contactList);
  u.sync = el('p', { className: 'messenger-sync' });
  u.sync.setAttribute('role', 'status');
  u.fab = iconButton('userPlus', 'Add contact', () => openAdd(), 'nc-fab');
  u.chats = setAttrs(el('section', { className: 'messenger-chats' }, chats.bar, u.stateView, u.chatsBody, u.sync, u.fab), { 'aria-label': 'Chats' });

  // Next to the list on a wide screen while no conversation is open.
  u.emptyTitle = el('h3');
  u.emptyText = el('p', { className: 'hint' });
  u.emptyCopyStatus = statusLine();
  u.emptyActions = el('div', { className: 'messenger-empty-actions' },
    button('Add contact', () => openAdd(), 'small'),
    button('Copy your ID', () => void copyOwnId(u.emptyCopyStatus), 'secondary small'));
  u.emptyView = el('div', { className: 'messenger-view messenger-empty' }, el('span', { className: 'messenger-empty-mark', text: '✉' }), u.emptyTitle, u.emptyText, u.emptyActions, u.emptyCopyStatus);
  u.emptyView.querySelector('.messenger-empty-mark').setAttribute('aria-hidden', 'true');

  // Conversation (chat_screen.dart): back, the contact's mark and ID, the
  // messages, the composer pinned at the bottom.
  u.convAvatar = el('span');
  u.convTitle = el('h2', { className: 'nc-bar-title' });
  u.convTitle.tabIndex = -1;
  u.convClaim = el('span', { className: 'contact-claim' });
  u.convHead = el('div', { className: 'nc-bar conversation-head' }, backButton(), u.convAvatar, el('div', { className: 'conversation-title' }, u.convTitle, u.convClaim));
  u.convNote = el('p', { className: 'notice conversation-note' });
  u.messageList = setAttrs(el('ol', { className: 'message-list' }), { 'aria-label': 'Messages', 'aria-live': 'polite' });
  u.composer = input('textarea', { id: 'nc-send-text', rows: '1', maxlength: String(TEXT_MAX), placeholder: 'Write a message', 'aria-label': 'Message', autocomplete: 'off' });
  u.sendButton = el('button', { className: 'composer-send' }); u.sendButton.type = 'submit';
  u.sendButton.setAttribute('aria-label', 'Send'); u.sendButton.title = 'Send';
  u.sendButton.append(icon('send'));
  u.counter = el('small', { className: 'composer-counter' });
  u.sendStatus = statusLine('hint composer-status');
  u.sendForm = el('form', { className: 'composer' }, el('div', { className: 'composer-row' }, u.composer, u.sendButton), el('div', { className: 'composer-foot' }, el('small', { className: 'composer-hint', text: 'Enter to send · Shift+Enter for a new line' }), u.counter), u.sendStatus);
  u.sendForm.id = 'nc-send-form';
  u.notReady = el('p', { className: 'hint composer-closed', text: 'Messaging with this contact is not ready yet. It is checked again automatically.' });
  u.conversationView = el('div', { className: 'messenger-view messenger-conversation' }, u.convHead, u.convNote, u.messageList, u.sendForm, u.notReady);
  u.pane = el('div', { className: 'messenger-pane' }, u.emptyView, u.conversationView);

  // Add contact (add_contact_dialog.dart): a modal dialog.
  u.addHeading = el('h2', { text: 'Add a contact' });
  u.addHeading.id = 'nc-add-title';
  u.addId = input('input', { id: 'nc-add-id', type: 'text', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', maxlength: '256', required: '' });
  u.addNote = input('input', { id: 'nc-add-note', type: 'text', maxlength: '200', autocomplete: 'off' });
  u.addStatus = statusLine();
  const addSubmit = el('button', { text: 'Send request' }); addSubmit.type = 'submit';
  u.addForm = el('form', { className: 'messenger-form' },
    ...field('nc-add-id', 'Their ID', u.addId),
    el('p', { className: 'hint', text: 'An ID is 128 characters, letters a–f and digits. Ask them to copy it from “Your ID & profile”.' }),
    ...field('nc-add-note', 'Note (optional, they see it with your request)', u.addNote),
    u.addStatus,
    el('div', { className: 'nc-dialog-actions' }, button('Close', () => u.addDialog.close(), 'secondary'), addSubmit));
  u.addForm.id = 'nc-add-form';
  u.addDialog = setAttrs(el('dialog', { className: 'nc-dialog' }, u.addHeading, u.addForm), { 'aria-labelledby': 'nc-add-title' });
  u.addDialog.id = 'nc-add-dialog';

  // Contacts (contacts_hub_screen.dart): Contacts and Requests tabs.
  const hub = appBar('Contacts', { back: true, actions: [iconButton('userPlus', 'Add contact', () => openAdd())] });
  u.hubHeading = hub.heading;
  const hubTabButton = (name, label) => {
    const node = button(label, () => { hubTab = name; if (name === 'requests') ui.requestsStatus.textContent = ''; render(); }, 'nc-tab');
    node.dataset.tab = name;
    return node;
  };
  u.hubTabContacts = hubTabButton('contacts', 'Contacts');
  u.hubTabRequests = hubTabButton('requests', 'Requests');
  u.hubRequestCount = el('span', { className: 'count-badge' }); u.hubTabRequests.append(u.hubRequestCount);
  u.hubTabs = setAttrs(el('div', { className: 'nc-tabs' }, u.hubTabContacts, u.hubTabRequests), { role: 'group', 'aria-label': 'Contacts sections' });
  u.hubList = setAttrs(el('ul', { className: 'contact-list' }), { 'aria-label': 'Contacts' });
  u.hubContacts = el('div', { className: 'nc-scroll' }, u.hubList);
  u.requestList = el('ul', { className: 'request-list' });
  u.outgoingList = el('ul', { className: 'request-list' });
  u.requestsStatus = statusLine();
  u.hubRequests = el('div', { className: 'nc-scroll nc-padded' },
    el('h3', { text: 'Waiting for you' }), u.requestList,
    el('h3', { text: 'Sent by you' }), u.outgoingList, u.requestsStatus);
  u.contactsView = setAttrs(el('section', { className: 'messenger-screen messenger-contacts' }, hub.bar, u.hubTabs, u.hubContacts, u.hubRequests), { 'aria-label': 'Contacts' });

  // Your ID & profile.
  const prof = appBar('Your ID & profile', { back: true });
  u.profileHeading = prof.heading;
  u.ownId = el('code', { className: 'own-id' });
  u.ownId.id = 'nc-own-id';
  u.copyStatus = statusLine();
  u.profileName = el('p', { className: 'hint' });
  u.bio = input('textarea', { id: 'nc-bio', rows: '3' });
  u.location = input('input', { id: 'nc-location', type: 'text', autocomplete: 'off' });
  u.website = input('input', { id: 'nc-website', type: 'url', autocomplete: 'off' });
  u.profileStatus = statusLine();
  // Profile picture: chosen here, made into the app's 128x128 JPEG.
  u.ownAvatar = setAttrs(el('span', { className: 'contact-avatar avatar-large' }), { 'aria-hidden': 'true' });
  u.avatarFile = input('input', { id: 'nc-avatar-file', type: 'file', accept: 'image/jpeg,image/png,image/webp' });
  u.avatarFile.hidden = true;
  u.avatarChange = button('Change picture', () => u.avatarFile.click(), 'secondary small');
  u.avatarRemove = button('Remove picture', () => void saveAvatar(''), 'secondary small');
  u.avatarStatus = statusLine();
  u.avatarBox = el('div', { className: 'own-avatar-box' }, u.ownAvatar,
    el('div', { className: 'own-avatar-actions' }, u.avatarChange, u.avatarRemove, u.avatarFile), u.avatarStatus);
  const profileSubmit = el('button', { text: 'Save profile' }); profileSubmit.type = 'submit';
  u.profileForm = el('form', { className: 'messenger-form' },
    ...field('nc-bio', 'About you', u.bio), ...field('nc-location', 'Location', u.location),
    ...field('nc-website', 'Website (https:// only)', u.website), profileSubmit, u.profileStatus);
  u.profileForm.id = 'nc-profile-form';
  u.memoryNote = el('p', { className: 'notice', text: 'This wallet is not saved on this device: messages are not kept after you lock, and senders are not told their messages arrived. Save the wallet in Device & settings, then lock and open it again to keep messages.' });
  u.memoryNote.hidden = true;
  u.erase = button('Delete message history on this device', () => void erase(), 'secondary small messenger-erase');
  u.erase.hidden = true;
  u.profileView = setAttrs(el('section', { className: 'messenger-screen messenger-profile' }, prof.bar,
    el('div', { className: 'nc-scroll nc-padded' },
      el('div', { className: 'own-id-box' }, el('span', { className: 'own-id-label', text: 'Your ID — share it so others can add you' }), u.ownId,
        button('Copy your ID', () => void copyOwnId(u.copyStatus), 'secondary small'), u.copyStatus),
      el('h3', { text: 'Your profile' }),
      el('p', { className: 'hint', text: 'Everyone can read your profile, including your picture. A name cannot be chosen here yet.' }),
      u.avatarBox, u.profileName, u.profileForm, u.memoryNote, u.erase)), { 'aria-label': 'Your ID & profile' });

  // One screen at a time on a narrow screen; on a wide one Chats stays next
  // to the open conversation (messenger.css, data-screen).
  u.layout = el('div', { className: 'messenger' }, u.chats, u.pane, u.contactsView, u.profileView, u.addDialog);
  root.replaceChildren(u.layout);
  ui = u;

  u.addForm.onsubmit = event => void addContact(event);
  u.sendForm.onsubmit = event => void send(event);
  u.profileForm.onsubmit = event => void saveProfile(event);
  u.avatarFile.onchange = () => {
    const file = u.avatarFile.files?.[0];
    u.avatarFile.value = '';
    if (file) void pickAvatar(file);
  };
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

// Navigation inside Messages. While Messages is not open only Chats (with
// its status) is shown; every change is handed to host.onScreen (render).
function show(next, { tab } = {}) {
  if (!ui) return;
  if (!isOpen()) next = 'list';
  if (next !== 'conversation') selectedFp = undefined;
  if (next === 'contacts' && tab) { hubTab = tab; if (tab === 'requests') ui.requestsStatus.textContent = ''; }
  screen = next;
  render();
  const focus = { contacts: ui.hubHeading, profile: ui.profileHeading }[next];
  focus?.focus({ preventScroll: true });
}

// The host's navigation (the Nodus Connect app's tabs and More menu):
// 'chats', 'contacts', 'requests', 'profile' or 'add' (the add-contact dialog).
export function messagesNavigate(target) {
  if (target === 'add') openAdd();
  else if (target === 'contacts' || target === 'requests') show('contacts', { tab: target });
  else if (target === 'profile') show('profile');
  else show('list');
}

function openAdd() {
  if (!ui) return;
  if (!isOpen()) { show('list'); return; }
  ui.addStatus.textContent = '';
  if (!ui.addDialog.open) ui.addDialog.showModal();
  ui.addId.focus();
}

function selectContact(fp) {
  selectedFp = fp; screen = 'conversation';
  ui.sendStatus.textContent = '';
  markRead(fp);
  render({ scroll: true });
  (contactOf(fp)?.salt ? ui.composer : ui.convTitle).focus({ preventScroll: true });
}

function setCount(node, count) {
  node.textContent = count ? (count > 99 ? '99+' : String(count)) : '';
  node.hidden = !count;
}

function render({ scroll = false } = {}) {
  if (!ui) return;
  const open = isOpen();
  // Closed: Chats only. A conversation whose contact is gone: back to Chats.
  if ((!open && screen !== 'list') || (screen === 'conversation' && !(selectedFp && contactOf(selectedFp)))) { screen = 'list'; selectedFp = undefined; }
  // data-screen drives the layout (messenger.css); data-open the closed state.
  ui.layout.dataset.screen = screen;
  ui.layout.dataset.open = String(open);
  ui.stateView.hidden = open;
  ui.chatsBody.hidden = !open;
  ui.fab.hidden = !open;
  ui.emptyView.hidden = screen !== 'list';
  ui.conversationView.hidden = screen !== 'conversation';
  ui.contactsView.hidden = screen !== 'contacts';
  ui.profileView.hidden = screen !== 'profile';
  for (const control of [ui.requestsAction, ui.profileAction]) control.disabled = !open;
  if (open && screen === 'conversation') markRead(selectedFp);
  const unread = open ? state.contacts.reduce((sum, c) => sum + unreadCount(c.fp), 0) : 0;
  const waiting = open ? requests.length : 0;
  renderCounts(unread, waiting);
  renderEmpty(open);
  if (open) {
    renderChats();
    if (screen === 'contacts') renderContacts();
    if (screen === 'conversation') renderConversation(scroll);
  }
  host.onUnread?.(unread);
  host.onRequests?.(waiting);
  const id = open ? ownFp : null;
  // The own CHAIN name (HF-4, dnac_name_of) travels with the ID; the
  // profile name is shown only on the profile screen, labelled.
  const ownName = open ? chainNameOf(ownFp) : '';
  const ownAvatar = open && typeof ownProfile?.avatar_base64 === 'string' ? ownProfile.avatar_base64 : '';
  const idKey = id ? `${id}|${ownName}|${ownAvatar}` : null;
  if (idKey !== notifiedId) { notifiedId = idKey; host.onIdentity?.(id, ownName, ownAvatar); }
  if (screen !== notifiedScreen) { notifiedScreen = screen; host.onScreen?.(screen); }
}

function renderCounts(unread, waiting) {
  setCount(ui.requestCount, waiting); setCount(ui.hubRequestCount, waiting);
  setCount(ui.chipUnreadCount, unread); setCount(ui.chipChatsCount, unread);
  ui.requestsAction.setAttribute('aria-label', waiting ? `Contact requests, ${waiting} waiting` : 'Contact requests');
  ui.requestsBanner.hidden = !waiting;
  ui.requestsBannerText.textContent = waiting === 1 ? '1 contact request is waiting for you' : `${waiting} contact requests are waiting for you`;
}

// Chats rows (contacts_screen.dart _ContactTile): the ID mark, the short ID
// in bold (a claimed name only as "claims the name …"), the last message;
// on the right its time and the unread count; a chevron.
function renderChats() {
  for (const node of [ui.chipAll, ui.chipUnread, ui.chipChats]) node.setAttribute('aria-pressed', String(node.dataset.filter === filter));
  if (!state.contacts.length) {
    ui.contactList.replaceChildren(el('li', { className: 'contact-empty', text: 'No contacts yet. Add one with their ID using the add-contact button.' }));
    return;
  }
  // Most recent conversation first (local order), then contacts without
  // messages in list order; ties keep the list order (stable sort).
  const ordered = state.contacts.map((c, index) => ({ c, index, last: lastMessage(c.fp) }))
    .sort((a, b) => (a.last && b.last ? compareLocal(b.last, a.last) : a.last ? -1 : b.last ? 1 : 0) || a.index - b.index);
  // 'chats' shows the same list as 'all' (the app's Chats chip without groups).
  const shown = filter === 'unread' ? ordered.filter(({ c }) => unreadCount(c.fp) > 0) : ordered;
  if (!shown.length) {
    ui.contactList.replaceChildren(el('li', { className: 'contact-empty', text: 'All caught up. No unread messages.' }));
    return;
  }
  ui.contactList.replaceChildren(...shown.map(({ c, last }) => {
    const unread = unreadCount(c.fp);
    const row = el('button', { className: `contact-row${unread ? ' has-unread' : ''}` });
    row.type = 'button';
    row.dataset.fp = c.fp;
    row.setAttribute('aria-current', String(screen === 'conversation' && c.fp === selectedFp));
    const preview = el('span', { className: 'contact-preview' });
    const label = last ? payloadPreview(last.text) : null;
    if (last && label) preview.append(last.dir === 'out' ? 'You: ' : '', label);
    else if (last) preview.append(last.dir === 'out' ? 'You: ' : '', untrusted(last.text));
    else preview.textContent = c.salt ? 'No messages yet' : 'Messaging is not ready yet';
    const side = el('span', { className: 'contact-side' });
    if (last) { const when = el('time', { text: shortWhen(last.at) }); when.dateTime = new Date(last.at).toISOString(); side.append(when); }
    if (unread) side.append(setAttrs(el('span', { className: 'count-badge', text: String(unread) }), { 'aria-label': `${unread} new` }));
    row.append(avatar(c.fp), el('span', { className: 'contact-main' }, el('span', { className: 'contact-name' }, nameTitle(c.fp), nameHint(c.fp)), preview), side, icon('chevron'));
    row.onclick = () => selectContact(c.fp);
    return el('li', {}, row);
  }));
}

// Contacts screen: the contacts in list order, or the requests.
function renderContacts() {
  for (const node of [ui.hubTabContacts, ui.hubTabRequests]) node.setAttribute('aria-pressed', String(node.dataset.tab === hubTab));
  ui.hubContacts.hidden = hubTab !== 'contacts';
  ui.hubRequests.hidden = hubTab !== 'requests';
  if (hubTab === 'requests') { renderRequests(); return; }
  ui.hubList.replaceChildren(...(state.contacts.length ? state.contacts.map(c => {
    const row = el('button', { className: 'contact-row' });
    row.type = 'button';
    const sub = el('span', { className: 'contact-preview', text: c.salt ? 'Open conversation' : 'Messaging is not ready yet' });
    row.append(avatar(c.fp), el('span', { className: 'contact-main' }, el('span', { className: 'contact-name' }, nameTitle(c.fp), nameHint(c.fp)), sub), icon('chevron'));
    row.onclick = () => selectContact(c.fp);
    return el('li', {}, row);
  }) : [el('li', { className: 'contact-empty', text: 'No contacts yet. Add one with their ID.' })]));
}

function renderEmpty(open) {
  ui.emptyActions.hidden = !open;
  if (!open) { ui.emptyTitle.textContent = 'Messages'; ui.emptyText.textContent = 'Your conversations open here.'; return; }
  const none = state.contacts.length === 0;
  ui.emptyTitle.textContent = none ? 'No contacts yet' : 'Choose a conversation';
  ui.emptyText.textContent = none
    ? 'Add a contact with their ID — a 128-character code they copy from “Your ID & profile”. Share your ID the same way so others can add you. Once they accept, you can write to each other.'
    : 'Pick a conversation from the list, or add a new contact with their ID.';
}

function renderRequests() {
  ui.requestList.replaceChildren(...(requests.length ? requests.map(request => el('li', { className: 'request-row' },
    avatar(request.sender),
    el('div', { className: 'request-main' },
      el('span', { className: 'contact-name' }, el('span', { className: 'request-label', text: 'Not a contact' }), nameTitle(request.sender)),
      nameHint(request.sender, { claimed: request.claimed_name, prefix: 'says their name is ' }),
      request.message ? el('p', { className: 'request-note' }, untrusted(request.message)) : null,
      el('div', { className: 'request-actions' }, button('Accept', () => void accept(request), 'small'), button('Decline', () => void decline(request), 'secondary small')))
  )) : [el('li', { className: 'contact-empty', text: 'No new requests.' })]));

  ui.outgoingList.replaceChildren(...(state.outgoing.length ? state.outgoing.map(o => el('li', { className: 'request-row' },
    avatar(o.fp),
    el('div', { className: 'request-main' },
      el('span', { className: 'contact-name' }, nameTitle(o.fp)),
      nameHint(o.fp),
      el('span', { className: 'contact-claim', text: 'waiting for them to accept' }),
      el('div', { className: 'request-actions' }, button('Withdraw', () => void withdraw(o.fp), 'secondary small')))
  )) : [el('li', { className: 'contact-empty', text: 'None.' })]));
}

function renderConversation(scroll) {
  const contact = contactOf(selectedFp);
  const list = ui.messageList;
  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
  ui.convAvatar.replaceWith(ui.convAvatar = avatar(contact.fp, ' conversation-avatar'));
  ui.convTitle.textContent = displayName(contact.fp);
  ui.convTitle.classList.toggle('chain-name', namesOf(contact.fp).verified);
  const claim = nameHint(contact.fp);
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
    // The message body lives only inside the bubble (§1.9); time and status
    // sit small at the bubble's foot (chat_screen.dart message bubble).
    // A shared-vault item (src/vaults/ui.js) is drawn as its card; any
    // other text as text.
    const card = payloadCard(m);
    items.push(el('li', { className: mine ? 'message message-out' : 'message message-in' },
      el('div', { className: 'message-bubble' }, card || el('div', { className: 'message-text' }, untrusted(m.text)), meta)));
  }
  if (!items.length) items.push(el('li', { className: 'message-none', text: contact.salt ? 'No messages yet. Say hello.' : 'No messages yet.' }));
  list.replaceChildren(...items);
  if (scroll || atBottom) list.scrollTop = list.scrollHeight;
}

function fillOwnAvatar() {
  const p = ownProfile || {};
  ui.ownAvatar.className = `contact-avatar avatar-large avatar-${parseInt(ownFp[0], 16) % 6}`;
  fillAvatar(ui.ownAvatar, initials(ownFp, chainNameOf(ownFp)), p.avatar_base64);
  ui.avatarRemove.hidden = !p.avatar_base64;
}

function fillProfile() {
  const p = ownProfile || {};
  ui.bio.value = p.bio || ''; ui.location.value = p.location || ''; ui.website.value = p.website || '';
  fillOwnAvatar();
  fillNameLine();
}

// The names line of "Your ID & profile" (also refreshed when the own chain
// name arrives, without touching the edit fields).
function fillNameLine() {
  const p = ownProfile || {};
  const line = ui.profileName;
  line.replaceChildren();
  // HF-4 (design R6): the chain name and the profile name are two different
  // things and are labelled as such.
  const chain = chainNameOf(ownFp);
  line.append(chain ? el('span', {}, 'Your chain name: ', el('strong', { className: 'chain-name', text: chain })) : 'You have no chain name.', el('br'));
  if (p.name) line.append('Your profile name (in the network directory, not on the chain): ', untrusted(p.name, undefined, { name: true }));
  else if (p.claimed_name) line.append('Name on your profile (not verified — its lookup record does not point to you): ', untrusted(p.claimed_name, undefined, { name: true }));
  else line.append('Your profile has no name.');
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

// A chosen picture made the way the app makes one
// (profile_editor_screen.dart:507-516): the centre square scaled to 128x128,
// JPEG at quality 0.8, stepping the quality down until the base64 fits
// AVATAR_UPLOAD_MAX_B64. Transparent parts become white (JPEG has no alpha).
const AVATAR_SIDE = 128, AVATAR_FILE_MAX = 20 * 1024 * 1024;
async function avatarFromFile(file) {
  if (file.size > AVATAR_FILE_MAX) throw new Error('That picture is too large. Choose one under 20 MB.');
  let bitmap;
  try { bitmap = await createImageBitmap(file); } catch { throw new Error('That file could not be read as a picture.'); }
  try {
    const side = Math.min(bitmap.width, bitmap.height);
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = AVATAR_SIDE;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, AVATAR_SIDE, AVATAR_SIDE);
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, AVATAR_SIDE, AVATAR_SIDE);
    for (const quality of [0.8, 0.7, 0.6, 0.5, 0.4]) {
      const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', quality));
      if (!blob) break;
      const bytes = new Uint8Array(await blob.arrayBuffer());
      let binary = '';
      for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      const b64 = btoa(binary);
      if (b64.length <= AVATAR_UPLOAD_MAX_B64) return b64;
    }
  } finally { bitmap.close(); }
  throw new Error('That picture could not be made small enough. Try another one.');
}

async function pickAvatar(file) {
  const gen = generation;
  ui.avatarStatus.textContent = 'Preparing the picture…';
  let b64;
  try { b64 = await avatarFromFile(file); }
  catch (error) { if (gen === generation) ui.avatarStatus.textContent = error.message; return; }
  if (gen === generation) await saveAvatar(b64);
}

// Writes only avatar_base64; the core keeps every other profile field as
// read from the network (nc_profile.c patch). '' removes the picture.
async function saveAvatar(b64) {
  const gen = generation;
  if (profileTaken || ui.avatarChange.disabled) return;
  ui.avatarChange.disabled = ui.avatarRemove.disabled = true;
  try {
    const patch = avatarPatch(b64);
    ui.avatarStatus.textContent = 'Saving…';
    const result = await core.profileUpdate(patch);
    if (gen !== generation) return;
    ui.avatarStatus.textContent = result.status === 'published' ? (b64 ? 'Your picture was saved.' : 'Your picture was removed.') : profileStatusText(result.status);
    if (result.status === 'published') { ownProfile = { ...(ownProfile || {}), ...patch }; fillOwnAvatar(); render(); }
    if (result.status === 'taken') profileTaken = true;
  } catch { if (gen === generation) ui.avatarStatus.textContent = 'Saving failed. Try again later.'; }
  finally { if (gen === generation) ui.avatarChange.disabled = ui.avatarRemove.disabled = false; }
}

async function erase() {
  if (!store?.persistent) return;
  if (!eraseArmed) { eraseArmed = true; ui.erase.textContent = 'Confirm: delete all messages on this device'; return; }
  const target = store;
  try { await target.erase(); closeMessages('Message history deleted from this device. Lock and open your wallet again to use Messages.'); }
  catch (error) { closeMessages(error.message); }
}

// ── shared vaults' use of Messages (src/vaults/ui.js) ──────────────────
// Vault items travel as 1:1 messages to the vault's members (a JSON text
// whose "type" is "nodus_vault": nc_plaintext_is_chat counts it as chat
// text, so it is stored, acknowledged and returned like any message; the
// frozen DNA Connect app shows its raw text). What this file adds: sending
// such a text programmatically, the list of stored messages, one kept
// record per vault (state.vaults, store.js), and drawing a vault item as a
// card (the vault module's renderer) instead of its raw text.
// Larger than the composer's TEXT_MAX: a vault item carries up to a 7-key
// vault code (36 KiB of hex); bounded below the 64 KiB a stored record may
// hold (store.js PLAINTEXT_MAX) with room for the message's own fields.
export const PAYLOAD_TEXT_MAX = 60000;
let payloadView = null;                  // { preview(text), card(message) } | null
const vaultListeners = new Set();
function payloadPreview(text) {
  try { return payloadView?.preview(text) || null; } catch { return null; }
}
function payloadCard(message) {
  try { return payloadView?.card(message) || null; } catch { return null; }
}
function notifyVaultHost() {
  for (const listener of vaultListeners) { try { listener(); } catch { /* the others still run */ } }
}
const VAULT_ADDRESS = /^[0-9a-f]{128}$/;

async function sendPayload(fp, text) {
  if (!isOpen()) throw new Error('Messages is not open.');
  const gen = generation, contact = contactOf(fp);
  if (!contact) throw new Error('This person is not in your contacts.');
  if (!contact.salt) throw new Error('Messaging with this contact is not ready yet.');
  if (typeof text !== 'string' || !text || new TextEncoder().encode(text).length > PAYLOAD_TEXT_MAX) throw new Error('This item is too large to send.');
  const message = { seq: takeSeq(), fp, dir: 'out', text, ts: nowSeconds(), at: Date.now() };
  await persist([message]);
  if (gen !== generation) throw new Error('Messages is not open.');
  messages.push(message); unpublished.add(fp);
  render();
  notifyVaultHost();
  // Not published now: the 30-second check publishes it (unpublished).
  try { await publishOutbox(contact, gen); } catch { /* retried by sync */ }
  if (gen === generation) render();
}

async function keepVault(address, value) {
  if (!isOpen()) throw new Error('Messages is not open.');
  if (typeof address !== 'string' || !VAULT_ADDRESS.test(address) || !value || typeof value !== 'object') throw new Error('Invalid vault.');
  const before = state.vaults[address];
  const id = before?.id || `v${takeSeq().padStart(20, '0')}`;
  state.vaults[address] = { id, at: nowSeconds() };
  try {
    await store.save(state, [], [], [{ id, address, value }]);
  } catch (error) {
    if (before) state.vaults[address] = before; else delete state.vaults[address];
    throw error;
  }
  vaultRecs.set(address, { id, value });
}

async function dropVault(address) {
  if (!isOpen() || !state.vaults[address]) return;
  const before = state.vaults[address];
  delete state.vaults[address];
  try { await persist(); } catch (error) { state.vaults[address] = before; throw error; }
  vaultRecs.delete(address);
}

export const vaultHost = {
  isOpen: () => isOpen(),
  ownFp: () => (isOpen() ? ownFp : undefined),
  // true: a saved wallet (records survive a reload); false: memory only
  persistent: () => isOpen() && !!store?.persistent,
  contacts: () => (isOpen() ? state.contacts.map(c => ({ fp: c.fp, ready: !!c.salt, name: displayName(c.fp), verified: namesOf(c.fp).verified })) : []),
  name: fp => (isOpen() && typeof fp === 'string' && VAULT_ADDRESS.test(fp) ? displayName(fp) : ''),
  messages: () => (isOpen() ? messages.map(m => ({ fp: m.fp, dir: m.dir, text: m.text, at: m.at, seq: String(m.seq) })) : []),
  send: sendPayload,
  vaults: () => (isOpen() ? [...vaultRecs.entries()].map(([address, r]) => ({ address, value: r.value })) : []),
  keepVault,
  dropVault,
  setPayloadView(view) { payloadView = view && typeof view.preview === 'function' && typeof view.card === 'function' ? view : null; if (isOpen()) render(); },
  onChange(listener) { vaultListeners.add(listener); return () => vaultListeners.delete(listener); },
  openConversation(fp) { if (isOpen() && contactOf(fp)) selectContact(fp); }
};

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
