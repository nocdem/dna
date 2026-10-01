// Nodus Connect — the Messages preview page (/preview/, package NC-4c of
// docs/plans/2026-09-24-web-connect-design.md rev 5).
//
// Governing records: docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md
// (first stage, Ek 2: contact list, send/accept contact requests, 1:1 text
// messages, own profile edit — no groups, media or calls; Q1: only words
// generated in this session are "fresh"; S8: history store = vault id) and
// 2026-09-30-connect-history-at-rest.md rev 2 (src/connect/store.js).
//
// One page = one module = one session (NC-4b): the page creates the wallet's
// own NODUS client (src/nodus/client.js createNodusClient with
// src/nodus/send-module.js nodusSendModuleFactory — the module that also
// carries the Messages exports), unlocks it with the signing seed and the
// locally derived address exactly as src/app.js startNodusSend does, and
// builds the Messages core on it (src/connect/core.js createNodusConnectCore
// ({ nodus })). The client keeps the session alive itself (its tick).
//
// Lifecycle (§1.8): the page opens only while this tab holds the wallet's
// single-tab Web Lock `nodus.wallet.session` (src/app.js pattern); 10 minutes
// without input, a manual Lock, `pagehide`, a change of the saved wallet, or
// the client leaving 'ready' locks it. Lock order: timers stop ->
// core.lock() (Messages keys wiped, nc_lock) -> client.lock() (queue stops,
// cancel, WebSocket closed, module memory zeroed, instance released) ->
// history store closed -> in-page data dropped -> THEN the Web Lock is
// released.
//
// Network calls: each is awaited before the next one is queued (design §6.4
// F7), so a wallet operation queued meanwhile waits at most one step.
// An error text coming from the core is never shown: it can carry technical
// terms; the page shows its own plain words.
import { Mnemonic, randomBytes } from 'ethers';
import { VAULT_KEY, decryptVault } from '../../vault.js';
import { normalizePhrase, validateNodusPhrase } from '../../recovery.js';
import { nodusSendModuleFactory } from '../../nodus/send-module.js';
import { createNodusClient } from '../../nodus/client.js';
import { deriveNodusAddress, nodusSigningSeed } from '../../nodus/derive.js';
import { createNodusConnectCore, acceptanceMayAutoApprove } from '../core.js';
import { openHistoryStore, memoryHistoryStore, StorageError } from '../store.js';
import {
  parseContactId, shortId, profilePatch, profileStatusText, contactListStatusText, senderClockLabel,
  recentDays, pendingOutbox, compareLocal, receivedKey,
  publishedSeqs, markPublished, markDelivered, ackToSend, messageStatus
} from './text.js';
import { el, untrusted, button, website } from './dom.js';

const $ = id => document.getElementById(id);
const IDLE_MS = 10 * 60 * 1000;          // src/app.js idle lock
const SYNC_MS = 30000;                   // how often requests and messages are checked
const HEX128 = /^[0-9a-f]{128}$/;
const SCREENS = ['nc-start', 'nc-unlock-form', 'nc-words-form', 'nc-create-form', 'nc-closed', 'nc-open'];

// ── session state (all dropped by lock) ────────────────────────────────
let nodus, core, store, state, messages = [], ownFp, ownProfile, fresh = false, vaultId = null;
let generation = 0, sessionRelease, syncTimer, idleTimer, idleDeadline = 0, syncing = false;
let requests = [], selectedFp, newPhraseText, eraseArmed = false, profileTaken = false;
const profiles = new Map();              // fp -> verified profile, this session
const received = new Set();              // receivedKey of every stored incoming message
const unpublished = new Set();           // contacts whose pending set must be (re)published
const saltChecked = new Set();           // contacts whose salt was reconciled this session
const dropped = new Map();               // fp -> messages that did not verify, this session
const others = new Map();                // fp -> authentic items that are not text (reactions, calls, …), last check

function status(text) { $('nc-status').textContent = text; }
function show(id) { for (const screen of SCREENS) $(screen).hidden = screen !== id; }
function isOpen() { return !!core && !!state; }

// ── single-tab Web Lock (decision 2026-09-23-web-wallet-single-tab) ────
function acquireSession() {
  if (sessionRelease) return Promise.resolve(true);
  if (!navigator.locks) return Promise.reject(new Error('This browser cannot keep Messages open in only one tab. Use a browser with Web Locks support.'));
  return new Promise((resolve, reject) => {
    let mine;
    navigator.locks.request('nodus.wallet.session', { ifAvailable: true }, held => {
      if (!held) { resolve(false); return undefined; }
      return new Promise(release => { mine = sessionRelease = release; resolve(true); });
    }).catch(error => {
      reject(error);
      // A hold this tab still has ends in a rejection only when another tab took it.
      if (mine && sessionRelease === mine) { sessionRelease = undefined; lock('Your wallet was opened in another tab. Messages was locked.'); }
    });
  });
}
function releaseSession() { const release = sessionRelease; sessionRelease = undefined; release?.(); }

// ── lock ───────────────────────────────────────────────────────────────
function lock(reason = 'Messages locked.') {
  generation++;
  clearInterval(syncTimer); clearTimeout(idleTimer);
  syncTimer = idleTimer = undefined; idleDeadline = 0; syncing = false;
  const c = core, client = nodus; core = undefined; nodus = undefined;
  try { c?.lock(); } catch { /* the rest of the lock must still run */ }
  try { client?.lock(); } catch { /* same */ }
  try { store?.close(); } catch { /* same */ }
  store = undefined; state = undefined; messages = []; ownFp = undefined; ownProfile = undefined;
  fresh = false; vaultId = null; requests = []; selectedFp = undefined; newPhraseText = undefined;
  eraseArmed = false; profileTaken = false;
  for (const set of [profiles, received, unpublished, saltChecked, dropped, others]) set.clear();
  for (const id of ['nc-password', 'nc-words', 'nc-new-words-check', 'nc-add-id', 'nc-add-note', 'nc-send-text', 'nc-bio', 'nc-location', 'nc-website']) $(id).value = '';
  for (const id of ['nc-new-words', 'nc-requests', 'nc-outgoing', 'nc-contacts', 'nc-messages']) $(id).replaceChildren();
  for (const id of ['nc-own-id', 'nc-add-status', 'nc-send-status', 'nc-profile-status', 'nc-profile-name', 'nc-sync', 'nc-closed-reason', 'nc-conversation-title', 'nc-conversation-note']) $(id).textContent = '';
  $('nc-conversation').hidden = true; $('nc-lock').hidden = true;
  $('nc-erase').textContent = 'Delete message history on this device';
  releaseSession();
  showStart();
  status(reason);
}

function showStart() {
  $('nc-choose-saved').disabled = !localStorage.getItem(VAULT_KEY);
  show('nc-start');
}

// ── idle lock (as src/app.js) ──────────────────────────────────────────
function expireIdle() { if (idleDeadline && Date.now() >= idleDeadline) { lock('Messages locked after 10 minutes without activity.'); return true; } return false; }
function activity() {
  if (expireIdle()) return;
  clearTimeout(idleTimer);
  const sensitive = core || sessionRelease || !$('nc-words-form').hidden || !$('nc-create-form').hidden || !$('nc-unlock-form').hidden;
  if (sensitive) { idleDeadline = Date.now() + IDLE_MS; idleTimer = setTimeout(() => lock('Messages locked after 10 minutes without activity.'), IDLE_MS); }
}

// ── open ───────────────────────────────────────────────────────────────
class Closed extends Error {}

// getPhrase runs only after this tab holds the session lock. The caller has
// hidden every form (show(null)), so nothing can start a second open while
// this one runs; should one start anyway, the generation check below locks
// whatever this one built.
async function open(getPhrase, { persistent, isFresh }) {
  // A Messages core / client left from an earlier open is superseded: lock
  // it (core first, then client — the lock order of §1.8) before the slots
  // below are overwritten.
  const leftCore = core, leftClient = nodus;
  core = undefined; nodus = undefined;
  try { leftCore?.lock(); } catch { /* the client lock must still run */ }
  try { leftClient?.lock(); } catch { /* nothing left to do */ }
  const gen = ++generation;
  status('Opening Messages…');
  let words, seed, client, created;
  // A lock() or a newer open() ran meanwhile (generation moved): lock what
  // THIS open built unless it is still the page's current one (lock()
  // already locked those; a newer open owns its own). Both locks are
  // idempotent.
  const superseded = () => {
    if (gen === generation) return false;
    if (created && created !== core) { try { created.lock(); } catch { /* the client lock must still run */ } }
    if (client && client !== nodus) { try { client.lock(); } catch { /* nothing left to do */ } }
    return true;
  };
  try {
    if (!nodusSendModuleFactory) throw new Closed('Messages is not available in this build.');
    if (!await acquireSession()) { if (!superseded()) { status('Your wallet is open in another tab. Lock it there, then try again.'); showStart(); } return; }
    if (superseded()) return;
    const { phrase, id } = await getPhrase();
    if (superseded()) return;
    // The address is derived locally first; the module must derive the same
    // one (client.unlock refuses otherwise), as in src/app.js.
    const address = await deriveNodusAddress(phrase);
    if (superseded()) return;
    client = createNodusClient({
      factory: nodusSendModuleFactory,
      // Once Messages is open, a session that leaves 'ready' (error, or
      // locked from inside) ends it; before that, open()'s catch reports.
      onState: next => { if (client === nodus && ownFp && next !== 'ready') lock('The connection to the network was lost. Unlock again to continue.'); }
    });
    nodus = client;
    seed = nodusSigningSeed(phrase);
    await client.unlock({ seed, fingerprint: address });
    if (superseded()) return;
    created = createNodusConnectCore({ nodus: client });
    core = created;
    words = new TextEncoder().encode(phrase);
    const unlocked = await created.unlock({ words, fresh: isFresh });
    if (superseded()) return;
    ownFp = unlocked.fingerprint; fresh = unlocked.fresh === true; vaultId = persistent ? id : null;
    $('nc-lock').hidden = false;
    activity();
    await finishOpen(gen);
    superseded();
  } catch (error) {
    if (superseded()) return;
    // Before the identity is open (password, words, module or connection
    // failed): back to the start, nothing kept. After it: Messages stays
    // closed with a retry that re-reads without asking for the words again.
    if (!ownFp) { lock(error instanceof Closed || /password|phrase|words/i.test(error.message) ? error.message : 'Messages could not connect right now. Try again in a minute.'); return; }
    closed(explain(error, 'Messages could not connect to the network right now. Try again in a minute.'));
  } finally { words?.fill(0); seed?.fill(0); }
}

// Our own plain-words errors (Closed, a storage failure) are shown as they
// are; anything else gets the caller's plain-words fallback.
function explain(error, fallback) { return error instanceof Closed || error instanceof StorageError ? error.message : fallback; }

function closed(reason) { $('nc-closed-reason').textContent = reason; show('nc-closed'); status(''); }

// Messages opens only after the own profile was read (or, for a fresh
// account, created) and the history was loaded. Any failure keeps it closed
// and writes nothing (design §1.7, §7 Q1 (iii)).
async function finishOpen(gen) {
  status('Reading your account…');
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
    status('Loading your messages…');
    // A saved wallet keeps its history (S8); typed words and a new account
    // keep nothing.
    const opened = vaultId ? await openHistoryStore({ core, vaultId }) : memoryHistoryStore();
    if (gen !== generation) { opened.close(); return; }
    store = opened;
    state = structuredClone(store.state);
    messages = [...store.messages];
    for (const m of messages) if (m.dir === 'in') received.add(receivedKey(m.fp, { seq: m.remoteSeq, senderTs: m.senderTs, text: m.text }));
    const now = nowSeconds();
    for (const contact of state.contacts) if (pendingOutbox(messages, contact.fp, now).length) unpublished.add(contact.fp);
  }
  await mergeContactList(gen);
  if (gen !== generation) return;

  $('nc-own-id').textContent = ownFp;
  $('nc-memory-note').hidden = store.persistent;
  $('nc-erase').hidden = !store.persistent;
  fillProfile();
  showTab('contacts');
  show('nc-open');
  status('');
  render();
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
  if (note && gen === generation) $('nc-add-status').textContent = note;
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
    if (gen === generation) { $('nc-sync').textContent = `Last checked ${new Date().toLocaleTimeString()}.`; render(); }
  } catch (error) {
    if (gen === generation) $('nc-sync').textContent = explain(error, 'The network could not be reached. Checking again automatically.');
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
    const delivered = markDelivered(messages, fp, ackValue, publishedBefore);
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

// ── rendering ──────────────────────────────────────────────────────────
function claimedName(fp) {
  const name = profiles.get(fp)?.claimed_name;
  return name ? el('span', { className: 'nc-hint', text: ' · claims the name ' }, untrusted(name, undefined, { name: true })) : null;
}

function render() {
  if (!isOpen()) return;
  $('nc-requests').replaceChildren(...(requests.length ? requests.map(request => el('li', {},
    el('span', { className: 'nc-label', text: 'Not a contact' }), ' ', el('span', { text: shortId(request.sender) }),
    request.claimed_name ? el('span', { className: 'nc-hint', text: ' · says their name is ' }, untrusted(request.claimed_name, undefined, { name: true })) : null,
    request.message ? el('p', { className: 'nc-note' }, untrusted(request.message)) : null,
    el('div', { className: 'nc-actions' }, button('Accept', () => void accept(request)), button('Decline', () => void decline(request), 'nc-secondary'))
  )) : [el('li', { className: 'nc-hint', text: 'No new requests.' })]));

  $('nc-outgoing').replaceChildren(...(state.outgoing.length ? state.outgoing.map(o => el('li', {},
    el('span', { text: shortId(o.fp) }), el('span', { className: 'nc-hint', text: ' · waiting for them to accept' }), ' ',
    button('Withdraw', () => void withdraw(o.fp), 'nc-secondary')
  )) : [el('li', { className: 'nc-hint', text: 'None.' })]));

  $('nc-contacts').replaceChildren(...(state.contacts.length ? state.contacts.map(c => el('li', { className: c.fp === selectedFp ? 'nc-selected' : undefined },
    button(shortId(c.fp), () => selectContact(c.fp), 'nc-link'), claimedName(c.fp),
    c.salt ? null : el('span', { className: 'nc-hint', text: ' · messaging is not ready with this contact yet' })
  )) : [el('li', { className: 'nc-hint', text: 'No contacts yet. Add one by ID.' })]));

  renderConversation();
}

function renderConversation() {
  const contact = selectedFp && contactOf(selectedFp);
  $('nc-conversation').hidden = !contact;
  if (!contact) return;
  $('nc-conversation-title').replaceChildren(shortId(contact.fp), claimedName(contact.fp) || '');
  const lost = dropped.get(contact.fp), other = others.get(contact.fp);
  $('nc-conversation-note').textContent = [
    contact.salt ? '' : 'Messaging with this contact is not ready yet. It is checked again automatically.',
    lost ? 'Some messages from this contact could not be checked and are not shown.' : '',
    other ? 'This contact also sent items this page cannot show yet (for example reactions, pictures or calls).' : ''
  ].filter(Boolean).join(' ');
  $('nc-send-form').hidden = !contact.salt;
  $('nc-messages').replaceChildren(...messages.filter(m => m.fp === contact.fp).sort(compareLocal).map(m => {
    const mine = m.dir === 'out';
    const meta = mine
      ? `You · ${new Date(m.at).toLocaleString()} · ${messageStatus(m)}`
      : `Received ${new Date(m.at).toLocaleString()} · ${senderClockLabel(m.senderTs)}`;
    // The message body lives only inside the bubble (§1.9).
    return el('li', { className: mine ? 'nc-out' : 'nc-in' }, el('div', { className: 'nc-bubble' }, untrusted(m.text)), el('div', { className: 'nc-meta', text: meta }));
  }));
}

function selectContact(fp) { selectedFp = fp; $('nc-send-status').textContent = ''; render(); $('nc-send-text').focus(); }

function showTab(tab) {
  const contacts = tab === 'contacts';
  $('nc-contacts-panel').hidden = !contacts; $('nc-profile-panel').hidden = contacts;
  $('nc-tab-contacts').setAttribute('aria-pressed', String(contacts)); $('nc-tab-profile').setAttribute('aria-pressed', String(!contacts));
}

function fillProfile() {
  const p = ownProfile || {};
  $('nc-bio').value = p.bio || ''; $('nc-location').value = p.location || ''; $('nc-website').value = p.website || '';
  const line = $('nc-profile-name');
  line.replaceChildren();
  if (p.claimed_name) line.append('Name on your profile (not checked here): ', untrusted(p.claimed_name, undefined, { name: true }));
  else line.textContent = 'Your profile has no name.';
  if (p.website) { const link = website(p.website); if (link) line.append(el('br'), 'Website: ', link); }
}

// ── actions ────────────────────────────────────────────────────────────
async function accept(request) {
  const gen = generation;
  $('nc-add-status').textContent = 'Accepting…';
  try {
    if (!await ensureProfile(request.sender)) { if (gen === generation) $('nc-add-status').textContent = "This person's account could not be read right now. Try again in a minute."; return; }
    if (gen !== generation) return;
    await core.requestAccept(request.sender, request.salt || null);
    if (gen !== generation) return;
    addContactLocal(request.sender, request.salt || null);
    requests = requests.filter(r => r.sender !== request.sender);
    await persist();
    if (gen !== generation) return;
    $('nc-add-status').textContent = 'Contact added.';
    render();
    await publishContacts(gen);
  } catch (error) { if (gen === generation) $('nc-add-status').textContent = explain(error, 'Accepting failed. Try again in a minute.'); }
}

async function decline(request) {
  // Local only: the request is hidden on this device and expires on the network.
  state.declined.push(request.sender);
  requests = requests.filter(r => r.sender !== request.sender);
  render();
  try { await persist(); } catch (error) { $('nc-add-status').textContent = error.message; }
}

async function withdraw(fp) {
  const gen = generation;
  try {
    await core.requestCancel(fp);
    if (gen !== generation) return;
    state.outgoing = state.outgoing.filter(o => o.fp !== fp);
    await persist();
    if (gen === generation) { $('nc-add-status').textContent = 'Request withdrawn.'; render(); }
  } catch (error) { if (gen === generation) $('nc-add-status').textContent = explain(error, 'Withdrawing failed. Try again in a minute.'); }
}

async function addContact(event) {
  event.preventDefault();
  const gen = generation;
  try {
    const fp = parseContactId($('nc-add-id').value);
    if (fp === ownFp) throw new Error('That is your own ID.');
    if (contactOf(fp)) throw new Error('This person is already a contact.');
    if (state.outgoing.some(o => o.fp === fp)) throw new Error('You already sent this person a request.');
    const note = $('nc-add-note').value;
    $('nc-add-status').textContent = 'Sending request…';
    let result;
    try { result = await core.requestSend(fp, note); }
    catch { throw new Error(new TextEncoder().encode(note).length > 255 ? 'The note is too long.' : 'The request could not be sent. Try again in a minute.'); }
    if (gen !== generation) return;
    // The offered salt is kept until they accept (core.js requestSend).
    state.outgoing.push({ fp, salt: result.salt, at: nowSeconds() });
    await persist();
    if (gen !== generation) return;
    $('nc-add-id').value = ''; $('nc-add-note').value = '';
    $('nc-add-status').textContent = 'Request sent. They appear in your contacts once they accept.';
    render();
  } catch (error) { if (gen === generation) $('nc-add-status').textContent = error.message; }
}

async function send(event) {
  event.preventDefault();
  const gen = generation, contact = selectedFp && contactOf(selectedFp);
  const text = $('nc-send-text').value;
  if (!contact || !contact.salt || !text.trim()) return;
  try {
    const message = { seq: takeSeq(), fp: contact.fp, dir: 'out', text, ts: nowSeconds(), at: Date.now() };
    await persist([message]);
    if (gen !== generation) return;
    messages.push(message); unpublished.add(contact.fp);
    $('nc-send-text').value = '';
    render();
    try { await publishOutbox(contact, gen); if (gen === generation) $('nc-send-status').textContent = ''; }
    catch { if (gen === generation) $('nc-send-status').textContent = 'Not sent yet. It is tried again automatically.'; }
    if (gen === generation) render();
  } catch (error) { if (gen === generation) $('nc-send-status').textContent = error.message; }
}

async function saveProfile(event) {
  event.preventDefault();
  const gen = generation;
  if (profileTaken) return;
  try {
    const patch = profilePatch({ bio: $('nc-bio').value, location: $('nc-location').value, website: $('nc-website').value });
    $('nc-profile-status').textContent = 'Saving…';
    const result = await core.profileUpdate(patch);
    if (gen !== generation) return;
    $('nc-profile-status').textContent = profileStatusText(result.status);
    if (result.status === 'published') { ownProfile = { ...(ownProfile || {}), ...patch }; fillProfile(); }
    if (result.status === 'taken') profileTaken = true;
  } catch (error) { if (gen === generation) $('nc-profile-status').textContent = /https|Invalid profile/.test(error.message) ? error.message : 'Saving failed. Try again later.'; }
}

async function erase() {
  if (!store?.persistent) return;
  if (!eraseArmed) { eraseArmed = true; $('nc-erase').textContent = 'Confirm: delete all messages on this device'; return; }
  const target = store;
  try { await target.erase(); lock('Message history deleted from this device.'); }
  catch (error) { lock(error.message); }
}

// ── wiring ─────────────────────────────────────────────────────────────
export function startMessages() {
  for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, activity);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) expireIdle(); });
  window.addEventListener('focus', expireIdle);
  window.addEventListener('pagehide', () => lock());
  // A saved wallet changed or removed in another tab (src/app.js does the same).
  window.addEventListener('storage', event => { if ((event.key === VAULT_KEY || event.key === null) && (core || sessionRelease)) lock('Saved wallet changed in another tab. Unlock again to continue.'); });

  for (const cancel of document.querySelectorAll('.nc-cancel')) cancel.onclick = () => lock('');
  $('nc-lock').onclick = () => lock();
  $('nc-retry').onclick = () => {
    if (!core || !ownFp) { lock(''); return; }
    const gen = generation;
    show(null);
    finishOpen(gen).catch(error => { if (gen === generation) closed(explain(error, 'Messages could not connect to the network right now. Try again in a minute.')); });
  };
  $('nc-tab-contacts').onclick = () => showTab('contacts');
  $('nc-tab-profile').onclick = () => showTab('profile');

  $('nc-choose-saved').onclick = () => { status(''); show('nc-unlock-form'); $('nc-password').focus(); activity(); };
  $('nc-choose-words').onclick = () => { status(''); show('nc-words-form'); $('nc-words').focus(); activity(); };
  $('nc-choose-create').onclick = () => {
    status('');
    newPhraseText = Mnemonic.entropyToPhrase(randomBytes(32));
    $('nc-new-words').replaceChildren(...newPhraseText.split(' ').map(word => el('li', { text: word })));
    show('nc-create-form'); activity();
  };
  $('nc-new-words-check').addEventListener('paste', event => event.preventDefault());

  // Each form is hidden (show(null)) before open() starts, so no form can be
  // submitted again while "Opening Messages…" runs (open() supersedes and
  // locks anyway). open() shows the start screen, the closed screen or
  // Messages when it ends.
  $('nc-unlock-form').onsubmit = event => {
    event.preventDefault();
    const password = $('nc-password').value; $('nc-password').value = '';
    show(null);
    void open(async () => {
      const text = localStorage.getItem(VAULT_KEY);
      if (!text) throw new Closed('No saved wallet on this device.');
      const saved = await decryptVault(text, password);
      return { phrase: saved.phrase, id: saved.id };
    }, { persistent: true, isFresh: false });
  };
  $('nc-words-form').onsubmit = event => {
    event.preventDefault();
    let phrase;
    try { phrase = validateNodusPhrase($('nc-words').value); } catch (error) { status(error.message); return; }
    $('nc-words').value = '';
    show(null);
    // Typed words are never "fresh" (decision Q1): a restored identity creates no record.
    void open(async () => ({ phrase, id: null }), { persistent: false, isFresh: false });
  };
  $('nc-create-form').onsubmit = event => {
    event.preventDefault();
    const phrase = newPhraseText;
    if (!phrase || normalizePhrase($('nc-new-words-check').value) !== phrase) { status('The words do not match. Check your written copy and type them again.'); return; }
    $('nc-new-words-check').value = ''; $('nc-new-words').replaceChildren(); newPhraseText = undefined;
    show(null);
    // Only words generated in this tab, this session, are "fresh" (Q1).
    void open(async () => ({ phrase, id: null }), { persistent: false, isFresh: true });
  };

  $('nc-add-form').onsubmit = event => void addContact(event);
  $('nc-send-form').onsubmit = event => void send(event);
  $('nc-profile-form').onsubmit = event => void saveProfile(event);
  $('nc-erase').onclick = () => void erase();
  showStart();
}
