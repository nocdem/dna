// Nodus Connect — Messages (contacts, requests, 1:1 text, own profile, and
// since package G3 the groups of src/connect/groups/).
//
// Governing records: docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md
// (first stage, Ek 2: contact list, send/accept contact requests, 1:1 text
// messages, own profile edit — no media or calls; groups follow
// 2026-10-04-connect-groups.md and the groups design rev 1; Q1: only words
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
//     the wallet's NODUS client is IDENTIFIED (nodusIdentified): what this
//     device keeps is shown first, the network phase follows once the
//     client is ready (nodusReady); the wallet's Lock, idle lock,
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
// terms; the page shows its own plain words (explain()). ONE exception: a
// conversation's collapsed "Details" line shows the last check's error as
// "Last check failed: <message>", bounded and with every long hex run cut
// out (diag.js errorText) — a diagnostic the user opens on purpose.
//
// Rendering (design rev 5 §1.9): every text through textContent (dom.js el);
// text written by someone else (names, notes, messages, profile fields) in a
// <bdi> with the "unusual characters" marker (dom.js untrusted); a website
// only as a checked https: link; no innerHTML, no inline style attribute.
import { createNodusConnectCore, acceptanceMayAutoApprove, CONTACT_READS_MAX } from '../core.js';
import { openHistoryStore, memoryHistoryStore, StorageError } from '../store.js';
import {
  parseContactInput, requestRefusal, profilePatch, profileStatusText, contactListStatusText, senderClockLabel,
  pendingOutbox, hasUndelivered, compareLocal, receivedKey,
  publishedSeqs, markPublished, markDelivered, ackToSend, messageStatus, avatarPatch, AVATAR_UPLOAD_MAX_B64,
  checkOrder, contactDays, contactNeedsFullSync, profileFresh, contactNames, mergeListedContacts, removeContact, unremoveContact,
  shortId, inspectUntrusted,
  updatingStageText, checkingContactsText, roundStartLine, stageLine, stageStartLine, contactStartLine, contactStepLine,
  contactLine, roundDoneLine
} from './text.js';
import { el, untrusted, button, website, fillAvatar } from './dom.js';
import { parseNameOf } from '../../nodus/names.js';
import { keptChainName as keptNameOf, chainLookupNeeded, chainNameAfterLookup, chainNoNameFresh, chainNoNameAfterLookup, resolveContactName, NAME_CHECK_TEXT } from './chain-names.js';
import { newDiag, diagSalt, diagDay, errorText, diagText } from './diag.js';
// The session log (memory only, cleared on lock): Messages' failures as
// shown, with the bounded error text (diag.js errorText) — never a message
// text, a key or a full ID (src/session-log.js scrubs every line too).
import { sessionLog } from '../../session-log.js';
const logFailure = (text, error) => sessionLog.log('messages', error === undefined ? text : `${text} (${errorText(error)})`, { error: true });
// The message check's progress (web 0.1.71): rounds, first-round stages and
// one line per contact (text.js roundStartLine … roundDoneLine) — counts,
// durations and the short ID only.
const logCheck = (text, failed = false) => sessionLog.log('messages', text, { error: failed });
// Groups (package G3): the state machine and its screens. Group invites,
// accepts, welcomes and leaves travel as 1:1 messages (bytes item 7,
// decision 13); they are routed to the groups module and never shown as
// chat text (isControl below).
import { createGroupsEngine } from '../groups/engine.js';
import { createGroupsView } from '../groups/ui.js';
import { controlType } from '../groups/model.js';

const SYNC_MS = 30000;                   // how often requests and messages are checked
// Contacts whose ACK and day buckets one call reads together (web 0.1.74,
// core.js CONTACT_READS_MAX = connect/nc_core.h NC_CONTACT_READS_MAX).
const CHECK_GROUP_MAX = CONTACT_READS_MAX;
const HISTORY_OPEN_MS = 15000;           // bound of the IndexedDB open + read (openLocal)
const HEX128 = /^[0-9a-f]{128}$/;
const TEXT_MAX = 4000;                   // one message, characters (the composer's maxlength)
const COMPOSER_ROWS = 5;                 // the composer grows up to this many lines
const STATUS_MARK = { 'waiting to send': '○', sent: '✓', delivered: '✓✓' };
const WAITING_TEXT = 'Messages opens as soon as your wallet is open.';
// The wallet tries the connection again by itself (src/app.js RECONNECT)
// and raises nodusReady again once it is made.
const UNAVAILABLE_TEXT = 'Messages needs the Nodus network connection, which is unavailable right now. The wallet tries to connect again by itself; Messages opens as soon as it is connected.';
const LOCAL_FAILED_TEXT = 'Your messages on this device could not be opened right now. Try again.';
// The status line under Chats while the network phase has not finished.
const CONNECTING_TEXT = 'Connecting to the network… Your messages on this device are shown; sending opens once connected.';
const UPDATING_TEXT = 'Updating…';
const OFFLINE_SEND_TEXT = 'Sending opens once Messages is connected to the network.';
const ADD_SUBMIT_TEXT = 'Send request';  // the add dialog's button while no chain name is shown (showAddResolved)

// ── session state (all dropped by close / reset) ───────────────────────
let core, store, state, messages = [], ownFp, ownProfile, fresh = false, vaultId = null;
let generation = 0, syncTimer, syncing = false;
let checkRound = 0;                      // message check rounds started this session (session log only)
let sending = false;                     // a composer send is being kept on this device (send)
let requests = [], selectedFp, eraseArmed = false, profileTaken = false;
let mlkemRepublishTried = false;         // the own profile was republished with the ML-KEM key this open (checkOwnAccount)
let removeArmed;                         // the contact whose "Remove" was pressed once (asks to confirm)
let addResolved;                         // { name, owner }: the add box's chain name, looked up and shown, awaiting confirmation
const profiles = new Map();              // fp -> verified profile, this session
const kept = new Map();                  // fp -> { id, record }: kept profile rows (saved wallet, state.profileCache)
const blobs = new Map();                 // 'fp|day' -> { blob, other }: day buckets already stored, this session
const received = new Set();              // receivedKey of every stored incoming message
const unpublished = new Set();           // contacts whose pending set must be (re)published
const saltChecked = new Set();           // contacts whose salt was reconciled this session
const dropped = new Map();               // fp -> messages that did not verify, this session
const others = new Map();                // fp -> authentic items that are not text (reactions, calls, …), last check
const lastRead = new Map();              // fp -> highest local seq shown to the user (this session only)
const diags = new Map();                 // fp -> the last message check's diagnostics (diag.js; memory only, never saved)
const vaultRecs = new Map();             // vault address -> { id, value }: shared vaults kept (state.vaults, src/vaults/)
// HF-4 chain names: fp -> the chain name ('' = none, or not answered), this
// session; kept across sessions only for a saved wallet (state.chainNames).
const chainNames = new Map();
const chainAsked = new Set();            // IDs whose chain name lookup was answered this session
const chainTried = new Map();            // fp -> page clock (ms) of its last chain name lookup, this session (spacing only)
let ownNameConfirmed = false;            // the own name was confirmed by this session's lookup
let nodusClient;                         // the wallet's client (nameOf), this session
// LOCAL FIRST: Messages opens on the wallet's IDENTIFIED client from what
// this device keeps (openLocal), then the NETWORK phase runs in the
// background once the client is ready (goOnline -> sync).
let groups;                              // the groups engine (src/connect/groups/engine.js), this session
let groupsView;                          // its screens (src/connect/groups/ui.js), mounted once
let netStarted = false;                  // the network phase started (client ready)
let online = false;                      // own account checked on the network
                                         // (read, or a fresh one published):
                                         // nothing is sent before

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
  clearInterval(syncTimer); syncTimer = undefined; syncing = false; sending = false; checkRound = 0;
  const c = core; core = undefined;
  try { c?.lock(); } catch { /* the rest must still run */ }
  try { store?.close(); } catch { /* same */ }
  store = undefined; state = undefined; messages = []; ownFp = undefined; ownProfile = undefined;
  fresh = false; vaultId = null; requests = []; selectedFp = undefined; nodusClient = undefined;
  eraseArmed = false; profileTaken = false; mlkemRepublishTried = false; ownNameConfirmed = false; removeArmed = undefined; addResolved = undefined;
  netStarted = false; online = false; groups = undefined;
  for (const set of [profiles, kept, blobs, received, unpublished, saltChecked, dropped, others, lastRead, diags, chainNames, chainAsked, chainTried, vaultRecs]) set.clear();
  notifyVaultHost();
  if (!ui) return;
  groupsView?.reset();
  for (const control of [ui.addId, ui.addNote, ui.composer, ui.bio, ui.location, ui.website]) control.value = '';
  ui.composer.rows = 1; ui.counter.textContent = '';
  for (const line of [ui.addStatus, ui.sendStatus, ui.profileStatus, ui.copyStatus, ui.emptyCopyStatus, ui.requestsStatus, ui.contactsStatus, ui.sync, ui.ownId, ui.profileName, ui.avatarStatus, ui.ownAvatar]) line.textContent = '';
  ui.messageList.replaceChildren(); ui.requestList.replaceChildren(); ui.outgoingList.replaceChildren();
  ui.contactList.replaceChildren(); ui.hubList.replaceChildren(); ui.convTitle.textContent = ''; ui.convClaim.replaceChildren(); ui.convNote.textContent = '';
  ui.convDiagText.textContent = ''; ui.convDiag.open = false; ui.convDiag.hidden = true;
  ui.erase.textContent = 'Delete message history on this device';
  ui.avatarChange.disabled = ui.avatarRemove.disabled = false;
  showAddResolved();
  if (ui.addDialog.open) ui.addDialog.close();
  screen = 'list'; hubTab = 'contacts'; filter = 'all';
}

// Messages is closed with a reason (an error, the connection, a deleted
// history). `retry`: the identity is open and only reading failed.
export function closeMessages(reason, { retry = false } = {}) {
  if (reason) logFailure(`Messages closed: ${reason}`);
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

// client: the wallet's NODUS client, identified (src/nodus/client.js
// identify — the network may still be connecting) or ready, its module with
// the Messages exports; phrase: the normalised recovery phrase; vaultId: the
// saved wallet's id or null (memory only: nothing is kept after lock and no
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
    await openLocal(gen);
  } catch (error) {
    if (superseded()) return;
    // Before the identity is open: Messages stays closed until the wallet is
    // opened again (core.lock is terminal). After it: retry the local open.
    if (!ownFp) { closeMessages(explain(error, 'Messages could not open right now. Lock and open your wallet again to retry.')); return; }
    closeMessages(explain(error, LOCAL_FAILED_TEXT), { retry: true });
  } finally { words?.fill(0); }
}

// Our own plain-words errors (Closed, a storage failure) are shown as they
// are; anything else gets the caller's plain-words fallback.
function explain(error, fallback) {
  const shown = error instanceof Closed || error instanceof StorageError ? error.message : fallback;
  logFailure(shown, error);
  return shown;
}

// LOCAL phase: what this device keeps, before any network call — the
// history store (a saved wallet's; typed words and a new account keep
// nothing, memory only), the contacts and conversations, the kept profiles
// and pictures, the kept chain names and the own ID. It writes nothing
// anywhere. The full view is shown at its end; the NETWORK phase
// (goOnline) starts as soon as the wallet's client is ready, and nothing is
// sent before it has read this account's own profile (or, for a fresh
// account, published it) — design §1.7, §7 Q1 (iii).
async function openLocal(gen) {
  phase = 'opening';
  showState('Opening Messages', 'Loading your messages…', false);
  if (!store) {
    // A saved wallet keeps its history (S8); typed words and a new account
    // keep nothing. The IndexedDB open and read are bounded (15 s, the
    // page's request pattern): the wallet's connection waits for this local
    // open (src/app.js startNodusSend), so a browser database that never
    // answers must not hold it. On expiry Messages closes with
    // HISTORY_SLOW_TEXT (retry offered), nothing half-loaded is kept and a
    // late database handle is closed (store.js bounded).
    const opened = vaultId ? await openHistoryStore({ core, vaultId, signal: AbortSignal.timeout(HISTORY_OPEN_MS) }) : memoryHistoryStore();
    if (gen !== generation) { opened.close(); return; }
    store = opened;
    state = structuredClone(store.state);
    messages = [...store.messages];
    for (const p of store.profiles) kept.set(p.fp, { id: p.id, record: p.record });
    for (const v of store.vaults || []) vaultRecs.set(v.address, { id: v.id, value: v.value });
    // Groups: what this device keeps (store.js groupRecords / groupMessages);
    // no network until the network phase.
    groups = createGroupsEngine({
      core, ownFp, state: () => state, takeSeq,
      saveAll: ({ records = [], messages: groupMessages = [] }) => store.save(state, groupMessages, [], [], records),
      sendDirect: sendControl,
      isContact: fp => !!contactOf(fp)?.salt,
      ensureProfile: fp => ensureProfile(fp, !!contactOf(fp)),
      reloadProfile,
      hasKemKey: fp => profiles.get(fp)?.has_mlkem === true,
      nameStatus: groupNameStatus,
      lookupName: groupNameLookup
    });
    groups.load({ records: store.groupRecords || [], messages: store.groupMessages || [] });
    for (const m of messages) if (m.dir === 'in') received.add(receivedKey(m.fp, { seq: m.remoteSeq, senderTs: m.senderTs, text: m.text }));
    const now = nowSeconds();
    for (const contact of state.contacts) if (hasUndelivered(messages, contact.fp, now)) unpublished.add(contact.fp);
    // History from earlier sessions is not "new".
    for (const contact of state.contacts) markRead(contact.fp);
  }
  // Kept profiles younger than 7 days are in place before the first screen
  // (no network: core.profileLoad checks the kept row's signature and
  // fingerprint again), so names and pictures show at once. This wallet's
  // own kept row (any age) only fills the view until the network phase
  // reads the profile again; its keys are never used for sending.
  for (const fp of [ownFp, ...state.contacts.map(c => c.fp)]) {
    const own = fp === ownFp, entry = state.profileCache[fp], row = kept.get(fp);
    if ((!own && profiles.has(fp)) || !entry || row?.id !== entry.id || (!own && !profileFresh(entry, nowSeconds()))) continue;
    try {
      const loaded = (await core.profileLoad(fp, row.record, entry.name)).profile;
      if (gen !== generation) return;
      if (own) { if (!online) ownProfile = loaded; } else profiles.set(fp, loaded);
    } catch { /* read from the network by the first check */ }
    if (gen !== generation) return;
  }
  // Kept chain names, likewise (no network; a name is permanent, so a kept
  // one does not expire — chain-names.js).
  for (const fp of [ownFp, ...state.contacts.map(c => c.fp)]) keptChainName(fp);

  ui.ownId.textContent = ownFp;
  ui.memoryNote.hidden = store.persistent;
  ui.erase.hidden = !store.persistent;
  fillProfile();
  phase = 'open';
  screen = 'list';
  ui.sync.textContent = CONNECTING_TEXT;
  render();
  notifyVaultHost();
  if (nodusClient?.state === 'ready') goOnline(gen);
}

// NETWORK phase, in the background: the 30-second check starts; its first
// round reads this account's own profile (a fresh account publishes it)
// and merges the own contact list from the network before anything else
// (sync). Until that succeeded nothing is sent (`online`); a failure keeps
// the view and is tried again on the next round.
function goOnline(gen) {
  if (gen !== generation || !isOpen() || netStarted) return;
  netStarted = true;
  ui.sync.textContent = UPDATING_TEXT;
  clearInterval(syncTimer);
  syncTimer = setInterval(() => { void sync(); }, SYNC_MS);
  void sync();
}

// The own profile on the network (was the gate of opening Messages; now
// the gate of sending). Throws Closed with plain words when it cannot be
// read (nothing is written then — Q1) or a fresh account's could not be
// published.
async function checkOwnAccount(gen) {
  let own = await core.profileGet(ownFp);
  if (gen !== generation) return false;
  const before = ownProfile;
  if (own.outcome === 'found') {
    if (profileNeedsMlkem(own.profile) && !mlkemRepublishTried) {
      mlkemRepublishTried = true;
      own = await republishWithMlkem(gen, own);
      if (gen !== generation) return false;
    }
    ownProfile = own.profile;
    await keepProfile(ownFp, own);
    if (gen !== generation) return false;
  } else if (own.outcome === 'empty' && fresh) {
    const made = await core.profileUpdate({});
    if (gen !== generation) return false;
    if (made.status !== 'published') throw new Closed(profileStatusText(made.status));
    ownProfile = null;
  } else throw new Closed('Your account could not be read from the network right now. Nothing was changed. Checking again automatically.');
  // The edit fields are refilled only if the user has not typed in them
  // while the network was being read.
  const was = before || {};
  if (ui.bio.value === (was.bio || '') && ui.location.value === (was.location || '') && ui.website.value === (was.website || '')) fillProfile();
  else { fillOwnAvatar(); fillNameLine(); }
  return true;
}

// A found own profile without the ML-KEM key (written by an older DNA
// Connect app): groups refuse such a member (groups/engine.js) and 1:1
// messages to it fall back to round-3 Kyber. The record carries the key
// outside its signed part (decision 2026-09-23-kem-mlkem-migration.md, K1
// rev 2 / K4). Exported for the unit test.
export function profileNeedsMlkem(profile) {
  return !!profile && typeof profile === 'object' && profile.has_mlkem !== true;
}

// Republishes the own profile once per open with the ML-KEM key added: an
// empty patch keeps every field; the core reads the profile again inside the
// same call and writes only on a FOUND read (nc_profile.c nc_profile_publish;
// decision 2026-09-30-nodus-connect-thin-core.md S3 / Q1). Returns the read
// to show and keep: the new one when it was published and reads back with
// the key, otherwise the earlier `own`. A failure never closes Messages; it
// is logged and tried again on a later open.
async function republishWithMlkem(gen, own) {
  try {
    const made = await core.profileUpdate({});
    if (gen !== generation) return own;
    if (made.status !== 'published') {
      if (made.status === 'taken') { profileTaken = true; logCheck('Own profile: adding the ML-KEM key was not written (the profile address is taken)', true); }
      else logCheck(`Own profile: adding the ML-KEM key was not written (${made.status}); tried again on a later open`, true);
      return own;
    }
    const again = await core.profileGet(ownFp);
    if (gen !== generation) return own;
    if (again.outcome === 'found' && !profileNeedsMlkem(again.profile)) {
      logCheck('Own profile: republished with the ML-KEM key');
      return again;
    }
    logCheck(`Own profile: republished with the ML-KEM key; the read back did not show it yet (${again.outcome})`);
    return own;
  } catch (error) {
    if (gen === generation) logFailure('Own profile: adding the ML-KEM key failed; tried again on a later open', error);
    return own;
  }
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
  unremoveContact(state, fp);
  state.outgoing = state.outgoing.filter(o => o.fp !== fp);
  state.declined = state.declined.filter(d => d !== fp);
  return contact;
}

// The own list on the network: add what it has and this device lacks. A
// salt this device already holds is kept (the agreement comes first, the
// list second — design §1.4 R3). A contact removed on this device is not
// added back (text.js mergeListedContacts).
async function mergeContactList(gen) {
  const list = await core.contactsGet();
  if (gen !== generation || list.outcome !== 'found') return;
  if (mergeListedContacts(state, list.contacts, ownFp)) await persist();
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
// 2026-10-02-onchain-names.md item 9). A found name of this ID or a contact
// is kept (state.chainNames — decision 2026-10-02-device-cache-only-when-saved:
// on the device only inside a saved wallet's encrypted history; an unsaved
// wallet's state lives in memory only) and, a name being permanent (item 4),
// does not expire: a contact's kept name is shown at once and not asked
// again; this wallet's own kept name is shown at once and asked again once
// per session (chain-names.js). An ID without a kept name is asked once per
// session by the sync round — a contact whose answered "no name" is kept
// (state.chainNoName, same saved-wallet-only rule, web 0.1.74) only once
// that answer is a day old — and a contact without a known name again when
// its conversation is opened (recheckChainNameOnOpen). An older node, a
// failed read or a module without names: nothing changes (a kept name stays)
// and nothing new is kept; a failed read does not count as asked, so a later
// round tries again. No ID is asked twice within CHAIN_LOOKUP_SPACING_MS
// (chainTried, in memory only).
function keptChainName(fp) {
  const name = keptNameOf(state.chainNames[fp]);
  if (!chainNames.has(fp) && name) chainNames.set(fp, name);
}
// `keep`: this ID's or a contact's name (a stranger's request is not kept,
// as ensureProfile). `opened`: the user just opened this contact's
// conversation (chain-names.js chainLookupNeeded). @return true when
// state.chainNames changed (the caller saves once).
async function ensureChainName(fp, keep = false, opened = false) {
  keptChainName(fp);
  const own = fp === ownFp, gen = generation, at = Date.now();
  // A contact's answered "no name" kept less than a day ago (web 0.1.74,
  // state.chainNoName, chain-names.js chainNoNameFresh) counts as asked for
  // the sync round; `opened` still asks (chainLookupNeeded ignores `asked`
  // then). Contacts only: the own ID is asked once per session as before.
  const contact = !own && !!contactOf(fp);
  const noNameKept = contact && chainNoNameFresh(state.chainNoName[fp], nowSeconds());
  if (!nodusClient?.nameable || !chainLookupNeeded({ asked: chainAsked.has(fp) || noNameKept, known: !!chainNameOf(fp), recheck: own, opened, lastTry: chainTried.get(fp), now: at })) return false;
  chainTried.set(fp, at);
  let found;
  try { found = parseNameOf(await nodusClient.nameOf({ owner: fp })); }
  catch { if (gen === generation && !chainNames.has(fp)) chainNames.set(fp, ''); return false; }
  if (gen !== generation) return false;
  chainAsked.add(fp);
  const now = nowSeconds();
  const after = chainNameAfterLookup(state.chainNames[fp], found, { keep, now });
  chainNames.set(fp, after.name);
  if (own) ownNameConfirmed = !!after.name;
  if (after.entry) state.chainNames[fp] = after.entry; else delete state.chainNames[fp];
  const none = chainNoNameAfterLookup(state.chainNoName[fp], found, { keep: keep && contact, now });
  if (none.at !== null) state.chainNoName[fp] = none.at; else delete state.chainNoName[fp];
  return after.changed || none.changed;
}
// Groups (decisions 2026-10-04-connect-groups.md items 17 + 18): only IDs
// with a confirmed chain name may be in a group. The groups engine reads the
// same names as the rest of Messages: 'found' = a name is known (kept in
// state.chainNames, or found this session — a name is permanent, so one is
// enough); 'none' = a lookup ANSWERED "no name" this session (chainAsked is
// set only by an answer); 'unknown' = no answer yet (never asked, or every
// lookup failed — a failed lookup does not move it).
function groupNameStatus(fp) {
  if (!state) return 'unknown';
  keptChainName(fp);
  if (chainNameOf(fp)) return 'found';
  return chainAsked.has(fp) ? 'none' : 'unknown';
}
// A lookup for the groups engine when no name is known: asked again even
// after an earlier "no name" (that answer is never final), but never twice
// for one ID within CHAIN_LOOKUP_SPACING_MS (ensureChainName, `opened`).
// A found name is kept (state.chainNames) for every ID a group asks about —
// a group member need not be a contact, and one confirmed name per identity
// is enough (decision 17) — so a group's history shows at the next local
// open without waiting for the network.
async function groupNameLookup(fp) {
  if (!isOpen()) return;
  const gen = generation;
  let moved;
  try { moved = await ensureChainName(fp, true, true); } catch { return; }
  if (moved && gen === generation && isOpen()) { try { await persist(); } catch { /* shown this session; the next save keeps it */ } }
}
// Opening a contact's conversation: a contact without a known chain name is
// asked again right then (it may have registered a name after this session
// first asked); a found name is shown at once and kept through the usual
// save. A kept name is not asked again (ensureChainName).
async function recheckChainNameOnOpen(fp) {
  if (!isOpen() || !contactOf(fp) || chainNameOf(fp)) return;
  const gen = generation;
  let moved;
  try { moved = await ensureChainName(fp, true, true); } catch { return; }
  if (gen !== generation || !isOpen() || !chainNameOf(fp)) return;
  if (moved) { try { await persist(); } catch { /* shown this session; the next save keeps it */ } }
  if (gen === generation && isOpen()) render();
}

// ── sync ───────────────────────────────────────────────────────────────
async function sync() {
  if (syncing || !isOpen() || !netStarted) return;
  syncing = true;
  const gen = generation;
  // Progress (web 0.1.71): the first round names each step before the
  // contacts in the status line and logs its start and duration; every
  // round counts its contacts in the status line and logs one line per
  // contact (session log, memory only). A later round leaves the status
  // line as it was until its contacts are checked, so it does not flicker
  // every 30 seconds. Nothing here changes what is called or in what order.
  const round = ++checkRound, first = !online, roundAt = Date.now();
  const stageBegin = name => {
    if (!first) return 0;
    ui.sync.textContent = updatingStageText(name);
    logCheck(stageStartLine(round, name));
    return Date.now();
  };
  const stageEnd = (name, at) => { if (first && gen === generation) logCheck(stageLine(round, name, Date.now() - at)); };
  try {
    // The first round of the network phase (goOnline): the own account,
    // then the own contact list; only then may anything be sent.
    if (!online) {
      const accountAt = stageBegin('account');
      if (!await checkOwnAccount(gen) || gen !== generation) return;
      stageEnd('account', accountAt);
      const listAt = stageBegin('contacts');
      await mergeContactList(gen);
      if (gen !== generation) return;
      stageEnd('contacts', listAt);
      online = true;
      render();
    }
    const requestsAt = stageBegin('requests');
    await syncRequests(gen);
    if (gen !== generation) return;
    stageEnd('requests', requestsAt);
    const publishAt = stageBegin('publish');
    await publishContacts(gen);
    if (gen !== generation) return;
    stageEnd('publish', publishAt);
    // Chain names (HF-4) of this ID, the contacts and the request screens,
    // BEFORE the message check so they are in place on the first check:
    // at most one answered read per ID per session (a failed read is tried
    // again on a later round, no sooner than CHAIN_LOOKUP_SPACING_MS), none
    // for a contact whose name is kept, and none for a contact whose "no
    // name" answer is kept and less than a day old (web 0.1.74,
    // ensureChainName).
    const namesAt = stageBegin('names');
    let namesMoved = false;
    for (const fp of new Set([ownFp, ...state.contacts.map(c => c.fp), ...state.outgoing.map(o => o.fp), ...requests.map(r => r.sender)])) {
      if (gen !== generation) return;
      // First round: one line per ID, so a lookup that never ends is named.
      if (first) logCheck(contactStepLine(shortId(fp), 'name'));
      if (await ensureChainName(fp, fp === ownFp || !!contactOf(fp))) namesMoved = true;
    }
    if (namesMoved && gen === generation) await persist();
    if (gen !== generation) return;
    stageEnd('names', namesAt);
    fillOwnAvatar(); fillNameLine(); render();
    // Smart sync, per contact (web 0.1.72, text.js contactDays): a contact
    // never checked, or last checked over 3 days ago, reads the 8 day
    // buckets; every other contact the 3 recent ones. The check time of
    // each contact whose buckets were all read is kept (state.dmSync) —
    // saved only when it moved by an hour or more, so a 30-second check
    // does not rewrite the state every time.
    const startedAt = nowSeconds(), today = core.dayToday();
    // One contact's failure is kept in that contact's Details line
    // (diags) and the check goes on with the next contact: a failure must
    // not leave every contact after it in the list unchecked, round after
    // round. A close / reset meanwhile still ends the check.
    let syncMoved = false, failed = 0, storageFailure, arrivedTotal = 0;
    // Check order (web 0.1.72, text.js checkOrder): never-checked contacts
    // first, then the ones with the newest message on this device, then
    // the rest — a copy; state.contacts keeps its order.
    const contacts = checkOrder(state.contacts, state.dmSync, messages);
    const daysOf = new Map(contacts.map(c => [c.fp, contactDays(c.fp, state.dmSync, startedAt, today)]));
    const full = contacts.filter(c => contactNeedsFullSync(c.fp, state.dmSync, startedAt)).length;
    logCheck(roundStartLine(round, { first, contacts: contacts.length, full, recent: contacts.length - full }));
    // Groups of contacts (web 0.1.74): up to CHECK_GROUP_MAX contacts, in
    // the check order. First, per contact and one at a time as before, the
    // profile and the salt (startContactCheck — a salt write stays in the
    // call that read it, design §6.4 F4); then ONE call reads the ACK and
    // the day buckets of every contact of the group that has a profile and
    // a salt (core.contactReads: the same strict read per key, the requests
    // pipelined in the module, 4 in flight at once — one call per contact
    // and step cost a round trip each, ~4.5 s per contact on the operator's
    // phone, 2026-10-07); then each contact's answers are handled in order
    // exactly as before (finishContactCheck: delivery marks, publish,
    // messages stored, ACK publish). A failure in a contact's own steps
    // stays that contact's; a failed group call fails each contact it read.
    for (let start = 0; start < contacts.length; start += CHECK_GROUP_MAX) {
      if (gen !== generation) return;
      ui.sync.textContent = checkingContactsText(start + 1, contacts.length);
      const group = [];
      for (let index = start; index < Math.min(start + CHECK_GROUP_MAX, contacts.length); index++) {
        if (gen !== generation) return;
        const contact = contacts[index];
        // Removed by the user while this check ran: not checked any more.
        if (!contactOf(contact.fp)) continue;
        const entry = { contact, index, id: shortId(contact.fp), at: Date.now(), before: incomingCount(contact.fp), days: daysOf.get(contact.fp) };
        logCheck(contactStartLine(entry.id));
        try { entry.ready = await startContactCheck(entry, gen); }
        catch (error) { entry.error = error; }
        if (gen !== generation) return;
        group.push(entry);
      }
      const reading = group.filter(e => e.ready === true && e.error === undefined);
      if (reading.length) {
        for (const e of reading) {
          // Delivery (NC-RT2 A, text.js markDelivered): which own messages
          // were published is taken BEFORE the ACK read is issued; a publish
          // finishing meanwhile (send()) does not count for this read.
          e.salt = e.contact.salt;
          e.publishedBefore = publishedSeqs(messages, e.contact.fp);
          logCheck(contactStepLine(e.id, 'reads', reading.length));
        }
        // Each bucket is passed the hash of the same bucket this session
        // already stored (blobs): an unchanged bucket is not decoded again
        // (the app's blob cache, dht_dm_outbox.c:30-80). blobs changes only
        // in finishContactCheck, and only for that contact's own keys, so
        // taking every skip hash here reads what a call per contact read.
        let answer;
        try {
          answer = await core.contactReads(reading.map(e => ({
            fp: e.contact.fp, salt: e.salt,
            days: e.days.map(day => ({ day, skipBlob: blobs.get(`${e.contact.fp}|${day}`)?.blob || '' }))
          })));
        } catch (error) { for (const e of reading) e.error = error; }
        if (gen !== generation) return;
        if (answer) reading.forEach((e, i) => { const r = answer.contacts[i]; if (r.error !== undefined) e.error = new Error(r.error); else e.reads = r; });
      }
      for (const e of group) {
        if (gen !== generation) return;
        const { contact, id, days } = e;
        // Removed by the user while its group was read: not handled.
        if (!contactOf(contact.fp)) continue;
        ui.sync.textContent = checkingContactsText(e.index + 1, contacts.length);
        let complete;
        try {
          if (e.error !== undefined) throw e.error;
          // No profile, or no salt: nothing was read (diag says which).
          complete = e.reads ? await finishContactCheck(e, gen) : false;
        } catch (error) {
          if (gen !== generation) return;
          failed++;
          if (error instanceof StorageError) storageFailure = error;
          const diag = diags.get(contact.fp);
          if (diag) diag.error = errorText(error);
          logFailure(`A contact (${shortId(contact.fp)}) could not be checked`, error);
          const got = incomingCount(contact.fp) - e.before;
          arrivedTotal += got;
          logCheck(contactLine(id, { ms: Date.now() - e.at, fresh: got, diag, days: days.length, failed: true }), true);
          continue;
        }
        if (gen === generation) {
          const got = incomingCount(contact.fp) - e.before;
          arrivedTotal += got;
          logCheck(contactLine(id, { ms: Date.now() - e.at, fresh: got, diag: diags.get(contact.fp), days: days.length }));
        }
        if (complete && gen === generation && contactOf(contact.fp)) {
          const last = state.dmSync[contact.fp];
          if (!last || BigInt(startedAt) - BigInt(last) >= 3600n) syncMoved = true;
          state.dmSync[contact.fp] = startedAt;
        }
      }
    }
    if (syncMoved && gen === generation) await persist();
    // Groups (package G3), after the 1:1 contacts — whose check delivered
    // their invites, accepts, welcomes and leaves: one group at a time, each
    // step awaited (design §6.4 F7); a group's failure is its own note.
    let groupsFailed = 0;
    if (gen === generation && groups) {
      try { groupsFailed = await groups.syncAll(() => gen === generation); }
      catch (error) { if (error instanceof StorageError) storageFailure = error; groupsFailed++; }
      if (gen !== generation) return;
    }
    // Names for the request screens: the profiles of the people we asked
    // and of those asking us (read once per session — ensureProfile caches;
    // a name shows only after nc_name_verify proved it).
    for (const fp of new Set([...state.outgoing.map(o => o.fp), ...requests.map(r => r.sender)])) {
      if (gen !== generation) return;
      await ensureProfile(fp);
    }
    if (gen === generation) { fillOwnAvatar(); fillNameLine(); }
    if (gen === generation) {
      const notChecked = (failed ? ` ${failed} contact${failed === 1 ? '' : 's'} could not be checked (see Details in the conversation).` : '') +
        (groupsFailed ? ` ${groupsFailed} group${groupsFailed === 1 ? '' : 's'} could not be checked.` : '');
      ui.sync.textContent = storageFailure
        ? `${storageFailure.message}${notChecked}`
        : `Last checked ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}. New messages are checked every 30 seconds.${notChecked}`;
      logCheck(roundDoneLine(round, { ms: Date.now() - roundAt, fresh: arrivedTotal, failed }));
      render();
    }
  } catch (error) {
    if (gen === generation) ui.sync.textContent = explain(error, 'The network could not be reached. Checking again automatically.');
  } finally { if (gen === generation) syncing = false; }
}

// What this step changed on screen (an outgoing request completed, or the
// incoming list differs) is drawn at once (web 0.1.83): the round's own
// render() comes only after every contact's message check, up to a minute
// later, and until then an accepted request stayed under "Sent by you".
async function syncRequests(gen) {
  const result = await core.requestsFetch();
  if (gen !== generation) return;
  const pending = new Set(state.outgoing.map(o => o.fp));
  const latest = new Map();
  const shownBefore = requests.map(r => `${r.sender}|${r.timestamp}`).join();
  let completed = false;
  for (const request of result.requests || []) {
    if (!request || !HEX128.test(request.sender) || request.sender === ownFp) continue;
    if (acceptanceMayAutoApprove(request, pending)) { await completeOutgoing(request, gen); if (gen !== generation) return; completed = true; continue; }
    // An acceptance without our own pending request is ignored (the app's
    // HIGH-7 rule, dna_engine_contacts.c:555-562).
    if (request.acceptance === true) continue;
    if (contactOf(request.sender) || state.declined.includes(request.sender)) continue;
    const seen = latest.get(request.sender);
    if (!seen || u64(request.timestamp) > u64(seen.timestamp)) latest.set(request.sender, request);
  }
  requests = [...latest.values()];
  if (gen === generation && (completed || requests.map(r => `${r.sender}|${r.timestamp}`).join() !== shownBefore)) render();
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

// A contact's message check, in two halves around its group's one read
// call (sync above, web 0.1.74). Each step's result is written to this
// contact's diagnostics record (diag.js) as it comes; an exception is added
// by sync(). One session log line before each network step (web 0.1.71):
// a check that never ends leaves its last step as the last line of the log.
//
// First half: the profile, then the salt (read, reconcile and the gated
// write in ONE core call, design §6.4 F4). True when the contact has a
// verified profile and a salt — its ACK and day buckets are then read in
// its group's call (core.contactReads). `entry`: the contact's record in
// its group (sync); its diagnostics record is kept there too.
async function startContactCheck(entry, gen) {
  const contact = entry.contact, fp = contact.fp;
  const previous = diags.get(fp), diag = newDiag(Date.now());
  diags.set(fp, diag);
  entry.diag = diag;
  const id = shortId(fp), step = name => logCheck(contactStepLine(id, name));
  step('profile');
  const profileOk = await ensureProfile(fp, true);
  if (gen !== generation) return false;
  diag.profile = profileOk ? 'ok' : 'failed';
  if (!profileOk) return false;
  if (!saltChecked.has(fp)) {
    step('salt');
    const result = await core.saltReconcile(fp, contact.salt || null);
    if (gen !== generation) return false;
    const changed = !!result.salt && result.salt !== contact.salt;
    diag.salt = diagSalt({ result, changed: result.status !== 'wait' && changed });
    if (result.status !== 'wait') {
      saltChecked.add(fp);
      if (changed) { contact.salt = result.salt; await persist(); unpublished.add(fp); }
    }
  // Reconciled earlier this session (also after a 'failed' status, which
  // is not retried): the status of that step is carried forward, so a
  // failed step is not shown as "salt ok".
  } else diag.salt = previous?.salt ?? diagSalt({ earlier: true });
  if (!contact.salt) { diag.noSalt = true; return false; }
  return true;
}

// Second half: the answers of the group's read call for this contact
// (`reads`: { ack, days } — what core.ackGet and core.outboxFetchDays
// answer for the same arguments), handled exactly as when each was its own
// call: delivery marks from the ACK, the pending publish, the day buckets'
// messages stored, the ACK publish. `salt` / `publishedBefore` / `days`
// were taken before the read call was issued (sync). True when every
// bucket of `days` was read (the contact's check time may move, sync).
async function finishContactCheck({ contact, id, salt, days, publishedBefore, reads, diag }, gen) {
  const fp = contact.fp;
  const step = name => logCheck(contactStepLine(id, name));
  const ack = reads.ack;
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

  if (unpublished.has(fp)) { step('publish'); await publishOutbox(contact, gen); }
  if (gen !== generation) return;

  // An unchanged bucket (the skip hash passed by sync) was not decoded
  // again (the app's blob cache, dht_dm_outbox.c:30-80): its non-text
  // count is reused. A hash is remembered only after the bucket's messages
  // were stored, and never for a bucket with a message that did not verify
  // (it stays counted in `dropped` and keeps the ACK back). The answers come
  // in the order of `days` (the group's read call, as core.outboxFetchDays
  // before it, web 0.1.73) and are handled exactly as one call per day was.
  const arrived = [], seen = []; let lost = 0, other = 0, complete = true;
  const results = reads.days;
  for (let i = 0; i < days.length; i++) {
    const day = days[i], result = results[i];
    const key = `${fp}|${day}`, before = blobs.get(key);
    diag.days.push(diagDay(day, result));
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
  // Group invites / accepts / welcomes / leaves (package G3): handed to the
  // groups module with `fp` — the AUTHENTICATED 1:1 sender (the outbox read
  // checks the message's author is this contact) — and kept as 1:1 records
  // flagged `control` (so they are deduplicated and acknowledged like any
  // message) that the chat never shows. The group's own state is saved
  // first: if that fails nothing of this check is kept and it runs again.
  for (const m of arrived) {
    if (!controlType(m.text)) continue;
    m.control = true;
    try { if (groups) await groups.onDirect(fp, m.text); }
    catch (error) { for (const x of arrived) received.delete(receivedKey(fp, { seq: x.remoteSeq, senderTs: x.senderTs, text: x.text })); throw error; }
    if (gen !== generation) return false;
  }
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
      step('ack publish');
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

// A 1:1 record that carries a group control message (flagged when it was
// kept; the text test also covers a record kept before the flag existed):
// published, acknowledged and deduplicated like any message, never shown.
const isControl = m => m.control === true || !!controlType(m.text);
// Stored incoming chat messages of one contact (group control records not
// counted): the difference across a contact's check is its "new" count in
// the session log (sync). Own messages sent meanwhile are not counted.
const incomingCount = fp => messages.reduce((n, m) => (m.fp === fp && m.dir === 'in' && !isControl(m) ? n + 1 : n), 0);

// ── read marks (UI only, this session; nothing is stored) ──────────────
function newestSeq(fp) {
  let newest = -1n;
  for (const m of messages) if (m.fp === fp && BigInt(m.seq) > newest) newest = BigInt(m.seq);
  return newest;
}
function markRead(fp) { lastRead.set(fp, newestSeq(fp)); }
function unreadCount(fp) {
  const seen = lastRead.get(fp) ?? -1n;
  return messages.filter(m => m.fp === fp && m.dir === 'in' && !isControl(m) && BigInt(m.seq) > seen).length;
}
function lastMessage(fp) {
  let last;
  for (const m of messages) if (m.fp === fp && !isControl(m) && (!last || compareLocal(m, last) > 0)) last = m;
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
// §1.9 G9), else ''. It is the title of a contact without a chain name
// (text.js contactNames; decision 2026-10-03-connect-name-display.md).
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
// A contact as plain text (aria labels, status lines, the vault host and
// the NODUS send recipient list): the chain name, else the short ID — never
// a profile name, which is someone else's text and needs the
// unusual-characters marking that plain text (an <option>, an aria-label)
// cannot carry (decision 2026-10-03-connect-name-display.md item 4).
function displayName(fp) {
  const chain = chainNameOf(fp);
  return chain || shortId(fp);
}
// The bold line (decision 2026-10-03-connect-name-display.md): a chain name
// gets the verified look (class chain-name), a profile name is plain text
// with the unusual-characters marking (dom.js untrusted), the short ID is
// plain.
function titleContent(n) {
  return n.fromProfile ? untrusted(n.title, undefined, { name: true }) : n.title;
}
function nameTitle(fp) {
  const n = namesOf(fp);
  return el('strong', n.verified ? { className: 'chain-name' } : {}, titleContent(n));
}

// The two letters shown when there is no picture: of the chain name or the
// profile name (direction controls and invisible characters removed), else
// of the ID.
export function initials(fp, name) { return (name ? [...name].slice(0, 2).join('') : fp.slice(0, 2)).toUpperCase(); }
function avatarName(fp) {
  const n = namesOf(fp);
  return n.verified ? n.title : n.fromProfile ? inspectUntrusted(n.title, { name: true }).text : '';
}

// The profile picture (avatar_base64 of the signature-checked profile,
// dom.js fillAvatar), else the initials.
function avatar(fp, extra = '') {
  const node = el('span', { className: `contact-avatar avatar-${parseInt(fp[0], 16) % 6}${extra}` });
  node.setAttribute('aria-hidden', 'true');
  return fillAvatar(node, initials(fp, avatarName(fp)), profiles.get(fp)?.avatar_base64);
}

// The line under the title (decision 2026-10-03-connect-name-display.md):
// the short ID in parentheses under a chain or profile name; an unverified
// claim only when there is neither (the title is then the short ID itself,
// so the two never appear together). null = nothing.
function nameHint(fp, { claimed, prefix = 'claims the name ' } = {}) {
  const n = namesOf(fp, claimed);
  const parts = [];
  if (n.id) parts.push(el('span', { className: 'contact-id', text: `(${n.id})` }));
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

// The host's own-ID line (Nodus Connect Home #home-id and More #more-id),
// from onIdentity: id = the own ID or null, name = the own chain name ('' =
// none), closed = its 4th argument. The chain name first, then the short ID;
// with no ID, why: Messages closed with a reason while the wallet is open,
// else the wallet is locked or Messages is still opening. Pure;
// test/connect-ui.test.js pins it.
export const OWN_ID_WAITING_TEXT = 'Appears when your wallet is open';
export const OWN_ID_CLOSED_TEXT = 'Messages could not open';
export function ownIdText({ id = null, name = '', closed = false } = {}) {
  if (id) return name ? `${name} · ${shortId(id)}` : shortId(id);
  return closed === true ? OWN_ID_CLOSED_TEXT : OWN_ID_WAITING_TEXT;
}

// ── view: the one-time DOM ─────────────────────────────────────────────
// root: an empty element of the host page. Every host callback is optional:
//   onUnread(n)      the total of unread messages (a navigation badge);
//   onRequests(n)    contact requests waiting for an answer;
//   onIdentity(fp, name, avatarBase64, closed)   the own ID while Messages is
//                    open, else null; with the own verified name and picture
//                    ('' if none); closed: true while fp is null because
//                    Messages is closed with a reason (closeMessages: the
//                    wallet is open but Messages failed to open — the
//                    identity unlock, the local open, a history that did not
//                    answer in 15 s — or closed since), false while it is
//                    waiting or opening (resetMessages on lock sets it back
//                    to false); ownIdText makes the host's ID line from these;
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
    openLocal(gen).catch(error => { if (gen === generation) closeMessages(explain(error, LOCAL_FAILED_TEXT), { retry: true }); });
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
  // Groups (package G3, src/connect/groups/ui.js): invitations, group rows
  // and "New group" above the conversations; a group's conversation in the
  // pane; the New group dialog.
  groupsView = createGroupsView({
    engine: () => groups, isOpen, online: () => online, ownFp: () => ownFp, contacts: () => (state ? state.contacts : []),
    el, button, untrusted, statusLine, input, setAttrs, icon, iconButton, backButton,
    nameTitle, nameHint: fp => nameHint(fp), displayName, shortWhen, dayLabel, sameDay, explain,
    openGroup, render
  });
  u.chatsBody = el('div', { className: 'nc-chats-body' }, u.chipRow, u.requestsBanner, groupsView.block, u.contactList);
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
  // The last message check of this contact (diag.js), collapsed; plain text.
  u.convDiagText = el('p', { className: 'conversation-diag-text' });
  u.convDiag = el('details', { className: 'hint conversation-diag' }, el('summary', { text: 'Details' }), u.convDiagText);
  u.convDiag.hidden = true;
  u.messageList = setAttrs(el('ol', { className: 'message-list' }), { 'aria-label': 'Messages', 'aria-live': 'polite' });
  u.composer = input('textarea', { id: 'nc-send-text', rows: '1', maxlength: String(TEXT_MAX), placeholder: 'Write a message', 'aria-label': 'Message', autocomplete: 'off' });
  u.sendButton = el('button', { className: 'composer-send' }); u.sendButton.type = 'submit';
  u.sendButton.setAttribute('aria-label', 'Send'); u.sendButton.title = 'Send';
  u.sendButton.append(icon('send'));
  u.counter = el('small', { className: 'composer-counter' });
  u.sendStatus = statusLine('hint composer-status');
  // While the network phase has not finished (online): the composer keeps
  // what is typed, Send waits.
  u.offlineNote = el('p', { className: 'hint composer-status', text: OFFLINE_SEND_TEXT });
  u.sendForm = el('form', { className: 'composer' }, el('div', { className: 'composer-row' }, u.composer, u.sendButton), el('div', { className: 'composer-foot' }, el('small', { className: 'composer-hint', text: 'Enter to send · Shift+Enter for a new line' }), u.counter), u.offlineNote, u.sendStatus);
  u.sendForm.id = 'nc-send-form';
  u.notReady = el('p', { className: 'hint composer-closed', text: 'Messaging with this contact is not ready yet. It is checked again automatically.' });
  u.conversationView = el('div', { className: 'messenger-view messenger-conversation' }, u.convHead, u.convNote, u.convDiag, u.messageList, u.sendForm, u.notReady);
  u.pane = el('div', { className: 'messenger-pane' }, u.emptyView, u.conversationView, groupsView.view);

  // Add contact (add_contact_dialog.dart): a modal dialog.
  u.addHeading = el('h2', { text: 'Add a contact' });
  u.addHeading.id = 'nc-add-title';
  u.addId = input('input', { id: 'nc-add-id', type: 'text', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', maxlength: '256', required: '' });
  u.addNote = input('input', { id: 'nc-add-note', type: 'text', maxlength: '200', autocomplete: 'off' });
  u.addStatus = statusLine();
  u.addSubmit = el('button', { text: ADD_SUBMIT_TEXT }); u.addSubmit.type = 'submit';
  // A chain name's lookup result, shown before the request may be sent
  // (addContact): the name, the ID it belongs to, and the wallet's caution.
  u.addResolvedText = el('span', { className: 'own-id-label' });
  u.addResolvedId = el('code', { className: 'own-id' });
  u.addResolved = el('div', { className: 'own-id-box' }, u.addResolvedText, u.addResolvedId, el('p', { className: 'hint', text: NAME_CHECK_TEXT }));
  u.addResolved.hidden = true;
  u.addForm = el('form', { className: 'messenger-form' },
    ...field('nc-add-id', 'Their ID or chain name', u.addId),
    el('p', { className: 'hint', text: 'An ID is 128 characters, letters a–f and digits. Ask them to copy it from “Your ID & profile”. A chain name is 3 to 36 letters a–z and digits; it is looked up and shown to you before the request is sent.' }),
    u.addResolved,
    ...field('nc-add-note', 'Note (optional, they see it with your request)', u.addNote),
    u.addStatus,
    el('div', { className: 'nc-dialog-actions' }, button('Close', () => u.addDialog.close(), 'secondary'), u.addSubmit));
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
  // A contact is removed on this device only (removeContactAction).
  u.contactsStatus = statusLine('hint contacts-status');
  u.hubContacts = el('div', { className: 'nc-scroll' }, u.contactsStatus, u.hubList);
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
  u.layout = el('div', { className: 'messenger' }, u.chats, u.pane, u.contactsView, u.profileView, u.addDialog, groupsView.dialog);
  root.replaceChildren(u.layout);
  ui = u;

  u.addForm.onsubmit = event => void addContact(event);
  // Any change to what is typed drops a shown lookup result: the request
  // goes only to the name that was looked up and shown.
  u.addId.addEventListener('input', () => { if (addResolved) { addResolved = undefined; showAddResolved(); ui.addStatus.textContent = ''; } });
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
  if (next !== 'conversation') { selectedFp = undefined; groupsView?.close(); }
  if (next !== 'contacts' && removeArmed) { removeArmed = undefined; ui.contactsStatus.textContent = ''; }
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
  addResolved = undefined; showAddResolved();
  if (!ui.addDialog.open) ui.addDialog.showModal();
  ui.addId.focus();
}

// A group's conversation (src/connect/groups/ui.js), in the pane like a
// contact's.
function openGroup(gid) {
  if (!isOpen() || !groups?.view(gid)) return;
  selectedFp = undefined;
  groupsView.open(gid);
  screen = 'conversation';
  render({ scroll: true });
  groupsView.focus();
}

function selectContact(fp) {
  groupsView?.close();
  selectedFp = fp; screen = 'conversation';
  ui.sendStatus.textContent = '';
  markRead(fp);
  render({ scroll: true });
  (contactOf(fp)?.salt ? ui.composer : ui.convTitle).focus({ preventScroll: true });
  void recheckChainNameOnOpen(fp);
}

function setCount(node, count) {
  node.textContent = count ? (count > 99 ? '99+' : String(count)) : '';
  node.hidden = !count;
}

function render({ scroll = false } = {}) {
  if (!ui) return;
  const open = isOpen();
  // A group's conversation is open (src/connect/groups/ui.js); a group that
  // was left is not shown any more.
  const shownGroup = open && screen === 'conversation' && groupsView?.selected ? groups?.view(groupsView.selected) : null;
  const groupOpen = !!shownGroup && shownGroup.status !== 'left';
  // Closed: Chats only. A conversation whose contact is gone: back to Chats.
  if ((!open && screen !== 'list') || (screen === 'conversation' && !groupOpen && !(selectedFp && contactOf(selectedFp)))) { screen = 'list'; selectedFp = undefined; groupsView?.close(); }
  // data-screen drives the layout (messenger.css); data-open the closed state.
  ui.layout.dataset.screen = screen;
  ui.layout.dataset.open = String(open);
  ui.stateView.hidden = open;
  ui.chatsBody.hidden = !open;
  ui.fab.hidden = !open;
  ui.emptyView.hidden = screen !== 'list';
  ui.conversationView.hidden = screen !== 'conversation' || groupOpen;
  ui.contactsView.hidden = screen !== 'contacts';
  ui.profileView.hidden = screen !== 'profile';
  for (const control of [ui.requestsAction, ui.profileAction]) control.disabled = !open;
  if (open && screen === 'conversation' && !groupOpen) markRead(selectedFp);
  // The group conversation is drawn first, so its read mark counts below.
  if (groupOpen) groupsView.renderView({ scroll });
  groupsView.view.hidden = !groupOpen;
  const unread = open ? state.contacts.reduce((sum, c) => sum + unreadCount(c.fp), 0) + groupsView.unreadTotal() : 0;
  const waiting = open ? requests.length : 0;
  renderCounts(unread, waiting);
  renderEmpty(open);
  if (open) {
    renderChats();
    if (screen === 'contacts') renderContacts();
    if (screen === 'conversation' && !groupOpen) renderConversation(scroll);
  }
  host.onUnread?.(unread);
  host.onRequests?.(waiting);
  const id = open ? ownFp : null;
  // The own CHAIN name (HF-4, dnac_name_of) travels with the ID; the
  // profile name is shown only on the profile screen, labelled.
  const ownName = open ? chainNameOf(ownFp) : '';
  const ownAvatar = open && typeof ownProfile?.avatar_base64 === 'string' ? ownProfile.avatar_base64 : '';
  // Closed (phase 'closed': the wallet is open but Messages failed to open,
  // or closed since) is told apart from waiting / opening, so the host can
  // say so instead of "appears when your wallet is open" (ownIdText).
  const closed = !id && phase === 'closed';
  const idKey = id ? `${id}|${ownName}|${ownAvatar}` : (closed ? 'closed' : null);
  if (idKey !== notifiedId) { notifiedId = idKey; host.onIdentity?.(id, ownName, ownAvatar, closed); }
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
  // Groups above the conversations; the 'chats' chip shows one-to-one
  // conversations only.
  groupsView.renderBlock({ unreadOnly: filter === 'unread' });
  if (filter === 'chats') groupsView.block.hidden = true;
  if (!state.contacts.length) {
    ui.contactList.replaceChildren(el('li', { className: 'contact-empty', text: 'No contacts yet. Add one with their ID or chain name using the add-contact button.' }));
    return;
  }
  // Most recent conversation first (local order), then contacts without
  // messages in list order; ties keep the list order (stable sort).
  const ordered = state.contacts.map((c, index) => ({ c, index, last: lastMessage(c.fp) }))
    .sort((a, b) => (a.last && b.last ? compareLocal(b.last, a.last) : a.last ? -1 : b.last ? 1 : 0) || a.index - b.index);
  // 'chats' shows the same conversations as 'all', without the groups.
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
    row.append(avatar(c.fp), el('span', { className: 'contact-main' }, el('span', { className: 'contact-name' }, nameTitle(c.fp)), nameHint(c.fp), preview), side, icon('chevron'));
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
  if (removeArmed && !contactOf(removeArmed)) removeArmed = undefined;
  ui.hubList.replaceChildren(...(state.contacts.length ? state.contacts.map(c => {
    const row = el('button', { className: 'contact-row' });
    row.type = 'button';
    row.dataset.fp = c.fp;
    const sub = el('span', { className: 'contact-preview', text: c.salt ? 'Open conversation' : 'Messaging is not ready yet' });
    row.append(avatar(c.fp), el('span', { className: 'contact-main' }, el('span', { className: 'contact-name' }, nameTitle(c.fp)), nameHint(c.fp), sub), icon('chevron'));
    row.onclick = () => selectContact(c.fp);
    // Remove asks once more before it acts (as "Delete message history").
    const armed = removeArmed === c.fp;
    const remove = button(armed ? 'Confirm: remove this contact' : 'Remove contact', () => void removeContactAction(c.fp), `secondary small contact-remove${armed ? ' contact-remove-armed' : ''}`);
    remove.setAttribute('aria-label', armed ? `Confirm: remove ${displayName(c.fp)}` : `Remove ${displayName(c.fp)}`);
    const actions = el('div', { className: 'contact-actions' }, remove);
    if (armed) actions.append(button('Keep', () => { removeArmed = undefined; ui.contactsStatus.textContent = ''; render(); }, 'secondary small'));
    return el('li', { className: 'contact-item' }, row, actions);
  }) : [el('li', { className: 'contact-empty', text: 'No contacts yet. Add one with their ID or chain name.' })]));
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
  const names = namesOf(contact.fp);
  ui.convTitle.replaceChildren(titleContent(names));
  ui.convTitle.classList.toggle('chain-name', names.verified);
  const claim = nameHint(contact.fp);
  ui.convClaim.replaceChildren(...(claim ? claim.childNodes : []));
  const lost = dropped.get(contact.fp), other = others.get(contact.fp);
  ui.convNote.textContent = [
    lost ? 'Some messages from this contact could not be checked and are not shown.' : '',
    other ? 'This contact also sent items this page cannot show yet (for example reactions, pictures or calls).' : ''
  ].filter(Boolean).join(' ');
  ui.convNote.hidden = !ui.convNote.textContent;
  ui.convDiagText.textContent = diagText(diags.get(contact.fp));
  ui.convDiag.hidden = !ui.convDiagText.textContent;
  ui.sendForm.hidden = !contact.salt;
  ui.notReady.hidden = !!contact.salt;
  ui.sendButton.disabled = !online || sending;
  ui.offlineNote.hidden = online;

  const items = [];
  let day;
  for (const m of messages.filter(x => x.fp === contact.fp && !isControl(x)).sort(compareLocal)) {
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
  // A name kept on this device is shown at once, without the confirmed
  // mark, until this session's lookup confirms it (ensureChainName).
  const chain = chainNameOf(ownFp);
  line.append(chain
    ? el('span', {}, 'Your chain name: ', el('strong', { className: ownNameConfirmed ? 'chain-name' : '', text: chain }), ownNameConfirmed ? '' : ' (saved on this device)')
    : 'You have no chain name.', el('br'));
  if (p.name) line.append('Your profile name (in the network directory, not on the chain): ', untrusted(p.name, undefined, { name: true }));
  else if (p.claimed_name) line.append('Name on your profile (not verified — its lookup record does not point to you): ', untrusted(p.claimed_name, undefined, { name: true }));
  else line.append('Your profile has no name.');
  if (p.website) { const link = website(p.website); if (link) line.append(el('br'), 'Website: ', link); }
}

// ── actions ────────────────────────────────────────────────────────────
async function accept(request) {
  const gen = generation;
  if (!online) { ui.requestsStatus.textContent = 'Requests can be answered once Messages is connected to the network.'; return; }
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
  if (!online) { ui.requestsStatus.textContent = 'A request can be withdrawn once Messages is connected to the network.'; return; }
  try {
    await core.requestCancel(fp);
    if (gen !== generation) return;
    state.outgoing = state.outgoing.filter(o => o.fp !== fp);
    await persist();
    if (gen === generation) { ui.requestsStatus.textContent = 'Request withdrawn.'; render(); }
  } catch (error) { if (gen === generation) ui.requestsStatus.textContent = explain(error, 'Withdrawing failed. Try again in a minute.'); }
}

// "Remove contact" (the app's dna_handle_remove_contact, dna_engine_contacts.c:
// 205-270, without its network half): pressed once it asks to confirm, the
// second press removes the contact ON THIS DEVICE (text.js removeContact).
// The messages with them stay on this device (hidden; shown again if they
// are added again). The own contact list on the network is NOT rewritten:
// the core only adds to it (nc_core.h nc_contactlist_add, merge-only), so
// other devices and the DNA Connect app keep listing the person; this
// device remembers the removal (state.removed) and does not take them back
// from that list.
async function removeContactAction(fp) {
  if (!isOpen() || !contactOf(fp)) return;
  if (removeArmed !== fp) {
    removeArmed = fp;
    ui.contactsStatus.textContent = 'Remove this contact from this device? Your messages with them stay on this device and come back if you add them again. Your other devices and the DNA Connect app still list them.';
    render();
    return;
  }
  removeArmed = undefined;
  const name = displayName(fp);
  removeContact(state, fp);
  for (const map of [unpublished, saltChecked, dropped, others, lastRead, diags, chainNames, chainAsked, chainTried, kept, profiles]) map.delete(fp);
  for (const key of [...blobs.keys()]) if (key.startsWith(`${fp}|`)) blobs.delete(key);
  if (selectedFp === fp) selectedFp = undefined;
  render();
  notifyVaultHost();
  try {
    await persist();
    if (isOpen()) ui.contactsStatus.textContent = `${name} was removed from your contacts on this device.`;
  } catch (error) {
    if (isOpen()) ui.contactsStatus.textContent = `${name} was removed for now, but this device could not save the change (${error instanceof StorageError ? error.message : 'storage failed'}). They may come back after you lock.`;
  }
}

// The add dialog's chain-name result (addResolved): shown, with the button
// naming who the request goes to, or hidden with the plain button.
function showAddResolved() {
  if (!ui) return;
  const r = addResolved;
  ui.addResolved.hidden = !r;
  ui.addResolvedText.textContent = r ? `${r.name} belongs to ${shortId(r.owner)}. Full ID:` : '';
  ui.addResolvedId.textContent = r ? r.owner : '';
  ui.addSubmit.textContent = r ? `Send request to ${r.name}` : ADD_SUBMIT_TEXT;
}

// Add a contact by ID, or by chain name in two presses: the first only looks
// the name up (chain-names.js resolveContactName — the wallet's NODUS-send
// lookup) and shows the name, the ID it belongs to and the wallet's
// look-alike caution; the button then reads "Send request to <name>" and the
// next press sends to that ID. A request never goes to a name the user has
// not seen resolved; editing the box drops the shown result. The owner ID
// is checked like a typed ID (own ID, already a contact, already requested)
// before it is shown and again before sending.
async function addContact(event) {
  event.preventDefault();
  const gen = generation;
  try {
    const typed = parseContactInput(ui.addId.value);
    let fp = typed.fp;
    if (typed.name) {
      if (!addResolved || addResolved.name !== typed.name) {
        addResolved = undefined; showAddResolved();
        const asked = ui.addId.value;
        ui.addStatus.textContent = 'Looking up the name…';
        const found = await resolveContactName(nodusClient, typed.name);
        if (gen !== generation) return;
        // The box changed while the lookup ran: this answer is not for it.
        if (ui.addId.value !== asked) { ui.addStatus.textContent = ''; return; }
        const refusal = requestRefusal(found.owner, { ownFp, isContact: !!contactOf(found.owner), isRequested: state.outgoing.some(o => o.fp === found.owner) });
        if (refusal) throw new Error(refusal);
        addResolved = { name: found.name, owner: found.owner };
        showAddResolved();
        ui.addStatus.textContent = `Check the name and the ID above, then press “Send request to ${found.name}”.`;
        return;
      }
      fp = addResolved.owner;
    }
    const refusal = requestRefusal(fp, { ownFp, isContact: !!contactOf(fp), isRequested: state.outgoing.some(o => o.fp === fp) });
    if (refusal) throw new Error(refusal);
    if (!online) throw new Error('Requests can be sent once Messages is connected to the network.');
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
    addResolved = undefined; showAddResolved();
    ui.addStatus.textContent = 'Request sent. They appear in your contacts once they accept.';
    render();
  } catch (error) { if (gen === generation) { ui.addStatus.textContent = error.message; logFailure('A contact request was not sent', error); } }
}

async function send(event) {
  event.preventDefault();
  // One send at a time: the text is taken from the composer, which is
  // cleared only once the message is kept on this device (persist). A second
  // Enter or click meanwhile would take the same text again and send it twice.
  if (sending) return;
  const gen = generation, contact = selectedFp && contactOf(selectedFp);
  const text = ui.composer.value;
  if (!contact || !contact.salt || !text.trim()) return;
  if (!online) { ui.sendStatus.textContent = OFFLINE_SEND_TEXT; return; }
  if (text.length > TEXT_MAX) { ui.sendStatus.textContent = `A message can be at most ${TEXT_MAX} characters.`; return; }
  sending = true; ui.sendButton.disabled = true;
  try {
    const message = { seq: takeSeq(), fp: contact.fp, dir: 'out', text, ts: nowSeconds(), at: Date.now() };
    await persist([message]);
    if (gen !== generation) return;
    messages.push(message); unpublished.add(contact.fp);
    ui.composer.value = ''; growComposer();
    // Kept and the composer is empty: the next message may be written and
    // sent while this one is published (retried by sync if it fails).
    sending = false;
    render({ scroll: true });
    try { await publishOutbox(contact, gen); if (gen === generation) ui.sendStatus.textContent = ''; }
    catch (error) { if (gen === generation) { ui.sendStatus.textContent = 'Not sent yet. It is tried again automatically.'; logFailure('A message was not sent yet; it is tried again automatically', error); } }
    if (gen === generation) render();
  } catch (error) { if (gen === generation) { ui.sendStatus.textContent = error.message; logFailure('A message could not be kept on this device', error); } }
  finally { if (gen === generation && sending) { sending = false; ui.sendButton.disabled = !online; } }
}

async function saveProfile(event) {
  event.preventDefault();
  const gen = generation;
  if (profileTaken) return;
  if (!online) { ui.profileStatus.textContent = 'Your profile can be saved once Messages is connected to the network.'; return; }
  try {
    const patch = profilePatch({ bio: ui.bio.value, location: ui.location.value, website: ui.website.value });
    ui.profileStatus.textContent = 'Saving…';
    const result = await core.profileUpdate(patch);
    if (gen !== generation) return;
    ui.profileStatus.textContent = profileStatusText(result.status);
    if (result.status === 'published') { ownProfile = { ...(ownProfile || {}), ...patch }; fillProfile(); }
    if (result.status === 'taken') profileTaken = true;
  } catch (error) { if (gen === generation) { ui.profileStatus.textContent = /https|Invalid profile/.test(error.message) ? error.message : 'Saving failed. Try again later.'; logFailure('Saving the profile failed', error); } }
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
  if (!online) { ui.avatarStatus.textContent = 'Your picture can be saved once Messages is connected to the network.'; return; }
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
  if (!online) throw new Error(OFFLINE_SEND_TEXT);
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

// ── the groups module's use of Messages (src/connect/groups/) ──────────
// A group invite / accept / welcome / leave to one contact: kept on this
// device as a 1:1 message flagged `control` (never shown), then published
// with that contact's pending set — the 30-second check publishes it again
// until it is delivered, as any 1:1 message.
async function sendControl(fp, text) {
  if (!isOpen()) throw new Error('Messages is not open.');
  if (!online) throw new Error(OFFLINE_SEND_TEXT);
  const gen = generation, contact = contactOf(fp);
  if (!contact?.salt) throw new Error('Messaging with this contact is not ready yet.');
  if (typeof text !== 'string' || !text || text.length > PAYLOAD_TEXT_MAX) throw new Error('Invalid group message.');
  const message = { seq: takeSeq(), fp, dir: 'out', text, ts: nowSeconds(), at: Date.now(), control: true };
  await persist([message]);
  if (gen !== generation) throw new Error('Messages is not open.');
  messages.push(message); unpublished.add(fp);
  try { await publishOutbox(contact, gen); } catch { /* retried by sync */ }
}
// A fresh owner-filtered read of a profile: its keys go back into the
// module's verified cache (64 entries, connect/nc_wasm.c) before a group
// key packet is built or a sender's messages are checked.
async function reloadProfile(fp) {
  if (fp === ownFp) return true;
  const result = await core.profileGet(fp);
  if (result.outcome !== 'found') return false;
  profiles.set(fp, result.profile);
  return true;
}

async function keepVault(address, value) {
  if (!isOpen()) throw new Error('Messages is not open.');
  if (typeof address !== 'string' || !VAULT_ADDRESS.test(address) || !value || typeof value !== 'object') throw new Error('Invalid vault.');
  const before = state.vaults[address];
  const id = before?.id || `v${takeSeq().padStart(20, '0')}`;
  const entry = { id, at: nowSeconds() };
  state.vaults[address] = entry;
  try {
    await store.save(state, [], [], [{ id, address, value }]);
  } catch (error) {
    // roll back only this call's own entry: a dropVault (or another
    // keepVault) that ran during the save stands as it left it
    if (state.vaults[address] === entry) {
      if (before) state.vaults[address] = before; else delete state.vaults[address];
    }
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
  messages: () => (isOpen() ? messages.filter(m => !isControl(m)).map(m => ({ fp: m.fp, dir: m.dir, text: m.text, at: m.at, seq: String(m.seq) })) : []),
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
  // LOCAL FIRST (src/app.js startNodusSend): the wallet's client is
  // identified — Messages opens from what this device keeps. Asked with
  // gather: the answer is the local open's promise, and the wallet connects
  // only after it settled (one queue: the local steps are not held behind
  // the connection's network waits). openMessages never rejects.
  nodusIdentified(detail) { return [openMessages(detail)]; },
  // The client is ready: the network phase of the Messages opened on THIS
  // client starts (if its local open is still running, it starts at its
  // end, openLocal); any other client opens Messages anew.
  nodusReady(detail) {
    if (core && nodusClient && nodusClient === detail?.client) { if (isOpen()) goOnline(generation); return; }
    // Only a host that hands over the words opens anew (src/app.js does);
    // a bare "ready" (the preview page's connectLoop) after Messages closed
    // keeps the reason already shown.
    if (typeof detail?.phrase === 'string') void openMessages(detail);
  },
  // A connection attempt of the identified client failed; the wallet tries
  // again by itself on the same client. The view stays; the reason is shown
  // in the status line (plain words from the wallet).
  nodusConnectFailed({ reason } = {}) { if (ui && isOpen() && !netStarted && typeof reason === 'string' && reason) ui.sync.textContent = reason; },
  // reason: the connection was lost (Messages stays closed until the
  // wallet's reconnect raises nodusReady again); none: the wallet is
  // locking or reconnecting.
  nodusClosing({ reason } = {}) { if (reason) closeMessages(reason); else resetMessages(); },
  nodusUnavailable() { closeMessages(UNAVAILABLE_TEXT); },
  // The saved wallet (and with it this history, src/app.js vault-delete) is
  // being deleted: the open store must not hold the database.
  vaultDeleting() { if (store?.persistent) closeMessages('The saved wallet and its message history were deleted from this device. Lock and open your wallet again to use Messages.'); },
  locked() { resetMessages(); },
  // The wallet's send form asks for recipients it may offer (src/app.js,
  // wallet-extensions.js gather): a contact's ID IS its NODUS address (the
  // core refuses an identity whose fingerprint differs from the NODUS
  // client's, core.js unlock; the NODUS adapter checks the address against
  // that fingerprint, src/adapters/nodus.js balances), so contacts are
  // offered for NODUS only. The label is the chain name or the short ID —
  // never a profile name or a claim (an <option> cannot carry the
  // unusual-characters marker).
  recipients({ network } = {}) {
    if (network !== 'nodus' || !isOpen()) return [];
    return state.contacts.map(c => ({ label: displayName(c.fp), address: c.fp }));
  }
};
