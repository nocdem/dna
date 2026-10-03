// The Messages preview page (/preview/, package NC-4c) as the HOST of
// src/connect/ui/messages.js. This page has its own unlock screens (saved
// wallet password / 24 words / new account) because it is not the wallet;
// the Nodus Connect site (src/connect-main.js) uses the wallet as host
// instead. /preview/ is removed from the wallet site once
// connect.nodusnetwork.io is live (decision 2026-10-01-connect-own-origin.md).
//
// One page = one module = one session (NC-4b): this page creates the
// wallet's own NODUS client (src/nodus/client.js createNodusClient with
// src/nodus/send-module.js nodusSendModuleFactory — the module that also
// carries the Messages exports), identifies it with the signing seed and
// the locally derived address as src/app.js startNodusSend does, hands it to
// Messages (messages.js openMessages: what this device keeps is shown
// first), then connects it (connectLoop: a failed attempt is retried on the
// same client).
//
// Lifecycle (§1.8): the page opens only while this tab holds the wallet's
// single-tab Web Lock `nodus.wallet.session` (src/app.js pattern); 10 minutes
// without input, a manual Lock, `pagehide`, a change of the saved wallet, or
// the client failing ('error' / 'locked') locks it. Lock order: Messages (resetMessages:
// sync stops -> core.lock() -> history store closed -> data dropped) ->
// client.lock() (queue stops, cancel, WebSocket closed, module memory
// zeroed, instance released) -> THEN the Web Lock is released.
import { Mnemonic, randomBytes } from 'ethers';
import { VAULT_KEY, decryptVault } from '../../vault.js';
import { normalizePhrase, validateNodusPhrase } from '../../recovery.js';
import { nodusSendModuleFactory } from '../../nodus/send-module.js';
import { createNodusClient } from '../../nodus/client.js';
import { deriveNodusAddress, nodusSigningSeed } from '../../nodus/derive.js';
import { mountMessages, openMessages, resetMessages, walletExtension } from './messages.js';
import { el } from './dom.js';

const $ = id => document.getElementById(id);
const IDLE_MS = 10 * 60 * 1000;          // src/app.js idle lock
const SCREENS = ['nc-start', 'nc-unlock-form', 'nc-words-form', 'nc-create-form', 'nc-open'];

let client, opening = 0, sessionRelease, idleTimer, idleDeadline = 0, newPhraseText;

function status(text) { $('nc-status').textContent = text; }
function show(id) { for (const screen of SCREENS) $(screen).hidden = screen !== id; }

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
  opening++;
  clearTimeout(idleTimer); idleTimer = undefined; idleDeadline = 0;
  resetMessages();
  const c = client; client = undefined;
  try { c?.lock(); } catch { /* the rest of the lock must still run */ }
  newPhraseText = undefined;
  for (const id of ['nc-password', 'nc-words', 'nc-new-words-check']) $(id).value = '';
  $('nc-new-words').replaceChildren();
  $('nc-lock').hidden = true;
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
  const sensitive = client || sessionRelease || !$('nc-words-form').hidden || !$('nc-create-form').hidden || !$('nc-unlock-form').hidden;
  if (sensitive) { idleDeadline = Date.now() + IDLE_MS; idleTimer = setTimeout(() => lock('Messages locked after 10 minutes without activity.'), IDLE_MS); }
}

// ── open ───────────────────────────────────────────────────────────────
class Closed extends Error {}

// getPhrase runs only after this tab holds the session lock. Every form is
// hidden (show(null)) before this starts, so nothing can start a second
// open while this one runs; should one start anyway, `opening` moves and
// this one locks the client it built.
async function open(getPhrase, { persistent, isFresh }) {
  const leftClient = client; client = undefined;
  resetMessages();
  try { leftClient?.lock(); } catch { /* nothing left to do */ }
  const run = ++opening;
  status('Opening Messages…');
  let seed, built;
  const superseded = () => {
    if (run === opening) return false;
    if (built && built !== client) { try { built.lock(); } catch { /* nothing left to do */ } }
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
    built = createNodusClient({
      factory: nodusSendModuleFactory,
      // Once open, a client that fails ('error': its keepalive failed, or a
      // node of another chain) or locks from inside ends the page. A failed
      // connection attempt returns to 'identified' and is tried again
      // (connectLoop); before the page opened, the catch below reports.
      onState: next => { if (built === client && (next === 'error' || next === 'locked')) lock('The connection to the network was lost. Unlock again to continue.'); }
    });
    seed = nodusSigningSeed(phrase);
    // LOCAL FIRST: the identity only (no session); Messages opens from what
    // this device keeps, THEN the connection is made (one queue: a
    // connection attempt queued first would hold the local steps).
    await built.identify({ seed, fingerprint: address });
    if (superseded()) return;
    client = built;
    $('nc-lock').hidden = false;
    show('nc-open'); status('');
    activity();
    // Only words generated in this tab, this session, are "fresh" (Q1).
    await openMessages({ client, phrase, vaultId: persistent ? id : null, fresh: isFresh });
    if (superseded()) return;
    void connectLoop(run, built);
  } catch (error) {
    if (superseded()) return;
    // The identity never opened: back to the start, nothing kept.
    lock(error instanceof Closed || /password|phrase|words/i.test(error.message) ? error.message : 'Messages could not connect right now. Try again in a minute.');
  } finally { seed?.fill(0); }
}

// The connection of an identified client, tried again on the SAME client
// after a fixed, growing wait (src/app.js RECONNECT) while this open is the
// current one; Messages keeps what it shows meanwhile. Success: Messages'
// network phase starts (messages.js walletExtension.nodusReady). A final
// refusal locks the client, and onState above locks the page.
const RETRY_MS = [5000, 10000, 20000, 40000, 60000];
async function connectLoop(run, built) {
  for (let attempt = 0; run === opening && built === client; attempt++) {
    try {
      await built.connectNetwork();
      if (run === opening && built === client) walletExtension.nodusReady({ client: built });
      return;
    } catch {
      if (run !== opening || built !== client || !built.identified) return;
      const wait = RETRY_MS[Math.min(attempt, RETRY_MS.length - 1)];
      walletExtension.nodusConnectFailed({ reason: `Not connected to the network right now; trying again in ${wait / 1000} seconds. Your messages on this device are shown.` });
      await new Promise(resolve => { setTimeout(resolve, wait); });
    }
  }
}

// ── wiring ─────────────────────────────────────────────────────────────
export function startStandalone() {
  mountMessages($('nc-root'));
  for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, activity);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) expireIdle(); });
  window.addEventListener('focus', expireIdle);
  window.addEventListener('pagehide', () => lock());
  // A saved wallet changed or removed in another tab (src/app.js does the same).
  window.addEventListener('storage', event => { if ((event.key === VAULT_KEY || event.key === null) && (client || sessionRelease)) lock('Saved wallet changed in another tab. Unlock again to continue.'); });

  for (const cancel of document.querySelectorAll('.nc-cancel')) cancel.onclick = () => lock('');
  $('nc-lock').onclick = () => lock();

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
  // submitted again while "Opening Messages…" runs.
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
    void open(async () => ({ phrase, id: null }), { persistent: false, isFresh: true });
  };
  showStart();
}
