import { getAddress } from 'ethers';
import { VAULT_KEY, ACTIVITY_KEY, parseVault, encryptVault, decryptVault, validateNewPassword } from './vault.js';
import { serializeActivity, parseActivity, activityKeyFor } from './activity-storage.js';
import { recordActivity, watchActivity, terminal } from './activity.js';
import { CHAINS, CELLFRAME } from './config.js';
import { CPUNK_ASSET } from './portfolio.js';
// Pure data, referenced only inside `if (import.meta.env.VITE_ENABLE_IXIOS === 'true')`
// blocks below, so a disabled build tree-shakes the whole module away.
import { IXIOS_NETWORK, IXIOS_ASSET } from './ixios/network.js';
import { NODUS_NETWORK, NODUS_ASSET } from './nodus/network.js';
import { deriveWallet, disposeWallet, newPhrase, normalizePhrase } from './keys.js';
import { adapters, prepareTransfer } from './wallet.js';
import { endpointUrl } from './core.js';
import { createPhraseFields } from './phrase-fields.js';
import { createPortfolio } from './portfolio-view.js';
import { renderQr } from './qr.js';
const $ = id => document.getElementById(id);
// Must equal the src/style.css media query that sets `.dashboard-grid` to one
// column (`@media (max-width: 900px)`): below it the Send / Receive panel sits
// under the asset list, off screen after a row click.
const SINGLE_COLUMN_DASHBOARD = '(max-width: 900px)';
// The only writer of #receive-address: the QR below it always encodes exactly
// the text shown (empty text, e.g. after lock or before a derivation settles,
// clears the QR).
function setReceiveAddress(text) { $('receive-address').textContent = text; renderQr($('receive-qr'), text); }
const phraseFields = createPhraseFields($('phrase-grid'), $('phrase-error'));
// Build-time flag: whether Cellframe/CPUNK appears in the network list, the
// endpoint map and the portfolio at all. This is a plain boolean used only for
// data (an <option>, an endpoint entry, a constructor argument) and never
// gates a dynamic import directly — see the top-level `if (import.meta.env...)`
// block further down for why that distinction matters for bundle size.
const CPUNK_ENABLED = import.meta.env.VITE_ENABLE_CPUNK !== 'false';
let wallet, pending, generatedPhrase, phraseStep, revision = 0, busy = false, lockTimer, idleDeadline = 0, confirmEnableTimer;
const DEFAULT_PHRASE_ENTRY_HELP = '24 words, in order. Paste your full phrase into any box to fill all 24. Start typing for local word suggestions; choose with the arrow keys and Enter, or tap a word.';
let cellframeDerivation, cellframeReader, nodusDerivation;
// Set only inside the VITE_ENABLE_IXIOS blocks below; undefined/no-ops in a
// disabled build (so no Ixios string literal is needed outside those blocks).
let doShowIxiosAddress, stopIxiosAddress = () => {}, ixiosChain, ixiosReader;
// Receive-panel derivation status line per receive-only network, shown only
// while that network is selected. The Ixios entry is added by its flag block.
const addressStatus = { nodus: $('nodus-address-status'), cellframe: $('cellframe-address-status') };
// index.html's #send-disabled-note text is Cellframe's; a network may carry its own `sendNote`.
const DEFAULT_SEND_DISABLED_NOTE = $('send-disabled-note').textContent;
let activitySession = null, activityBlocked = false, historyWrites = Promise.resolve(), vaultOperation = 0;
const history = []; let stopTracking = () => {};
function withActivityLock(write) {
  if (!navigator.locks) return Promise.reject(new Error('This browser cannot safely save wallet activity across tabs. Use a browser with Web Locks support.'));
  return navigator.locks.request('nodus.wallet.storage', write);
}
// Single-tab rule (decision 2026-09-23-web-wallet-single-tab): a wallet opens
// only in the tab holding the exclusive `nodus.wallet.session` Web Lock, and
// that tab holds it until lock(). The browser releases it when the tab closes
// or crashes, so no timer, storage flag or heartbeat is involved.
// sessionRelease: resolves the promise that keeps this tab's lock held.
// sessionRequest: an in-flight request shared by concurrent open attempts.
// sessionClaims: open attempts in flight; the last one to finish without an
// open wallet gives the lock back, so a failed open never keeps it.
// sessionEnded: settles once this tab's previous request is over — for a held
// lock, after the lock manager has released it — so a lock-then-reopen in this
// tab never finds its own just-released hold still in place and refuses itself.
let sessionRelease, sessionRequest, sessionClaims = 0, sessionConflictFlow, sessionEnded = Promise.resolve();
function releaseSession() { const release = sessionRelease; sessionRelease = undefined; release?.(); }
function requestSession({ steal = false } = {}) {
  if (sessionRelease) return Promise.resolve(sessionRelease);
  if (sessionRequest && !steal) return sessionRequest;
  if (!navigator.locks) return Promise.reject(new Error('This browser cannot keep the wallet open in only one tab. Use a browser with Web Locks support.'));
  const request = sessionEnded.then(() => new Promise((granted, failed) => {
    let mine;
    // steal cannot be combined with ifAvailable.
    sessionEnded = navigator.locks.request('nodus.wallet.session', steal ? { steal: true } : { ifAvailable: true }, held => {
      if (!held) { granted(undefined); return undefined; }
      return new Promise(release => { mine = sessionRelease = release; granted(release); });
    }).then(() => {}, error => {
      failed(error); // no-op once granted
      // A hold this tab still has can only end in a rejection when another tab stole it.
      if (mine && sessionRelease === mine) { sessionRelease = undefined; lock(); message('Wallet was opened in another tab. This tab was locked.'); }
    });
  }));
  sessionRequest = request;
  const settled = () => { if (sessionRequest === request) sessionRequest = undefined; };
  request.then(settled, settled);
  return request;
}
// Every open path claims before any key derivation and unclaims in its finally.
// The claim resolves to this tab's hold, or undefined when another tab has it;
// the caller must still check `session === sessionRelease` before deriving.
function claimSession() { sessionClaims++; return requestSession(); }
function unclaimSession() { if (--sessionClaims === 0 && !wallet) releaseSession(); }
function refuseOpen(flow) {
  // Clears every entered secret, exactly as locking does; nothing was opened.
  lock(); message('');
  sessionConflictFlow = flow; $('session-conflict').hidden = false; $('session-takeover').focus();
}
function visibleActivity() { return wallet ? history.filter(row => row.chain === $('chain').value && row.address === wallet.addresses[row.chain]) : []; }
function persistActivity({ required = false } = {}) {
  const session = activitySession, source = wallet;
  if (!session || !source) return Promise.resolve();
  const rows = history.filter(row => row.address === source.addresses[row.chain]).map(row => ({ ...row }));
  const current = () => session === activitySession && source === wallet && !source.locked && localStorage.getItem(VAULT_KEY) === session.vault;
  const changed = () => { if (required) throw new Error('Wallet storage changed before broadcast. Review the transfer again.'); };
  // WARNING: a per-tab queue alone loses other tabs' signed transaction records.
  // Read, authenticate, merge and write under one origin-wide browser lock.
  historyWrites = historyWrites.catch(() => {}).then(() => withActivityLock(async () => {
    if (!current()) return changed();
    if (activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
    const saved = await parseActivity(localStorage.getItem(ACTIVITY_KEY), session.id, source.addresses, session.key);
    if (!current()) return changed();
    const merged = new Map([...saved, ...rows].map(row => [`${row.chain}:${row.hash}`, row]));
    const combined = [...merged.values()].sort((a, b) => {
      const time = Date.parse(a.createdAt) - Date.parse(b.createdAt), aKey = `${a.chain}:${a.hash}`, bKey = `${b.chain}:${b.hash}`;
      return time || (aKey < bKey ? -1 : aKey > bKey ? 1 : 0);
    });
    const encrypted = await serializeActivity(session.id, combined, session.key);
    if (!current()) return changed();
    localStorage.setItem(ACTIVITY_KEY, encrypted);
  }));
  return historyWrites;
}
function renderActivity(save = true) {
  if (save) void persistActivity().catch(error => { $('vault-status').textContent = error.message; });
  $('activity').replaceChildren(...visibleActivity().map(row => {
    const div = document.createElement('div'), link = document.createElement('a');
    div.textContent = `${row.amount} ${row.symbol} → ${row.to} · ${row.status} · ${row.readError || row.note} `;
    link.href = CHAINS[row.chain].explorer + encodeURIComponent(row.hash); link.textContent = 'View transaction'; link.target = '_blank'; link.rel = 'noopener noreferrer'; div.append(link);
    if (!terminal(row.status)) {
      const abandon = document.createElement('button'); abandon.type = 'button'; abandon.className = 'secondary small';
      abandon.textContent = row._abandonArmed ? 'Confirm abandon' : 'Mark as abandoned';
      abandon.onclick = () => {
        if (row._abandonArmed) {
          row.status = 'abandoned'; row.note = 'Marked abandoned by you; the network may still include it. Check the explorer.'; delete row._abandonArmed;
          renderActivity();
        } else { row._abandonArmed = true; renderActivity(false); }
      };
      div.append(' ', abandon);
    }
    return div;
  }));
}
function trackActivity() { stopTracking(); renderActivity(); if (wallet) stopTracking = watchActivity(visibleActivity, renderActivity); }
const endpoints = Object.fromEntries(Object.entries(CHAINS).map(([key, chain]) => [key, chain.endpoint]));
// Receive-only networks outside CHAINS, in display order (network selector,
// portfolio filters, badges and asset rows). None can be sent to: src/wallet.js
// has no adapter for them. Nodus leads every list (and so is the network
// selected when the page loads); Cellframe and Ixios follow CHAINS. Nodus has
// no endpoint: nothing reads a balance for it (src/nodus/network.js).
const leadingNetworks = [{ network: NODUS_NETWORK, asset: NODUS_ASSET }];
const extraNetworks = [];
if (CPUNK_ENABLED) { endpoints.cellframe = CELLFRAME.endpoint; extraNetworks.push({ network: CELLFRAME, asset: CPUNK_ASSET }); }
// Ixios: receive-only, like Cellframe (see src/ixios/network.js).
if (import.meta.env.VITE_ENABLE_IXIOS === 'true') {
  ixiosChain = IXIOS_ASSET.chain;
  endpoints[ixiosChain] = IXIOS_NETWORK.endpoint; extraNetworks.push({ network: IXIOS_NETWORK, asset: IXIOS_ASSET });
}
const receiveOnlyNetworks = Object.fromEntries([...leadingNetworks, ...extraNetworks].map(({ network, asset }) => [asset.chain, network]));
function networkFor(chain) { return CHAINS[chain] || receiveOnlyNetworks[chain]; }
const portfolio = createPortfolio({
  // cellframeReader / ixiosReader are set, in the same module-load callback as
  // their address derivation, before either ever reports an address to the
  // portfolio, so each is ready by the time its branch runs. In a disabled
  // Ixios build ixiosChain is undefined and never matches.
  readBalances: (chain, address, endpoint, options) => chain === 'cellframe'
    ? cellframeReader(address, endpoint, options)
    : chain === ixiosChain ? ixiosReader(address, endpoint, options)
    : adapters[chain].balances(chain, address, endpoint, options),
  // action 'send' / 'receive' (the row's buttons) also moves focus to that block
  // of the Send / Receive panel; 'select' (a click on the row itself) only
  // switches the panel's network, and when the dashboard is single-column (the
  // panel below the asset list: SINGLE_COLUMN_DASHBOARD) scrolls it into view.
  selectAsset(chain, symbol, action) {
    if (!wallet) return;
    $('chain').value = chain; selectChain(); $('asset').value = symbol;
    if (action === 'select') { if (matchMedia(SINGLE_COLUMN_DASHBOARD).matches) $('send-form').scrollIntoView({ block: 'start' }); return; }
    $(action === 'send' ? 'quick-send' : 'quick-receive').click();
  },
  leadingNetworks,
  extraNetworks
});
const message = text => { $('wallet-status').textContent = text; };
for (const { network, asset } of leadingNetworks) $('chain').add(new Option(network.name, asset.chain));
for (const [key, chain] of Object.entries(CHAINS)) $('chain').add(new Option(chain.name, key));
for (const { network, asset } of extraNetworks) $('chain').add(new Option(network.name, asset.chain));
if (CPUNK_ENABLED) {
  // The default HTML text (kept for a disabled build, where it stays true
  // unedited) says CPUNK is "not included"; with the module enabled its
  // balance IS shown here, just never priced into the total. NODUS is listed
  // in every build, but has no balance to show yet.
  $('portfolio-scope').textContent = 'Supported assets on Ethereum, BNB Smart Chain, Solana, TRON and Cellframe. NODUS is shown, but its balance is not shown yet. The CPUNK balance is shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total.';
}
if (import.meta.env.VITE_ENABLE_IXIOS === 'true') {
  $('portfolio-scope').textContent = CPUNK_ENABLED
    ? 'Supported assets on Ethereum, BNB Smart Chain, Solana, TRON, Cellframe and Ixios. NODUS is shown, but its balance is not shown yet. CPUNK and IXIOS balances are shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total.'
    : 'Supported assets on Ethereum, BNB Smart Chain, Solana, TRON and Ixios. NODUS is shown, but its balance is not shown yet. The IXIOS balance is shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total. CPUNK is not included.';
}
function expireIdle() {
  if (idleDeadline && Date.now() >= idleDeadline) { lock(); return true; }
  return false;
}
function activity() {
  if (expireIdle()) return;
  clearTimeout(lockTimer);
  // A tab that took the session over holds it before the wallet is reopened;
  // the same idle lock gives it back if nobody reopens it here.
  const sensitive = wallet || sessionRelease || !$('phrase-form').hidden || $('unlock-wallet').disabled || $('vault-save').disabled || ['unlock-password', 'vault-password', 'vault-old-password'].some(id => $(id).value);
  if (sensitive) { idleDeadline = Date.now() + 10 * 60 * 1000; lockTimer = setTimeout(lock, 10 * 60 * 1000); }
}
for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, activity);
document.addEventListener('visibilitychange', () => { if (!document.hidden) expireIdle(); });
window.addEventListener('focus', expireIdle);
function closeReview() { clearTimeout(confirmEnableTimer); pending?.cancel(); pending = undefined; $('review-dialog').close(); $('review-details').replaceChildren(); $('review-error').textContent = ''; }
$('review-dialog').addEventListener('keydown', event => { if (event.key === 'Enter' && $('confirm-send').disabled) event.preventDefault(); });
function lock() {
  portfolio.clear();
  phraseFields.clear();
  nodusDerivation?.abort(); nodusDerivation = undefined;
  $('nodus-address-status').textContent = '';
  cellframeDerivation?.abort(); cellframeDerivation = undefined;
  $('cellframe-address-status').textContent = '';
  stopIxiosAddress();
  revision++; vaultOperation++; activitySession = null; activityBlocked = false; idleDeadline = 0; stopTracking(); closeReview(); disposeWallet(wallet); wallet = undefined; generatedPhrase = undefined;
  releaseSession(); $('session-conflict').hidden = true;
  $('discard-activity').hidden = true;
  $('phrase-form').hidden = true; $('wallet-open').hidden = true; $('welcome').hidden = false;
  history.length = 0; $('account-explorer').removeAttribute('href');
  $('activity').replaceChildren(); setReceiveAddress(''); $('balances').replaceChildren(); $('recipient').value = ''; $('amount').value = '';
  for (const id of ['unlock-password', 'vault-password', 'vault-old-password']) $(id).value = '';
  $('vault-risk-confirm').checked = false;
  updateVaultUI(); clearTimeout(lockTimer); message('Wallet locked. Restore your recovery phrase or unlock your saved wallet.');
}
window.addEventListener('pagehide', lock);
function phraseForm(create) {
  phraseFields.clear();
  vaultOperation++; $('unlock-password').value = ''; $('unlock-form').hidden = true; $('session-conflict').hidden = true;
  phraseStep = create ? 'backup' : 'restore';
  generatedPhrase = create ? newPhrase() : undefined;
  $('welcome').hidden = true; $('phrase-form').hidden = false; $('backup-confirm').checked = false;
  phraseFields.set(generatedPhrase || '', create);
  $('phrase-label').textContent = create ? 'Write down your 24-word recovery phrase privately' : 'Enter your 24-word Nodus recovery phrase';
  $('phrase-entry-help').textContent = DEFAULT_PHRASE_ENTRY_HELP;
  $('phrase-help').textContent = 'This phrase controls your funds. It stays local; an encrypted copy is stored only if you choose to save it. Keep an offline backup. This screen clears after 10 minutes of inactivity.';
  $('phrase-submit').textContent = create ? 'I saved it — verify backup' : 'Open wallet'; message('');
  // Show the recovery warning before focusing a word field, including on narrow screens.
  $('recovery-warning-title').focus({ preventScroll: true });
  $('recovery-warning').scrollIntoView({ block: 'start' });
  activity();
}
$('create').onclick = () => phraseForm(true);
$('restore').onclick = () => phraseForm(false);
$('phrase-cancel').onclick = lock;
$('phrase-form').onsubmit = async event => {
  event.preventDefault();
  if (phraseStep === 'backup') {
    phraseStep = 'verify'; phraseFields.set(undefined, false, { allowPaste: false });
    $('phrase-label').textContent = 'Re-enter your saved recovery phrase'; $('phrase-submit').textContent = 'Open wallet';
    $('phrase-entry-help').textContent = 'Type each word from your written backup; pasting is disabled here.';
    phraseFields.focus(); return;
  }
  const operation = ++vaultOperation; let claimed = false;
  try {
    const phrase = phraseFields.read();
    if (phraseStep === 'verify' && normalizePhrase(phrase) !== generatedPhrase) throw new Error('The phrase does not match. Re-enter your saved backup.');
    // No key is derived until this tab holds the single-tab session lock.
    claimed = true; const session = await claimSession();
    if (operation !== vaultOperation) return;
    if (!session) { refuseOpen('phrase'); return; }
    if (session !== sessionRelease) return;
    wallet = deriveWallet(phrase); generatedPhrase = undefined; phraseFields.clear();
    $('phrase-form').hidden = true; $('wallet-open').hidden = false; message('Wallet open. Portfolio balances load automatically.'); selectChain(); activity(); void showNodusAddress(); void showCellframeAddress(); showIxiosAddress(); focusOpenWallet();
  } catch (error) { if (operation === vaultOperation) message(error.message); }
  finally { if (claimed) unclaimSession(); }
};
// The Nodus address is shown in the receive panel when Nodus is the selected
// network, like Cellframe's and Ixios's below. It is stored on the wallet
// (source.addresses.nodus) only once current() passes, so #copy-address finds
// nothing to copy until then. No balance is read for it (src/nodus/network.js).
async function showNodusAddress() {
  nodusDerivation?.abort();
  const operation = new AbortController(), source = wallet;
  nodusDerivation = operation;
  $('nodus-address-status').textContent = 'Calculating your Nodus address locally…';
  const current = () => nodusDerivation === operation && source === wallet && !source.locked && !operation.signal.aborted;
  try {
    const { deriveNodusAddress } = await import('./nodus/derive.js');
    if (!current()) return;
    const address = await deriveNodusAddress(source.recoveryPhrase, { signal: operation.signal });
    if (!current()) return;
    source.addresses.nodus = address;
    if ($('chain').value === NODUS_ASSET.chain) setReceiveAddress(address);
    $('nodus-address-status').textContent = 'Derived locally from this wallet’s recovery phrase.';
  } catch {
    if (current()) $('nodus-address-status').textContent = 'Nodus address unavailable. Lock and reopen your wallet to retry.';
  }
}
// Same pattern as showNodusAddress(): AbortController, current() guard, aborted
// on lock, late results dropped. The address is stored on the wallet object
// (source.addresses.cellframe) only once current() passes.
//
// Both dynamic imports (and the WASM they pull in via cpunk/derive.js) must
// stay behind a *top-level* `if (import.meta.env.VITE_ENABLE_CPUNK !== 'false')`
// block for `VITE_ENABLE_CPUNK=false npm run build` to drop them from the
// bundle: Vite's static-asset-URL scan for `new URL(..., import.meta.url)`
// (used by cpunk/derive.js to fetch legacy-dilithium.wasm) runs over the whole
// module graph before Rollup's tree-shaking removes unreachable branches, so a
// guard written as an early return *inside* a function does not prevent the
// wasm file from being emitted — verified empirically: with the guard as a
// function-body `if (!CPUNK_ENABLED) return;`, `legacy-dilithium.wasm` still
// appeared in a disabled build. Only the literal top-level `if` (as used for
// ./adapters/cpunk.js below, matching the pre-existing code) eliminates it.
let doShowCellframeAddress;
if (import.meta.env.VITE_ENABLE_CPUNK !== 'false') {
  Promise.all([import('./adapters/cpunk.js'), import('./cpunk/derive.js')]).then(([{ readCpunk }, { deriveCpunkAddress }]) => {
    cellframeReader = (address, endpoint, options) => readCpunk({ address, endpoint, signal: options.signal }).then(result => [{ symbol: 'CPUNK', balance: result.balance }]);
    doShowCellframeAddress = async () => {
      cellframeDerivation?.abort();
      const operation = new AbortController(), source = wallet;
      cellframeDerivation = operation;
      const current = () => cellframeDerivation === operation && source === wallet && !source.locked && !operation.signal.aborted;
      $('cellframe-address-status').textContent = 'Calculating your Cellframe address locally…';
      try {
        const address = await deriveCpunkAddress(source.recoveryPhrase, { signal: operation.signal });
        if (!current()) return;
        source.addresses.cellframe = address;
        if ($('chain').value === 'cellframe') setReceiveAddress(address);
        $('cellframe-address-status').textContent = 'Derived locally from this wallet’s recovery phrase.';
        portfolio.setAddress('cellframe', address);
      } catch {
        if (current()) {
          $('cellframe-address-status').textContent = 'Cellframe address unavailable. Lock and reopen your wallet to retry.';
          portfolio.setAddress('cellframe', undefined);
        }
      }
    };
    // The module can resolve after a wallet is already open (or after a lock/
    // reopen raced ahead of it); start derivation for whichever wallet is
    // current once it is ready, exactly as a direct showCellframeAddress()
    // call would have.
    if (wallet && !wallet.locked) void doShowCellframeAddress();
  }).catch(() => { if (wallet && !wallet.locked) $('cellframe-address-status').textContent = 'Cellframe address unavailable. Lock and reopen your wallet to retry.'; });
}
function showCellframeAddress() { void doShowCellframeAddress?.(); }
// Ixios receive-only address (default OFF), shown in the receive panel when
// Ixios is the selected network, like Cellframe's. Same pattern as
// showNodusAddress() and doShowCellframeAddress(): AbortController, current()
// guard, aborted and cleared on lock, late results dropped; the address is
// stored on the wallet (source.addresses.ixios) and reported to the portfolio
// only once current() passes; the portfolio then reads its balance through
// ixiosReader, as it does Cellframe's through cellframeReader.
// Everything Ixios-specific — the dynamic imports (derive.js fetches
// nodus/mldsa87.wasm through `new URL(..., import.meta.url)`; balance.js reads
// the balance), the status element and the UI text — stays inside this literal
// top-level `if`, for the reason given above the VITE_ENABLE_CPUNK block: only
// then does a disabled build carry no Ixios code or text in its JavaScript.
// lock(), the open paths and readBalances reach it only through
// stopIxiosAddress / doShowIxiosAddress / ixiosChain + ixiosReader.
if (import.meta.env.VITE_ENABLE_IXIOS === 'true') {
  let ixiosDerivation;
  const chain = IXIOS_ASSET.chain;
  const unavailable = 'Ixios address unavailable. Lock and reopen your wallet to retry.';
  // Created here rather than in index.html so a disabled build has no Ixios markup.
  const status = document.createElement('p');
  status.id = 'ixios-address-status'; status.className = 'hint'; status.hidden = true;
  status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  $('cellframe-address-status').after(status); addressStatus[chain] = status;
  stopIxiosAddress = () => { ixiosDerivation?.abort(); ixiosDerivation = undefined; status.textContent = ''; };
  Promise.all([import('./ixios/derive.js'), import('./ixios/address.js'), import('./ixios/balance.js')]).then(([{ deriveIxiosAddress }, { ixiosChecksumAddress }, { readIxiosBalance }]) => {
    ixiosReader = (address, endpoint, options) => readIxiosBalance(address, endpoint, { signal: options.signal });
    doShowIxiosAddress = async () => {
      ixiosDerivation?.abort();
      const operation = new AbortController(), source = wallet;
      ixiosDerivation = operation;
      status.textContent = 'Calculating your Ixios address locally…';
      const current = () => ixiosDerivation === operation && source === wallet && !source.locked && !operation.signal.aborted;
      try {
        const bytes = await deriveIxiosAddress(source.recoveryPhrase, { signal: operation.signal });
        if (!current()) return;
        const address = ixiosChecksumAddress(bytes);
        source.addresses[chain] = address;
        if ($('chain').value === chain) setReceiveAddress(address);
        status.textContent = 'Derived locally from this wallet’s recovery phrase.';
        portfolio.setAddress(chain, address);
      } catch {
        if (current()) { status.textContent = unavailable; portfolio.setAddress(chain, undefined); }
      }
    };
    // The modules can resolve after a wallet is already open; start derivation
    // for whichever wallet is current, as a direct showIxiosAddress() would.
    if (wallet && !wallet.locked) void doShowIxiosAddress();
  }).catch(() => { if (wallet && !wallet.locked) status.textContent = unavailable; });
}
function showIxiosAddress() { void doShowIxiosAddress?.(); }
function selectChain() {
  revision++; closeReview(); const chain = $('chain').value; const c = networkFor(chain);
  for (const label of document.querySelectorAll('.selected-network-name')) label.textContent = c.name;
  const address = wallet.addresses[chain];
  setReceiveAddress(address || '');
  portfolio.setSelected(chain);
  // A network with no RPC to choose (Nodus) hides the connection settings.
  $('rpc-settings').hidden = !c.rpcOptions; if (c.rpcOptions) populateRpcChoice(chain, c);
  $('asset').replaceChildren(...[c.symbol, ...c.tokens.map(t => t.symbol)].map(s => new Option(s, s)));
  $('solana-send-hint').hidden = chain !== 'solana';
  const explorers = { ethereum: 'https://etherscan.io/address/', bsc: 'https://bscscan.com/address/', solana: 'https://solscan.io/account/', tron: 'https://tronscan.org/#/address/' };
  if (explorers[chain]) { $('account-explorer').href = explorers[chain] + encodeURIComponent(address); $('account-explorer').hidden = false; }
  else { $('account-explorer').removeAttribute('href'); $('account-explorer').hidden = true; }
  trackActivity();
  $('recipient').value = ''; $('amount').value = '';
  $('send-fields').hidden = !!c.receiveOnly; $('send-disabled-note').hidden = !c.receiveOnly;
  $('send-disabled-note').textContent = c.sendNote || DEFAULT_SEND_DISABLED_NOTE;
  for (const [key, node] of Object.entries(addressStatus)) node.hidden = chain !== key;
}
$('chain').onchange = selectChain;
// Both shortcuts lead to the same Send / Receive panel: receive block on top,
// send block below it.
$('quick-send').onclick = () => {
  $('send-block-title').focus({ preventScroll: true });
  $('send-block').scrollIntoView({ block: 'start' });
};
$('quick-receive').onclick = () => {
  $('receive-title').focus({ preventScroll: true });
  $('receive-panel').scrollIntoView({ block: 'start' });
};
$('lock').onclick = lock;
$('copy-address').onclick = async () => {
  // Nodus/Cellframe/Ixios addresses are absent until their local derivation settles.
  const address = wallet?.addresses[$('chain').value];
  if (!address) { message('Address not available yet.'); return; }
  try { await navigator.clipboard.writeText(address); message('Address copied.'); }
  catch { message('Copy unavailable. Select and copy the address above.'); }
};
// Custom HTTPS endpoint is offered for every network except TRON, which keeps
// its single restricted provider (checked again below in save-rpc's onclick).
// #rpc-endpoint always mirrors the currently resolved URL — hidden and synced
// to the picked option's url, or shown empty for the user to type into — so
// save-rpc's existing endpointUrl($('rpc-endpoint').value) read needs no change.
const CUSTOM_RPC = 'custom';
function setRpcCustomVisible(visible) { $('rpc-endpoint-label').hidden = !visible; $('rpc-endpoint').hidden = !visible; }
function setRpcNote(note) { $('rpc-choice-note').hidden = !note; $('rpc-choice-note').textContent = note || ''; }
function populateRpcChoice(chain, c) {
  const options = c.rpcOptions;
  $('rpc-choice').replaceChildren(...options.map((option, index) => new Option(option.label, String(index))));
  if (chain !== 'tron') $('rpc-choice').add(new Option('Custom HTTPS endpoint…', CUSTOM_RPC));
  const current = endpoints[chain];
  const matchIndex = options.findIndex(option => endpointUrl(option.url) === endpointUrl(current));
  if (matchIndex >= 0) {
    $('rpc-choice').value = String(matchIndex); $('rpc-endpoint').value = options[matchIndex].url;
    setRpcCustomVisible(false); setRpcNote(options[matchIndex].note);
  } else {
    $('rpc-choice').value = CUSTOM_RPC; $('rpc-endpoint').value = current;
    setRpcCustomVisible(true); setRpcNote(undefined);
  }
}
$('rpc-choice').onchange = () => {
  const chain = $('chain').value, c = networkFor(chain), value = $('rpc-choice').value;
  if (!c.rpcOptions) return;
  if (value === CUSTOM_RPC) { setRpcCustomVisible(true); $('rpc-endpoint').value = ''; $('rpc-endpoint').focus(); setRpcNote(undefined); return; }
  const option = c.rpcOptions[Number(value)];
  setRpcCustomVisible(false); $('rpc-endpoint').value = option.url; setRpcNote(option.note);
};
$('save-rpc').onclick = () => { if (!networkFor($('chain').value).rpcOptions) return; try { const chain = $('chain').value, endpoint = endpointUrl($('rpc-endpoint').value); if (chain === 'tron' && endpoint !== endpointUrl(CHAINS.tron.endpoint)) throw new Error('TRON requires the mainnet provider.'); endpoints[chain] = endpoint; revision++; closeReview(); stopTracking(); for (const row of visibleActivity()) row.endpoint = endpoints[$('chain').value]; trackActivity(); portfolio.changeEndpoint(chain, endpoint); message('RPC updated for this tab.'); } catch (error) { message(error.message); } };
$('send-form').onsubmit = async event => {
  event.preventDefault(); if (busy) return;
  // Belt-and-suspenders: the send fields are hidden/disabled for a receive-only
  // network already, and prepareTransfer() has no adapter for a receive-only
  // network to route to either (src/wallet.js is unchanged), so this can only be
  // reached by a script bypassing the UI, not a real user. The message is the
  // network's own note (Cellframe: index.html's default text).
  const selected = networkFor($('chain').value);
  if (selected?.receiveOnly) { message(selected.sendNote || DEFAULT_SEND_DISABLED_NOTE); return; }
  if ($('chain').value === 'ethereum' || $('chain').value === 'bsc') {
    const address = wallet.addresses[$('chain').value];
    const blocking = history.find(row => row.chain === $('chain').value && row.address === address && !terminal(row.status));
    if (blocking) { message(`A previous send on this network has no final result yet (tx ${blocking.hash}). Wait for it to resolve, or mark it as abandoned in Activity.`); return; }
  }
  busy = true; $('review-button').disabled = true; const current = revision;
  message('Preparing transfer and network fee…');
  try {
    const transfer = await prepareTransfer({ wallet, chain: $('chain').value, symbol: $('asset').value, to: $('recipient').value, amount: $('amount').value, endpoint: endpoints[$('chain').value] });
    if (current !== revision || !wallet) { transfer.cancel(); return; }
    pending = transfer; $('review-details').replaceChildren();
    const isEvm = transfer.chain === 'ethereum' || transfer.chain === 'bsc';
    const details = { Network: `${CHAINS[transfer.chain].name} mainnet`, From: transfer.from, To: isEvm ? getAddress(transfer.to) : transfer.to };
    if (isEvm && /^0x[0-9a-f]{40}$/.test(transfer.to)) details['Address check'] = 'No checksum in what you typed — compare the form above with your source character by character.';
    Object.assign(details, { Asset: transfer.symbol, Amount: transfer.amount, 'Network fee': transfer.fee });
    if (isEvm) details['Transaction number (nonce)'] = transfer.nonce;
    details['Review expires'] = new Date(transfer.expiresAt).toLocaleTimeString();
    for (const [key, value] of Object.entries(details)) {
      const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = key; dd.textContent = value;
      if (key === 'Address check') dd.className = 'notice';
      $('review-details').append(dt, dd);
    }
    $('confirm-send').disabled = true; $('review-error').textContent = ''; $('review-dialog').showModal(); message('Review every transfer detail before confirming.');
    clearTimeout(confirmEnableTimer); confirmEnableTimer = setTimeout(() => { $('confirm-send').disabled = false; }, 600);
  } catch (error) { if (current === revision) message(error.message); }
  finally { busy = false; $('review-button').disabled = false; }
};
$('cancel-send').onclick = closeReview;
$('review-dialog').addEventListener('cancel', event => { if (busy) event.preventDefault(); else closeReview(); });
$('confirm-send').onclick = async () => {
  if (!pending || busy) return;
  busy = true; const transfer = pending, current = revision; pending = undefined; let record;
  $('confirm-send').disabled = true; $('cancel-send').disabled = true; $('review-error').textContent = 'Signing locally and broadcasting…';
  try {
    const hash = await transfer.confirm(async details => {
      record = recordActivity(transfer, details); history.push(record); if (current === revision) renderActivity(false);
      // The signed hash must be durable before the first network submission.
      await persistActivity({ required: true });
    });
    if (record) { record.note = 'Broadcast submitted; awaiting confirmation.'; if (current === revision) trackActivity(); }
    closeReview();
    if (current !== revision) return;
    message('Broadcast submitted; confirmation is pending. ');
    $('recipient').value = ''; $('amount').value = '';
    const link = document.createElement('a'); link.href = CHAINS[transfer.chain].explorer + encodeURIComponent(hash); link.textContent = `View transaction ${hash}`; link.target = '_blank'; link.rel = 'noopener noreferrer'; $('wallet-status').append(link);
  } catch (error) {
    if (record) { record.status = 'unknown'; record.note = 'Broadcast outcome uncertain. Tracking the signed transaction; do not resend automatically.'; if (current === revision) trackActivity(); }
    closeReview();
    if (current === revision) message(record ? `${error.message} A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.` : error.message);
  } finally { busy = false; $('cancel-send').disabled = false; }
};
function updateVaultUI() {
  try {
    const saved = localStorage.getItem(VAULT_KEY);
    $('unlock-form').hidden = !!wallet || !saved;
    $('wallet-storage-state').textContent = saved && activitySession?.vault === saved
      ? 'Encrypted copy saved in this browser.'
      : saved ? 'Temporary session · the saved copy has not been unlocked here.' : 'Temporary session · this wallet has not been saved on this device.';
  }
  catch {
    $('vault-status').textContent = 'Device storage is unavailable. Use a temporary wallet in this tab.';
    $('wallet-storage-state').textContent = 'Device storage is unavailable.';
  }
}
function focusOpenWallet() {
  updateVaultUI();
  portfolio.open(wallet.addresses, endpoints);
  $('wallet-title').focus({ preventScroll: true });
  document.querySelector('.wallet-card').scrollIntoView({ block: 'start' });
}
updateVaultUI();
$('unlock-form').onsubmit = async event => {
  if (expireIdle()) { event.preventDefault(); return; }
  event.preventDefault(); const operation = ++vaultOperation; let claimed = false;
  const password = $('unlock-password').value; $('unlock-password').value = ''; $('unlock-wallet').disabled = true; $('session-conflict').hidden = true;
  try {
    const text = localStorage.getItem(VAULT_KEY); if (!text) throw new Error('No saved wallet on this device.');
    // The password is not even tried until this tab holds the single-tab session lock.
    claimed = true; const session = await claimSession();
    if (operation !== vaultOperation) return;
    if (!session) { refuseOpen('unlock'); return; }
    if (session !== sessionRelease) return;
    const saved = await decryptVault(text, password);
    if (operation !== vaultOperation || session !== sessionRelease || text !== localStorage.getItem(VAULT_KEY)) return;
    const restored = deriveWallet(saved.phrase); let key, rows = [], problem = '';
    try {
      key = await activityKeyFor(saved.phrase, saved.id);
      try { rows = await parseActivity(localStorage.getItem(ACTIVITY_KEY), saved.id, restored.addresses, key); }
      catch (error) { problem = error.message; }
      if (operation !== vaultOperation || session !== sessionRelease || text !== localStorage.getItem(VAULT_KEY)) { disposeWallet(restored); return; }
    } catch (error) { disposeWallet(restored); throw error; }
    disposeWallet(wallet); wallet = restored; activitySession = { id: saved.id, key, vault: text }; activityBlocked = !!problem;
    history.length = 0; history.push(...rows);
    $('discard-activity').hidden = !problem; $('vault-status').textContent = problem || 'Saved activity authenticated.';
    $('welcome').hidden = true; $('phrase-form').hidden = true; $('wallet-open').hidden = false; updateVaultUI(); selectChain(); activity(); void showNodusAddress(); void showCellframeAddress(); showIxiosAddress(); message('Saved wallet unlocked locally.'); focusOpenWallet();
  } catch (error) { if (operation === vaultOperation) $('vault-status').textContent = error.message; }
  finally { $('unlock-wallet').disabled = false; if (claimed) unclaimSession(); }
};
$('session-takeover').onclick = async () => {
  const operation = ++vaultOperation, flow = sessionConflictFlow;
  $('session-conflict').hidden = true;
  try {
    // The other tab's hold is aborted and that tab locks itself. Nothing entered
    // before the refusal was kept, so the wallet is reopened here from scratch.
    const session = await requestSession({ steal: true });
    if (operation !== vaultOperation || session !== sessionRelease) { if (!sessionClaims && !wallet && session === sessionRelease) releaseSession(); return; }
    if (flow === 'unlock' && !$('unlock-form').hidden) {
      activity(); $('unlock-password').focus();
      message('This tab now has the wallet. Enter your local password again to open it here.');
    } else {
      phraseForm(false);
      message('This tab now has the wallet. Enter your recovery phrase again to open it here.');
    }
  } catch (error) { if (operation === vaultOperation) message(error.message); }
};
async function saveVault(change) {
  if (!wallet || wallet.locked) return;
  if (!$('vault-risk-confirm').checked) {
    $('vault-status').textContent = 'Before saving, read and accept the risks of storing an encrypted wallet on this device.';
    $('vault-risk-confirm').reportValidity();
    return;
  }
  const source = wallet, operation = ++vaultOperation;
  const password = $('vault-password').value, oldPassword = $('vault-old-password').value;
  $('vault-password').value = ''; $('vault-old-password').value = '';
  $('vault-save').disabled = true; $('vault-change').disabled = true;
  try {
    const previous = localStorage.getItem(VAULT_KEY); let id;
    validateNewPassword(password);
    if (activityBlocked) throw new Error('Check the explorer and discard the unreadable history before changing the saved wallet.');
    if (previous && !change) throw new Error('A wallet is already saved. Unlock it to change its password, or explicitly delete it first.');
    if (change) {
      if (!previous) throw new Error('No saved wallet to change.');
      // A phrase-only restore has not authenticated or loaded saved activity.
      if (activitySession?.vault !== previous) throw new Error('Lock and unlock the saved wallet before changing its password.');
      const saved = await decryptVault(previous, oldPassword);
      if (saved.phrase !== source.recoveryPhrase) throw new Error('Unlock the saved wallet before changing its password.');
      id = saved.id;
    }
    if (operation !== vaultOperation || wallet !== source || source.locked) return;
    const encrypted = await encryptVault(source.recoveryPhrase, password, id);
    const newId = parseVault(encrypted).id, key = await activityKeyFor(source.recoveryPhrase, newId);
    if (operation !== vaultOperation || wallet !== source || source.locked || localStorage.getItem(VAULT_KEY) !== previous) return;
    const stored = await withActivityLock(() => {
      if (operation !== vaultOperation || wallet !== source || source.locked || !$('vault-risk-confirm').checked || localStorage.getItem(VAULT_KEY) !== previous) return false;
      localStorage.setItem(VAULT_KEY, encrypted); activitySession = { id: newId, key, vault: encrypted }; return true;
    });
    if (!stored) {
      if (operation === vaultOperation && wallet === source && !source.locked && !$('vault-risk-confirm').checked) $('vault-status').textContent = 'Save canceled. The storage risks were not accepted; no new copy was saved.';
      return;
    }
    updateVaultUI();
    await persistActivity();
    if (operation !== vaultOperation || wallet !== source || source.locked) return;
    $('vault-risk-confirm').checked = false;
    $('vault-status').textContent = change ? 'Local password changed.' : 'Encrypted wallet saved on this device. Keep your recovery backup.';
  } catch (error) { if (operation === vaultOperation) $('vault-status').textContent = error.message; }
  finally { $('vault-save').disabled = false; $('vault-change').disabled = false; }
}
$('vault-save').onclick = () => saveVault(false);
$('vault-change').onclick = () => saveVault(true);
$('vault-password').addEventListener('input', () => {
  try { validateNewPassword($('vault-password').value); $('password-hint').textContent = 'Meets the minimum checks. Use a unique password and keep your recovery backup.'; }
  catch (error) { $('password-hint').textContent = error.message; }
});
$('discard-activity').onclick = async () => {
  if (!wallet || !activitySession || !activityBlocked) return;
  const source = wallet, session = activitySession, previous = localStorage.getItem(ACTIVITY_KEY);
  try {
    await withActivityLock(async () => {
      const encrypted = await serializeActivity(session.id, [], session.key);
      if (wallet !== source || source.locked || activitySession !== session || localStorage.getItem(VAULT_KEY) !== session.vault || localStorage.getItem(ACTIVITY_KEY) !== previous) throw new Error('Wallet or history changed. Unlock again before discarding history.');
      localStorage.setItem(ACTIVITY_KEY, encrypted); history.length = 0; activityBlocked = false; $('discard-activity').hidden = true;
    });
    renderActivity(false); $('vault-status').textContent = 'Unreadable local history discarded. Check the account explorer before resending any previous payment.';
  } catch (error) { $('vault-status').textContent = error.message; }
};
$('vault-delete').onclick = async () => {
  if (!$('vault-delete-confirm').checked) { $('vault-status').textContent = 'Confirm that you have your backup before deleting.'; return; }
  vaultOperation++; activitySession = null; activityBlocked = false; $('discard-activity').hidden = true;
  try {
    const previous = localStorage.getItem(VAULT_KEY);
    await withActivityLock(() => {
      if (localStorage.getItem(VAULT_KEY) !== previous) throw new Error('Saved wallet changed before deletion.');
      localStorage.removeItem(VAULT_KEY); localStorage.removeItem(ACTIVITY_KEY);
    });
    $('vault-status').textContent = 'Saved wallet and saved activity deleted from this device.'; updateVaultUI();
  }
  catch { $('vault-status').textContent = 'Device storage could not be deleted.'; }
  $('vault-delete-confirm').checked = false;
};

window.addEventListener('storage', event => { if (event.key === VAULT_KEY || event.key === null) { lock(); $('vault-status').textContent = 'Saved wallet changed in another tab. Unlock again to continue.'; } });
