import { getAddress } from 'ethers';
import { VAULT_KEY, ACTIVITY_KEY, BALANCES_KEY, HISTORY_KEY, ADDRESS_BOOK_KEY, parseVault, encryptVault, decryptVault, validateNewPassword } from './vault.js';
import { deleteVaultHistory, HistoryDeleteBlocked } from './connect/store.js';
import { serializeActivity, parseActivity, requireSavedForEvm, activityKeyFor, serializeBalances, parseBalances, balancesKeyFor, serializeHistory, parseHistory, historyKeyFor, serializeAddressBook, parseAddressBook, addressBookKeyFor } from './activity-storage.js';
import { addAddress, updateAddress, removeAddress, addressesFor, findAddress, checkAddress } from './address-book.js';
import { validateCellframeAddress } from './cpunk-protocol.js';
import { readHistory, mergeHistory, historySupported, HISTORY_SOURCES, HISTORY_LIMIT } from './history.js';
import { recordActivity, watchActivity, checkActivity, terminal, submissionStatus } from './activity.js';
import { CHAINS, CELLFRAME } from './config.js';
import { CPUNK_ASSET, displayAmount } from './portfolio.js';
// Pure data, referenced only inside `if (import.meta.env.VITE_ENABLE_IXIOS === 'true')`
// blocks below, so a disabled build tree-shakes the whole module away.
import { IXIOS_NETWORK, IXIOS_ASSET } from './ixios/network.js';
import { NODUS_ASSET, nodusNetworkFor } from './nodus/network.js';
// null until package (c3) ships the module; see src/nodus/send-module.js.
import { nodusSendModuleFactory } from './nodus/send-module.js';
import { createNodusClient, NODUS_CONNECT_BOUND_MS } from './nodus/client.js';
import { netLevelFor, netStatusView } from './net-status.js';
// The session log (memory only, cleared on lock; Device & settings → Logs).
import { sessionLog, stepLog, logPageErrors, mountSessionLogView } from './session-log.js';
import { deriveWallet, disposeWallet, newPhrase, normalizePhrase } from './keys.js';
import { adapters, prepareTransfer } from './wallet.js';
import { endpointUrl, formatUnits } from './core.js';
import { createPhraseFields } from './phrase-fields.js';
import { createPortfolio } from './portfolio-view.js';
import { renderQr } from './qr.js';
// Wallet-only page: no extension is registered and these are no-ops; the
// Nodus Connect page registers Messages (src/connect-main.js).
import { raise, gather, siteName } from './wallet-extensions.js';
import { createSiteLock } from './site-lock.js';
const $ = id => document.getElementById(id);
// Must equal the src/style.css media query that sets `.dashboard-grid` to one
// column (`@media (max-width: 900px)`): below it the Send / Receive panel sits
// under the asset list, off screen after a row click.
const SINGLE_COLUMN_DASHBOARD = '(max-width: 900px)';
// The only writer of #receive-address: the QR below it always encodes exactly
// the text shown (empty text, e.g. after lock or before a derivation settles,
// clears the QR).
function setReceiveAddress(text) { $('receive-address').textContent = text; renderQr($('receive-qr'), text); }
// The only writer of the network line in the open-wallet bar (#net-status,
// src/net-status.js). Nodus Connect loads this file too and its page has no
// such line (connect-site/index.html), so a missing element is skipped.
const netStatus = $('net-status'), netStatusText = $('net-status-text');
let netLevelLogged;
function setNetStatus(level) {
  // Each change of level goes to the session log, on both pages.
  if (level !== netLevelLogged) { netLevelLogged = level; const shown = netStatusView(level); if (shown) sessionLog.log('net', `Network status: ${shown.text}`, { error: shown.level === 'offline' }); }
  if (!netStatus || !netStatusText) return;
  const view = netStatusView(level);
  netStatus.hidden = !view;
  if (!view) return;
  netStatus.dataset.level = view.level;
  // Same text: no write, so the live region is not read out again.
  if (netStatusText.textContent !== view.text) netStatusText.textContent = view.text;
}
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
// The NODUS send module's client for the open wallet (src/nodus/client.js);
// only ever set when nodusSendModuleFactory is not null.
let nodusClient;
// Bumped whenever the claim offer must be re-read or withdrawn; a status read
// started under an older value is dropped (refreshClaim).
let claimCheck = 0;
// Set only inside the VITE_ENABLE_IXIOS blocks below; undefined/no-ops in a
// disabled build (so no Ixios string literal is needed outside those blocks).
let doShowIxiosAddress, stopIxiosAddress = () => {}, ixiosChain, ixiosReader;
// Receive-panel derivation status line per receive-only network, shown only
// while that network is selected. The Ixios entry is added by its flag block.
const addressStatus = { nodus: $('nodus-address-status'), cellframe: $('cellframe-address-status') };
// index.html's #send-disabled-note text is Cellframe's; a network may carry its own `sendNote`.
const DEFAULT_SEND_DISABLED_NOTE = $('send-disabled-note').textContent;
let activitySession = null, activityBlocked = false, historyWrites = Promise.resolve(), vaultOperation = 0;
// True only while the open wallet's words were generated in this tab and
// verified (the create flow); handed to extensions (src/wallet-extensions.js
// nodusReady, decision 2026-09-30-nodus-connect-thin-core Q1).
let walletFresh = false;
// Cross-site rule (src/site-lock.js, decision 2026-10-01-connect-own-origin):
// while a wallet is open here its site's mark is refreshed; the other site's
// fresh mark refuses an open and locks an open wallet.
const siteLock = createSiteLock({ site: siteName(), onOther: text => { lock(); message(text); } });
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
// The last balances, saved encrypted only while a SAVED wallet is open
// (activitySession set by unlock / save; decision
// 2026-10-02-device-cache-only-when-saved). An unsaved wallet writes nothing.
let latestKept = null, balanceWrites = Promise.resolve();
function persistBalances(entries) {
  latestKept = entries;
  const session = activitySession, source = wallet;
  if (!session?.balancesKey || !source) return;
  balanceWrites = balanceWrites.catch(() => {}).then(async () => {
    const encrypted = await serializeBalances(session.id, entries, session.balancesKey);
    if (session !== activitySession || source !== wallet || source.locked || localStorage.getItem(VAULT_KEY) !== session.vault) return;
    localStorage.setItem(BALANCES_KEY, encrypted);
  }).catch(() => { /* the balances are read again next time */ });
}
// ── Account history (src/history.js) ────────────────────────────────────
// Read for the network selected in Send / Receive, at most once per
// HISTORY_AUTO_MS by itself and once per HISTORY_MANUAL_MS on "Refresh
// history": public providers limit requests (operator 2026-10-02; Blockscout
// answered 10 requests per ~20 minutes, measured that day). Kept in memory;
// with a SAVED wallet also encrypted in HISTORY_KEY (decision
// 2026-10-02-device-cache-only-when-saved).
const HISTORY_AUTO_MS = { ethereum: 30 * 60 * 1000 }, HISTORY_AUTO_DEFAULT_MS = 5 * 60 * 1000, HISTORY_MANUAL_MS = 30 * 1000;
let historyByChain = {}, historyJob = null, historyNote = {}, accountHistoryWrites = Promise.resolve();
const historyFor = chain => { const h = historyByChain[chain]; return h && wallet && h.address === wallet.addresses[chain] ? h : null; };
const historyTime = ms => new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const shortPeer = peer => peer.length > 18 ? `${peer.slice(0, 8)}…${peer.slice(-6)}` : peer;
function renderHistory() {
  const list = $('history'), status = $('history-status'), button = $('history-refresh');
  if (!wallet) { list.replaceChildren(); status.textContent = ''; button.hidden = true; return; }
  const chain = $('chain').value, h = historyFor(chain), supported = historySupported(chain);
  button.hidden = !supported; button.disabled = !!historyJob || !wallet.addresses[chain];
  status.textContent = !supported ? `Account history for ${networkFor(chain)?.name ?? chain} is not read here. Use the account explorer.`
    : historyJob?.chain === chain ? `Reading account history from ${HISTORY_SOURCES[chain]}…`
    : historyNote[chain] || (h ? `Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${historyTime(h.readAt)}. Your own sends are tracked above.` : 'Account history has not been read yet.');
  const el = (tag, className, text) => { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
  list.replaceChildren(...(supported && h ? h.rows : []).map(r => {
    const div = el('div', `activity-row history-dir-${r.dir}`), main = el('span', 'activity-main');
    const sign = r.dir === 'in' ? '+' : r.dir === 'out' ? '−' : '';
    const what = r.dir === 'self' ? 'to yourself' : r.peer ? `${r.dir === 'in' ? 'from' : 'to'} ${shortPeer(r.peer)}` : r.dir === 'in' ? 'received' : 'sent';
    main.append(el('strong', '', `${sign}${displayAmount(r.amount)} ${r.symbol}`), el('small', '', what));
    const side = el('span', 'activity-side'), badge = el('span', 'status-badge', r.status);
    badge.dataset.status = r.status;
    const when = el('time', '', historyTime(r.time)); when.dateTime = new Date(r.time).toISOString();
    side.append(badge, when);
    const footer = el('div', 'activity-footer');
    if (CHAINS[r.chain]) {
      const link = document.createElement('a');
      link.href = CHAINS[r.chain].explorer + encodeURIComponent(r.hash); link.textContent = 'View transaction'; link.target = '_blank'; link.rel = 'noopener noreferrer'; footer.append(link);
    } else footer.append(el('span', 'activity-id', `Transaction ID ${r.hash}`));
    div.append(main, side, footer);
    return div;
  }));
}
async function loadHistory(chain, { manual = false } = {}) {
  if (!wallet || !historySupported(chain) || historyJob?.chain === chain) return;
  // Another network's read is cancelled: only the shown network is read.
  if (historyJob) { historyJob.controller.abort(); historyJob = null; }
  const address = wallet.addresses[chain];
  if (!address) return;
  const kept = historyFor(chain), gap = manual ? HISTORY_MANUAL_MS : (HISTORY_AUTO_MS[chain] ?? HISTORY_AUTO_DEFAULT_MS);
  if (kept && Date.now() - kept.readAt < gap) {
    if (manual) { historyNote[chain] = `Read ${historyTime(kept.readAt)}. Try again in a minute — the provider limits requests.`; renderHistory(); }
    return;
  }
  const source = wallet, job = { chain, controller: new AbortController() };
  historyJob = job; delete historyNote[chain]; renderHistory();
  try {
    // Solana: signatures already read are not fetched again.
    const known = new Map();
    for (const r of kept?.rows || []) { if (!known.has(r.hash)) known.set(r.hash, []); known.get(r.hash).push(r); }
    const rows = await readHistory(chain, address, { endpoint: endpoints[chain], signal: job.controller.signal, known });
    if (historyJob !== job || wallet !== source) return;
    historyByChain[chain] = { address, readAt: Date.now(), rows: mergeHistory(kept?.rows, rows) };
    persistHistory();
  } catch (error) { if (historyJob === job) historyNote[chain] = error.message; }
  finally { if (historyJob === job) { historyJob = null; renderHistory(); } }
}
function persistHistory() {
  const session = activitySession, source = wallet;
  if (!session?.historyKey || !source) return;
  const snapshot = Object.fromEntries(Object.entries(historyByChain).filter(([chain, h]) => h.address === source.addresses[chain]));
  accountHistoryWrites = accountHistoryWrites.catch(() => {}).then(async () => {
    const encrypted = await serializeHistory(session.id, snapshot, session.historyKey);
    if (session !== activitySession || source !== wallet || source.locked || localStorage.getItem(VAULT_KEY) !== session.vault) return;
    localStorage.setItem(HISTORY_KEY, encrypted);
  }).catch(() => { /* read again next time */ });
}
function clearHistory() { historyJob?.controller.abort(); historyJob = null; historyByChain = {}; historyNote = {}; renderHistory(); }
$('history-refresh').onclick = () => void loadHistory($('chain').value, { manual: true });
function renderActivity(save = true) {
  if (save) void persistActivity().catch(error => { $('vault-status').textContent = error.message; });
  // A row is laid out like a portfolio holding row (src/portfolio-view.js):
  // amount and what it did on the left, status and when on the right, the
  // network's note below, then the transaction link and any row action.
  const el = (tag, className, text) => { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
  $('activity').replaceChildren(...visibleActivity().map(row => {
    const div = el('div', 'activity-row');
    // A claim of this wallet's allocation (src/adapters/nodus.js isClaimRow)
    // pays the wallet itself.
    const claim = adapters.nodus.isClaimRow(row);
    // A staking row (0.1.29) carries its action in `kind` in this tab only
    // (src/activity.js recordActivity); reloaded, it reads as a transfer.
    const what = claim ? ['Allocation claim', '→ your address']
      : row.kind === 'delegate' ? ['Delegation', `→ witness ${row.to}`]
      : row.kind === 'undelegate' ? ['Undelegation', `back from witness ${row.to} (returned locked)`]
      : row.kind === 'stake' ? ['Witness bond']
      : row.kind === 'name' ? ['Chain name registration', row.name ? `"${row.name}"` : 'for your address']
      : row.kind === 'evm' ? ['Smart contracts', row.evmTitle || 'transaction']
      : [`→ ${row.to}`];
    const main = el('span', 'activity-main');
    main.append(el('strong', '', `${row.amount} ${row.symbol}`), el('small', '', what.join(' · ')));
    const side = el('span', 'activity-side'), badge = el('span', 'status-badge', row.status);
    badge.dataset.status = row.status;
    const when = el('time', '', new Date(row.createdAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }));
    when.dateTime = row.createdAt;
    const where = el('small', '', `${networkFor(row.chain)?.name ?? row.chain} · `); where.append(when);
    side.append(badge, where);
    const footer = el('div', 'activity-footer');
    div.append(main, side, el('p', 'activity-note', row.readError || row.note), footer);
    // NODUS has no explorer link in the first delivery (design §1.4).
    if (CHAINS[row.chain]) {
      const link = document.createElement('a');
      link.href = CHAINS[row.chain].explorer + encodeURIComponent(row.hash); link.textContent = 'View transaction'; link.target = '_blank'; link.rel = 'noopener noreferrer'; footer.append(link);
    } else footer.append(el('span', 'activity-id', `${claim ? 'Claim ID' : row.kind ? 'Transaction ID' : 'Transfer ID'} ${row.hash}`));
    // A NODUS send always resolves: included, or 'expired' once the chain passes
    // its expiry block. Its coins stay held until then (src/adapters/nodus.js
    // lockedInputs), so it is never marked abandoned by hand.
    if (!terminal(row.status) && row.chain !== NODUS_ASSET.chain) {
      const abandon = document.createElement('button'); abandon.type = 'button'; abandon.className = 'secondary small';
      abandon.textContent = row._abandonArmed ? 'Confirm abandon' : 'Mark as abandoned';
      abandon.onclick = () => {
        if (row._abandonArmed) {
          row.status = 'abandoned'; row.note = 'Marked abandoned by you; the network may still include it. Check the explorer.'; delete row._abandonArmed;
          renderActivity();
        } else { row._abandonArmed = true; renderActivity(false); }
      };
      footer.append(abandon);
    }
    return div;
  }));
}
// NODUS rows are checked through the send module (block scan for the
// intent_id; for a claim, for the coin it creates). A claim that reaches a
// final state re-reads the NODUS balance and the claim offer once the
// tracker has stored that state on the row (it does so after this returns).
const checkRow = async (row, options) => {
  if (row.chain !== NODUS_ASSET.chain) return checkActivity(row, options);
  const update = await adapters.nodus.checkNodusActivity(row, { ...options, client: nodusClient });
  if (adapters.nodus.isClaimRow(row) && terminal(update.status) && !terminal(row.status)) setTimeout(() => {
    if (!wallet || !nodusClient) return;
    void refreshClaim();
    if (update.status === 'confirmed') portfolio.setAddress(NODUS_ASSET.chain, wallet.addresses.nodus);
  }, 0);
  // Any other NODUS transaction that reaches a final state may have moved a
  // delegation or the validator list, or registered this wallet's chain
  // name (a reloaded row no longer says which): re-read both once.
  else if (terminal(update.status) && !terminal(row.status)) setTimeout(() => { if (wallet && nodusClient) { void refreshStaking(); void refreshName(); } }, 0);
  return update;
};
function trackActivity() { stopTracking(); renderActivity(); if (wallet) stopTracking = watchActivity(visibleActivity, () => { renderActivity(); followSubmission(); }, { check: checkRow }); }
const endpoints = Object.fromEntries(Object.entries(CHAINS).map(([key, chain]) => [key, chain.endpoint]));
// Receive-only networks outside CHAINS, in display order (network selector,
// portfolio filters, badges and asset rows). None can be sent to: src/wallet.js
// has no adapter for them. Nodus leads every list (and so is the network
// selected when the page loads); Cellframe and Ixios follow CHAINS. Nodus has
// no endpoint: nothing reads a balance for it (src/nodus/network.js).
// With a send module in the build, the receive-only entry is the
// "connecting" one (src/nodus/network.js nodusNetworkFor).
const NODUS_HAS_MODULE = nodusSendModuleFactory !== null;
const leadingNetworks = [{ network: nodusNetworkFor(false, { module: NODUS_HAS_MODULE }), asset: NODUS_ASSET }];
const extraNetworks = [];
if (CPUNK_ENABLED) { endpoints.cellframe = CELLFRAME.endpoint; extraNetworks.push({ network: CELLFRAME, asset: CPUNK_ASSET }); }
// Ixios: receive-only, like Cellframe (see src/ixios/network.js).
if (import.meta.env.VITE_ENABLE_IXIOS === 'true') {
  ixiosChain = IXIOS_ASSET.chain;
  endpoints[ixiosChain] = IXIOS_NETWORK.endpoint; extraNetworks.push({ network: IXIOS_NETWORK, asset: IXIOS_ASSET });
}
// The NODUS entry is swapped for its sendable variant only while a send module
// is ready (setNodusReady below); without a module it stays receive-only.
const receiveOnlyNetworks = Object.fromEntries([...leadingNetworks, ...extraNetworks].map(({ network, asset }) => [asset.chain, network]));
function networkFor(chain) { return CHAINS[chain] || receiveOnlyNetworks[chain]; }
const portfolio = createPortfolio({
  // cellframeReader / ixiosReader are set, in the same module-load callback as
  // their address derivation, before either ever reports an address to the
  // portfolio, so each is ready by the time its branch runs. In a disabled
  // Ixios build ixiosChain is undefined and never matches.
  // NODUS is read only while its send module is ready (it is not in the
  // portfolio's read list otherwise), through that module's client.
  readBalances: (chain, address, endpoint, options) => chain === 'cellframe'
    ? cellframeReader(address, endpoint, options)
    : chain === ixiosChain ? ixiosReader(address, endpoint, options)
    : chain === NODUS_ASSET.chain ? adapters.nodus.balances(chain, address, endpoint, { ...options, client: nodusClient })
    : adapters[chain].balances(chain, address, endpoint, options),
  // action 'send' / 'receive' (the row's buttons) also moves focus to that block
  // of the Send / Receive panel; 'select' (a click on the row itself) only
  // switches the panel's network, and when the dashboard is single-column (the
  // panel below the asset list: SINGLE_COLUMN_DASHBOARD) scrolls it into view.
  selectAsset(chain, symbol, action) {
    if (!wallet) return;
    if (action !== 'earn') showEarn(false);
    $('chain').value = chain; selectChain(); $('asset').value = symbol;
    if (action === 'select') { if (matchMedia(SINGLE_COLUMN_DASHBOARD).matches) $('send-form').scrollIntoView({ block: 'start' }); return; }
    $(action === 'send' ? 'quick-send' : action === 'earn' ? 'quick-earn' : 'quick-receive').click();
  },
  onKept: entries => persistBalances(entries),
  leadingNetworks,
  extraNetworks
});
// The status line after a submission follows its Activity record: it changes
// when the tracker (trackActivity) stores a network answer on the record
// (src/activity.js submissionStatus), and stops following once that answer
// is final or any other message replaces the line. It is written only when
// its text changes (Nodus Connect re-shows its toast on every write,
// src/connect-main.js).
let submissionFollow = null;
// Every status text shown here also goes to the session log (scrubbed
// there: no IDs, addresses, quoted names or amounts); `category` and
// `error` only sort it in the Logs view.
const message = (text, { category = 'wallet', error = false } = {}) => {
  submissionFollow = null; $('wallet-status').textContent = text;
  if (text) sessionLog.log(category, text, { error });
};
// The session-log category of a review's transaction (transfer.kind).
const logCategoryFor = kind => (['delegate', 'undelegate', 'stake'].includes(kind) ? 'stake' : kind === 'name' ? 'names' : kind === 'claim' ? 'wallet' : 'send');
function explorerLink(chain, hash) {
  const link = document.createElement('a'); link.href = CHAINS[chain].explorer + encodeURIComponent(hash); link.textContent = `View transaction ${hash}`; link.target = '_blank'; link.rel = 'noopener noreferrer';
  return link;
}
// ── Address book (src/address-book.js) ─────────────────────────────────
// Saved recipients { label, network, address } for every network the wallet
// sends on (operator 2026-10-03; the DNA Connect app's address book,
// dna_engine_addressbook.c). Each address is checked by its own network's
// check (ADDRESS_CHECKS, the same checks the send path uses: src/adapters
// isRecipientAddress, nodusRecipient; Cellframe's is structural only,
// src/cpunk-protocol.js). The send form of a network offers only that
// network's entries (plus, on Nodus Connect, the contacts for NODUS —
// wallet-extensions.js gather 'recipients'); a choice only fills the
// recipient field, which prepareTransfer checks as if typed.
// Kept with a SAVED wallet only, encrypted under its own key
// (ADDRESS_BOOK_KEY, src/activity-storage.js serializeAddressBook; decision
// 2026-10-02-device-cache-only-when-saved); an unsaved wallet keeps it in
// memory until lock, and saving the wallet saves it too.
function evmAddressCheck(name) {
  return text => {
    if (!adapters.ethereum.isRecipientAddress(text)) throw new Error(`Enter a ${name} address: 0x and 40 characters 0-9, a-f.`);
    // A mixed-case address carries a checksum (EIP-55); getAddress refuses a
    // wrong one and gives the checksummed form that is saved.
    try { return getAddress(text); } catch { throw new Error(`This ${name} address does not match its own check (capital and small letters). Copy it again from your source.`); }
  };
}
const ADDRESS_CHECKS = {
  nodus: text => adapters.nodus.nodusRecipient(text),
  ethereum: evmAddressCheck('Ethereum'),
  bsc: evmAddressCheck('BNB Smart Chain'),
  solana: text => { if (!adapters.solana.isRecipientAddress(text)) throw new Error('Enter a Solana address.'); return text; },
  tron: text => { if (!adapters.tron.isRecipientAddress(text)) throw new Error('Enter a TRON address.'); return text; },
  ...(CPUNK_ENABLED ? { cellframe: validateCellframeAddress } : {})
};
// The networks an address can be saved for, in the network selector's order.
const ADDRESS_NETWORKS = [NODUS_ASSET.chain, ...Object.keys(CHAINS), ...(CPUNK_ENABLED ? ['cellframe'] : [])].filter(chain => ADDRESS_CHECKS[chain]);
$('address-book-network').replaceChildren(...ADDRESS_NETWORKS.map(chain => new Option(networkFor(chain).name, chain)));
let addressBook = [], addressBookEditing = null, addressBookDeleteArmed = null, addressBookNote = '', addressBookWrites = Promise.resolve();
// The saved address book did not authenticate or check out at unlock: it is
// left as it is until the user saves an address (commitAddressBook).
let addressBookUnreadable = false;
let recipientChoicesShown = [], lastSentRecipient = null;
const shortAddress = address => address.length > 20 ? `${address.slice(0, 10)}…${address.slice(-6)}` : address;
// Saved encrypted only while a SAVED wallet is open (activitySession with
// its address book key). Resolves true when written, false when there is
// nothing to write to (unsaved wallet, or the wallet changed meanwhile);
// rejects when the browser refused the write.
function persistAddressBook() {
  const session = activitySession, source = wallet, entries = addressBook;
  if (!session?.addressBookKey || !source) return Promise.resolve(false);
  const write = addressBookWrites.catch(() => {}).then(async () => {
    const encrypted = await serializeAddressBook(session.id, entries, session.addressBookKey);
    if (session !== activitySession || source !== wallet || source.locked || localStorage.getItem(VAULT_KEY) !== session.vault) return false;
    localStorage.setItem(ADDRESS_BOOK_KEY, encrypted);
    return true;
  });
  addressBookWrites = write;
  return write;
}
function addressBookStatus(text) { $('address-book-status').textContent = text; }
function resetAddressForm() {
  addressBookEditing = null;
  $('address-book-label').value = ''; $('address-book-address').value = '';
  $('address-book-form-title').textContent = 'Add an address';
  $('address-book-save').textContent = 'Save address';
  $('address-book-cancel').hidden = true;
}
function renderAddressBook() {
  $('address-book-storage').textContent = !wallet ? ''
    : [activitySession?.addressBookKey ? 'Saved encrypted with this wallet on this device.' : 'This wallet is not saved on this device: the address book is kept only until you lock. Save the wallet in Device & settings to keep it.', addressBookNote].filter(Boolean).join(' ');
  const el = (tag, className, text) => { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const small = (text, onClick) => { const node = el('button', 'secondary small', text); node.type = 'button'; node.onclick = onClick; return node; };
  if (addressBookDeleteArmed && !addressBook.some(e => e.id === addressBookDeleteArmed)) addressBookDeleteArmed = null;
  $('address-book-list').replaceChildren(...(wallet && addressBook.length ? addressBook.map(entry => {
    const row = el('div', 'address-book-row'), main = el('span', 'address-book-main');
    // The label is the user's own text, checked when saved (address-book.js
    // addressLabel); shown as text only.
    main.append(el('strong', '', entry.label), el('small', '', `${networkFor(entry.network)?.name ?? entry.network}${ADDRESS_CHECKS[entry.network] ? '' : ' · not available in this version'}`), el('code', 'address-book-address', entry.address));
    const actions = el('span', 'address-book-row-actions');
    const armed = addressBookDeleteArmed === entry.id;
    actions.append(
      small('Edit', () => editAddress(entry.id)),
      small(armed ? 'Confirm delete' : 'Delete', () => void deleteAddress(entry.id)));
    if (armed) actions.append(small('Keep', () => { addressBookDeleteArmed = null; renderAddressBook(); }));
    row.append(main, actions);
    return row;
  }) : wallet ? [el('p', 'hint', 'No saved addresses yet. Add one below, or save a recipient after you send.')] : []));
  renderRecipientBook();
}
// Every change: the list in memory first, then saved (a saved wallet).
async function commitAddressBook(next, done) {
  const source = wallet;
  addressBook = next; addressBookNote = ''; addressBookUnreadable = false; renderAddressBook();
  let saved;
  try { saved = await persistAddressBook(); }
  catch { if (wallet === source) addressBookStatus(`${done} It could not be saved on this device (the browser refused); it is kept until you lock.`); return; }
  if (wallet !== source) return;
  addressBookStatus(saved ? done : `${done} It is kept until you lock (this wallet is not saved on this device).`);
}
function editAddress(id) {
  const entry = addressBook.find(e => e.id === id);
  if (!entry) return;
  addressBookEditing = id;
  $('address-book-label').value = entry.label;
  // A network this version cannot check is not in the selector: such an
  // entry can be renamed only by deleting and saving it again.
  if (!ADDRESS_CHECKS[entry.network]) { resetAddressForm(); addressBookStatus('This address is of a network this version does not offer; it can only be deleted here.'); return; }
  $('address-book-network').value = entry.network; $('address-book-address').value = entry.address;
  $('address-book-form-title').textContent = 'Change an address';
  $('address-book-save').textContent = 'Save changes';
  $('address-book-cancel').hidden = false;
  addressBookStatus('');
  $('address-book-label').focus();
}
async function deleteAddress(id) {
  if (!wallet) return;
  if (addressBookDeleteArmed !== id) { addressBookDeleteArmed = id; renderAddressBook(); return; }
  addressBookDeleteArmed = null;
  if (addressBookEditing === id) resetAddressForm();
  await commitAddressBook(removeAddress(addressBook, id), 'Address deleted.');
}
$('address-book-form').onsubmit = async event => {
  event.preventDefault();
  if (!wallet) return;
  try {
    const fields = { label: $('address-book-label').value, network: $('address-book-network').value, address: $('address-book-address').value };
    const editing = addressBookEditing;
    const next = editing ? updateAddress(addressBook, editing, fields, ADDRESS_CHECKS) : addAddress(addressBook, fields, ADDRESS_CHECKS);
    resetAddressForm();
    await commitAddressBook(next, editing ? 'Address changed.' : 'Address saved.');
    if (lastSentRecipient && findAddress(addressBook, lastSentRecipient.chain, lastSentRecipient.address)) hideSaveRecipient();
  } catch (error) { addressBookStatus(error.message); }
};
$('address-book-cancel').onclick = () => { resetAddressForm(); addressBookStatus(''); };
// The send form: the saved entries of the selected network, then (Nodus
// Connect) the contacts for NODUS; each address checked again here, and the
// wallet's own address left out.
function recipientChoices(chain) {
  if (!wallet || !ADDRESS_CHECKS[chain]) return [];
  const saved = addressesFor(addressBook, chain).map(e => ({ label: e.label, address: e.address, group: 'Address book' }));
  const extra = [];
  for (const r of gather('recipients', { network: chain })) {
    if (!r || typeof r.label !== 'string' || !r.label || r.label.length > 64) continue;
    let address;
    try { address = checkAddress(chain, r.address, ADDRESS_CHECKS); } catch { continue; }
    if ([...saved, ...extra].some(c => c.address === address)) continue;
    extra.push({ label: r.label, address, group: 'Contacts' });
  }
  return [...saved, ...extra].filter(c => c.address !== wallet.addresses[chain]);
}
function renderRecipientBook() {
  const chain = $('chain').value, choices = recipientChoices(chain);
  recipientChoicesShown = choices;
  const select = $('recipient-saved'), groups = new Map();
  choices.forEach((c, index) => {
    if (!groups.has(c.group)) { const group = document.createElement('optgroup'); group.label = c.group; groups.set(c.group, group); }
    groups.get(c.group).append(new Option(`${c.label} · ${shortAddress(c.address)}`, String(index)));
  });
  select.replaceChildren(new Option('Saved recipients…', ''), ...groups.values());
  const current = choices.findIndex(c => c.address === $('recipient').value.trim());
  select.value = current >= 0 ? String(current) : '';
  $('recipient-book').hidden = choices.length === 0;
}
$('recipient-saved').onchange = () => {
  const choice = recipientChoicesShown[Number($('recipient-saved').value)];
  if ($('recipient-saved').value === '' || !choice) return;
  $('recipient').value = choice.address;
};
// The list is read again when the recipient field is used (contacts can
// change while the wallet is open); a typed address that differs from the
// chosen one clears the choice.
$('recipient').addEventListener('focus', renderRecipientBook);
$('recipient').addEventListener('input', () => {
  const choice = recipientChoicesShown[Number($('recipient-saved').value)];
  if ($('recipient-saved').value !== '' && choice?.address !== $('recipient').value.trim()) $('recipient-saved').value = '';
});
// After a plain send: offer to save its recipient (the address the transfer
// was built for — for a chain name, the address the name resolved to).
function hideSaveRecipient() { lastSentRecipient = null; $('save-recipient-row').hidden = true; $('save-recipient-text').textContent = ''; }
function offerSaveRecipient(chain, to, suggested) {
  hideSaveRecipient();
  if (!wallet || !ADDRESS_CHECKS[chain]) return;
  let address;
  try { address = checkAddress(chain, to, ADDRESS_CHECKS); } catch { return; }
  if (findAddress(addressBook, chain, address) || address === wallet.addresses[chain]) return;
  lastSentRecipient = { chain, address, suggested: typeof suggested === 'string' ? suggested : '' };
  $('save-recipient-text').textContent = `${shortAddress(address)} is not in your address book.`;
  $('save-recipient-row').hidden = false;
}
$('save-recipient').onclick = () => {
  if (!wallet || !lastSentRecipient) return;
  resetAddressForm();
  $('address-book-network').value = lastSentRecipient.chain;
  $('address-book-address').value = lastSentRecipient.address;
  $('address-book-label').value = lastSentRecipient.suggested;
  addressBookStatus('Give this address a name, then press Save address.');
  $('address-book-panel').scrollIntoView({ block: 'start' });
  $('address-book-label').focus({ preventScroll: true });
};
function clearAddressBook() {
  addressBook = []; addressBookNote = ''; addressBookUnreadable = false; addressBookDeleteArmed = null; recipientChoicesShown = [];
  resetAddressForm(); addressBookStatus(''); hideSaveRecipient();
  $('recipient-saved').replaceChildren(new Option('Saved recipients…', '')); $('recipient-book').hidden = true;
  $('address-book-list').replaceChildren(); $('address-book-storage').textContent = '';
}
function followSubmission() {
  const follow = submissionFollow;
  if (!follow) return;
  const text = submissionStatus(follow.record, follow);
  if (text === null || text === follow.shown) return;
  follow.shown = text; $('wallet-status').textContent = follow.link ? `${text} ` : text;
  sessionLog.log(logCategoryFor(follow.record.kind), text, { error: ['failed', 'expired', 'replaced'].includes(follow.record.status) });
  if (follow.link) $('wallet-status').append(explorerLink(follow.record.chain, follow.record.hash));
  if (terminal(follow.record.status)) submissionFollow = null;
}
for (const { network, asset } of leadingNetworks) $('chain').add(new Option(network.name, asset.chain));
for (const [key, chain] of Object.entries(CHAINS)) $('chain').add(new Option(chain.name, key));
for (const { network, asset } of extraNetworks) $('chain').add(new Option(network.name, asset.chain));
// The portfolio scope line. Its NODUS sentence follows the actual state: the
// balance is read only while the send module is ready (setNodusReady), and
// even then it is a testnet balance, never priced into the total. The default
// (no CPUNK, no Ixios) is index.html's own text.
const NODUS_SCOPE = {
  false: 'NODUS is shown, but its balance is not shown yet.',
  true: 'The NODUS balance is shown (Nodus testnet), but it does not count toward the estimated total.'
};
let portfolioScope = nodus => `Supported assets on Ethereum, BNB Smart Chain, Solana and TRON. ${nodus} Only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total. CPUNK is not included.`;
if (CPUNK_ENABLED) {
  // With the CPUNK module enabled its balance IS shown here, just never
  // priced into the total.
  portfolioScope = nodus => `Supported assets on Ethereum, BNB Smart Chain, Solana, TRON and Cellframe. ${nodus} The CPUNK balance is shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total.`;
}
if (import.meta.env.VITE_ENABLE_IXIOS === 'true') {
  portfolioScope = CPUNK_ENABLED
    ? nodus => `Supported assets on Ethereum, BNB Smart Chain, Solana, TRON, Cellframe and Ixios. ${nodus} CPUNK and IXIOS balances are shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total.`
    : nodus => `Supported assets on Ethereum, BNB Smart Chain, Solana, TRON and Ixios. ${nodus} The IXIOS balance is shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total. CPUNK is not included.`;
}
function showPortfolioScope(nodusReady) { $('portfolio-scope').textContent = portfolioScope(NODUS_SCOPE[nodusReady === true]); }
showPortfolioScope(false);
function expireIdle() {
  if (idleDeadline && Date.now() >= idleDeadline) { lock(); return true; }
  return false;
}
function activity() {
  if (expireIdle()) return;
  clearTimeout(lockTimer);
  // A tab that took the session over holds it before the wallet is reopened;
  // the same idle lock gives it back if nobody reopens it here.
  const sensitive = wallet || sessionRelease || !$('phrase-form').hidden || $('unlock-wallet').disabled || $('vault-save').disabled || ['unlock-password', 'vault-password', 'vault-confirm-password', 'vault-old-password'].some(id => $(id).value);
  if (sensitive) { idleDeadline = Date.now() + 10 * 60 * 1000; lockTimer = setTimeout(lock, 10 * 60 * 1000); }
}
for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, activity);
document.addEventListener('visibilitychange', () => { if (!document.hidden) expireIdle(); });
window.addEventListener('focus', expireIdle);
function closeReview() { clearTimeout(confirmEnableTimer); pending?.cancel(); pending = undefined; $('review-dialog').close(); $('review-details').replaceChildren(); $('review-error').textContent = ''; }
$('review-dialog').addEventListener('keydown', event => { if (event.key === 'Enter' && $('confirm-send').disabled) event.preventDefault(); });
// NODUS leaves receive-only mode only while `ready` (a module client that
// finished unlock for the open wallet); any other state restores it.
function setNodusReady(ready, { reselect = true } = {}) {
  const network = nodusNetworkFor(ready, { module: NODUS_HAS_MODULE });
  if (receiveOnlyNetworks[NODUS_ASSET.chain] === network) return;
  receiveOnlyNetworks[NODUS_ASSET.chain] = network;
  if (!ready && wallet) wallet.nodusClient = undefined;
  if (!ready) { claimCheck++; portfolio.setAction(NODUS_ASSET.chain, undefined); hideStaking(); hideName(); }
  portfolio.setNetwork(NODUS_ASSET.chain, network);
  showPortfolioScope(ready);
  if (reselect && wallet && $('chain').value === NODUS_ASSET.chain) selectChain();
}
// Lock order lives in the client (src/nodus/client.js lock): stop the queue ->
// C cancel flag -> close the WebSocket -> zero module memory -> release.
function stopNodusSend(options) {
  clearNodusRetry();
  const client = nodusClient; nodusClient = undefined;
  // Extensions on this client (Messages) close first (design rev 5 §1.8).
  if (client) raise('nodusClosing', {});
  client?.lock();
  setNodusReady(false, options);
}
// RECONNECT (operator 2026-10-03: Nodus Connect sometimes showed no NODUS
// balance, no Earn and "Sending NODUS is not available in this release"
// until the page was reloaded). Cause: NODUS leaves receive-only mode only
// when ONE client.unlock() succeeds (setNodusReady(true) below); a first
// connection that failed — no pinned node answered in time
// (nodus-send-wasm.c nsw_unlock -> nodus_client_connect, each step bounded
// by the 5 s connect timeout of nodus_client.c), the module file did not
// load, the chain check failed — ended in the catch below and nothing ever
// tried again, and a client is single-use (src/nodus/client.js unlock), so
// only a lock / reopen or a reload made a new one. Likewise a ready client
// that later fell into 'error' (its keepalive failed) stayed down. Now a
// failed or lost connection is tried again with a NEW client after a fixed,
// growing wait (no randomness), for as long as the same wallet is open;
// success restores the sendable network, the balance, Earn, the name and
// the extensions (Messages, vaults) exactly as the first open does.
const NODUS_RETRY_MS = [5000, 10000, 20000, 40000, 60000];
let nodusRetryTimer, nodusRetries = 0;
function clearNodusRetry() { clearTimeout(nodusRetryTimer); nodusRetryTimer = undefined; }
// `again`: the step to retry (connectNodus on the same identified client);
// none = a new client (startNodusSend).
// @return the wait in seconds (for the status line).
function scheduleNodusRetry(source, address, again) {
  const fresh = !again;
  if (fresh) again = () => startNodusSend(source, address);
  clearNodusRetry();
  const wait = NODUS_RETRY_MS[Math.min(nodusRetries, NODUS_RETRY_MS.length - 1)];
  nodusRetries++;
  sessionLog.log('net', `retry ${nodusRetries} in ${wait / 1000} s (${fresh ? 'new connection' : 'same connection'})`);
  nodusRetryTimer = setTimeout(() => {
    nodusRetryTimer = undefined;
    if (source === wallet && !source.locked && source.addresses.nodus === address) void again();
  }, wait);
  return wait / 1000;
}
// Started once the Nodus address is derived, so the module's own identity can
// be checked against it (client.identify). Never runs while no module exists.
//
// LOCAL FIRST (operator 2026-10-04: Connect must show what it keeps before
// the network): the client is first IDENTIFIED (no session, nothing sent),
// extensions are told at once (nodusIdentified — Messages opens from this
// device's history), then the session is opened (connectNodus). A failed
// connection attempt keeps the identified client and the extensions' view
// and is tried again ON THE SAME CLIENT after the RECONNECT wait; only a
// failed identify, a node of another chain (final — the client locks
// itself) or a lost ready connection end the client.
async function startNodusSend(source, address) {
  stopNodusSend();
  let wasReady = false;
  // Each connection step of this client goes to the session log as
  // "attempt N · <step> <ms> ok|failed|timed out" (N = retries since the
  // last success + 1), "stuck" past the CONNECT WATCHDOG bound.
  const client = createNodusClient({ factory: nodusSendModuleFactory, steps: stepLog(sessionLog, 'net', () => nodusRetries + 1, NODUS_CONNECT_BOUND_MS), onState: state => {
    // The bar follows this client's progress (amber while connecting, green
    // when ready). 'error' / 'locked' are not shown here: the code that
    // decides whether the connection is tried again (below, startNodusSend,
    // connectNodus) sets amber or red right after them.
    if (client === nodusClient && state !== 'error' && state !== 'locked') setNetStatus(netLevelFor(state));
    if (client !== nodusClient || state === 'ready') return;
    // A failed identify or connection attempt is handled where it is made
    // (startNodusSend, connectNodus); only a client that was ready and then
    // failed is handled here.
    if (!wasReady) return;
    // The client failed after it was ready: extensions on it close too, and
    // a new connection is tried (RECONNECT above).
    if (state === 'locked' || state === 'error') {
      raise('nodusClosing', { reason: 'The connection to the Nodus network was lost. Reconnecting by itself…' });
      setNodusReady(false);
      if (source === wallet && !source.locked) {
        const seconds = scheduleNodusRetry(source, address);
        setNetStatus('connecting');
        $('nodus-address-status').textContent = `Derived locally from this wallet’s recovery phrase. The connection to the Nodus network was lost; trying again in ${seconds} seconds.`;
      }
      return;
    }
    setNodusReady(false);
  } });
  nodusClient = client;
  const current = () => client === nodusClient && source === wallet && !source.locked;
  let seed;
  try {
    const { nodusSigningSeed } = await import('./nodus/derive.js');
    if (!current()) { client.lock(); return; }
    seed = nodusSigningSeed(source.recoveryPhrase);
    await client.identify({ seed, fingerprint: address });
    if (!current()) { client.lock(); return; }
  } catch (error) {
    if (client === nodusClient) {
      const why = error?.message ? ` (${error.message})` : '';
      raise('nodusUnavailable');
      if (source === wallet && !source.locked) {
        const seconds = scheduleNodusRetry(source, address);
        setNetStatus('connecting');
        $('nodus-address-status').textContent = `Derived locally from this wallet’s recovery phrase. Nodus balance and sending are unavailable right now${why}; trying again in ${seconds} seconds.`;
      }
    }
    return;
  } finally { seed?.fill(0); }
  // The saved wallet's id only when this wallet is the unlocked saved copy
  // (activitySession is set by unlock or by saving it here).
  // Asked with gather, not raise: an extension answers with the promise of
  // its LOCAL open (Messages: history store, kept profiles — each a queue
  // slot of this client), and the connection waits for it. The client runs
  // one operation at a time; a connection attempt queued first would hold
  // every local step behind its network waits.
  const opening = gather('nodusIdentified', { client, phrase: source.recoveryPhrase, vaultId: activitySession?.id ?? null, fresh: walletFresh });
  await Promise.allSettled(opening.filter(step => typeof step?.then === 'function'));
  await connectNodus(source, address, client, () => { wasReady = true; });
}
// One connection attempt of an identified client (startNodusSend). Success:
// exactly what the first open always did. A failure that may be retried
// keeps the client and the extensions' view (nodusConnectFailed) and tries
// again on the SAME client after the RECONNECT wait; a final one (the node
// serves another chain: the client has locked itself) closes the
// extensions and is not retried.
async function connectNodus(source, address, client, markReady) {
  const current = () => client === nodusClient && source === wallet && !source.locked;
  if (!current()) return;
  try {
    await client.connectNetwork();
    if (!current()) return;
    markReady(); nodusRetries = 0;
    source.nodusClient = client;
    setNetStatus('connected');
    $('nodus-address-status').textContent = 'Derived locally from this wallet’s recovery phrase.';
    setNodusReady(true);
    portfolio.setAddress(NODUS_ASSET.chain, address);
    void refreshClaim();
    void refreshStaking();
    void refreshName();
    // lockedInputs(): coins of this wallet's pending NODUS transactions
    // (src/adapters/nodus.js lockedInputs) — an extension that builds from
    // the wallet's coins (smart contracts, src/evm/ui.js) never offers them.
    // evmRecord / evmPending: the smart-contract panel's Activity row and
    // its one-pending reservation (recordEvmActivity / evmPendingRows).
    raise('nodusReady', {
      client, phrase: source.recoveryPhrase, vaultId: activitySession?.id ?? null, fresh: walletFresh,
      lockedInputs: () => (wallet === source ? adapters.nodus.lockedInputs(history.filter(row => row.address === source.addresses.nodus)) : new Set()),
      evmRecord: (details, what) => recordEvmActivity(source, details, what),
      evmPending: () => evmPendingRows(source)
    });
  } catch (error) {
    if (!current()) return;
    const why = error?.message ? ` (${error.message})` : '';
    // CONNECT WATCHDOG (src/nodus/client.js NODUS_CONNECT_BOUND_MS): the
    // attempt did not settle in time and the client locked itself — its
    // queue was held by the hung call, so it cannot be tried again. The
    // extensions on it close now and a NEW client is made after the
    // RECONNECT wait (startNodusSend, which first locks this one again —
    // a no-op — so there is never a second live client). This client is
    // dropped here: its late results were already discarded by its lock,
    // and the current() checks keep it away from the next one.
    if (error?.timedOut === true) {
      nodusClient = undefined;
      raise('nodusClosing', { reason: 'The Nodus network did not answer in time. Reconnecting by itself…' });
      setNodusReady(false);
      const seconds = scheduleNodusRetry(source, address);
      setNetStatus('connecting');
      $('nodus-address-status').textContent = `Derived locally from this wallet’s recovery phrase. Nodus balance and sending are unavailable right now${why}; trying again in ${seconds} seconds.`;
      return;
    }
    if (client.identified) {
      const seconds = scheduleNodusRetry(source, address, () => connectNodus(source, address, client, markReady));
      raise('nodusConnectFailed', { reason: `Not connected to the network right now; trying again in ${seconds} seconds. Your messages on this device are shown.` });
      setNetStatus('connecting');
      $('nodus-address-status').textContent = `Derived locally from this wallet’s recovery phrase. Nodus balance and sending are unavailable right now${why}; trying again in ${seconds} seconds.`;
      return;
    }
    // Final: the client locked itself (it reached a node of another chain).
    nodusClient = undefined;
    raise('nodusClosing', { reason: 'The Nodus network could not be verified. Lock and open your wallet again to retry.' });
    setNodusReady(false);
    setNetStatus('offline');
    $('nodus-address-status').textContent = `Derived locally from this wallet’s recovery phrase. Nodus balance and sending are unavailable${why}. Lock and reopen your wallet to retry.`;
  }
}
// SMART CONTRACTS (src/evm/ui.js, red-team 1 F8): an EVM transaction is
// recorded in Activity exactly like a NODUS send — recordActivity's NODUS
// row (hash = intent id, expiryHeight, fromHeight, inputs), so
// adapters.nodus.lockedInputs holds its coins against every other send and
// the tracker (checkRow) resolves it by block scan — and made durable
// BEFORE its envelope leaves the browser (the confirm-send rule). `to` is
// this wallet's own address: the EVM account is bound to it, and it is the
// marker evmPendingRows reads after a reload (src/activity-storage.js does
// not keep `kind`; a reloaded row reads as a NODUS transfer to this wallet's
// own address, like a staking or name row). `what`: { title, amount } —
// the panel's action and the NODUS leaving the coins (amount + fee).
async function recordEvmActivity(source, details, { title, amount } = {}) {
  if (wallet !== source || source.locked) throw new Error('The wallet was locked. Nothing was sent.');
  // An unsaved wallet keeps no Activity (persistActivity saves nothing
  // without activitySession), so the record could not be durable: refuse
  // before any row exists (red-team 2; the NODUS send path is unchanged).
  requireSavedForEvm(!!activitySession);
  // the saved Activity refuses a row whose amount is not this decimal form
  // (src/activity-storage.js) — never write one that would make it unreadable
  if (typeof amount !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(amount)) throw new Error('Invalid smart-contract record. Nothing was sent.');
  const own = source.addresses.nodus;
  const record = recordActivity({ chain: NODUS_ASSET.chain, from: own, to: own, symbol: NODUS_ASSET.symbol, amount }, details);
  record.kind = 'evm'; record.evmTitle = typeof title === 'string' ? title : '';
  record.note = 'Smart-contract transaction signed; sending.';
  history.push(record); renderActivity(false);
  // The signed hash must be durable before the first network submission.
  // If it cannot be saved nothing is sent (src/evm/contract.js confirm
  // submits only after this resolves), so the row is withdrawn again.
  try { await persistActivity({ required: true }); }
  catch (error) {
    const at = history.indexOf(record);
    if (at >= 0) history.splice(at, 1);
    renderActivity(false);
    throw error;
  }
  trackActivity();
}
// The one-pending reservation of the smart-contract account (operator
// decision 2026-10-04-nodus-evm-kurultay-k2-summary.md #2), read from Activity:
// every unresolved NODUS row of this wallet that may be an EVM transaction
// — marked 'evm' in this tab, or (after a reload, `kind` not kept) any row
// to this wallet's own address. It over-matches self-transfers and name
// registrations (the next smart-contract transaction then waits for them
// too); it never misses an EVM row. A claim row is never one.
function evmPendingRows(source) {
  if (wallet !== source || source.locked) return [];
  const own = source.addresses.nodus;
  return history.filter(row => row.chain === NODUS_ASSET.chain && row.address === own && !terminal(row.status) && !adapters.nodus.isClaimRow(row)
    && (row.kind === 'evm' || (row.kind === undefined && row.to === own))).map(row => ({ hash: row.hash, expiryHeight: row.expiryHeight }));
}
// "1234567.5" -> "1,234,567.5" (display only).
function groupDigits(text) { const [whole, fraction] = text.split('.'); return whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',') + (fraction ? `.${fraction}` : ''); }
// GENESIS CLAIM (0.1.26): offers "Claim your allocation" under the NODUS
// asset while the connected module reports an allocation for this wallet
// that is claimable now (src/adapters/nodus.js claimStatus) and no claim of
// it is still unresolved in Activity. Any failure withdraws the offer.
async function refreshClaim() {
  const client = nodusClient, source = wallet, check = ++claimCheck;
  portfolio.setAction(NODUS_ASSET.chain, undefined);
  if (!client || !source || source.locked || !client.claimable) return;
  try {
    const status = await adapters.nodus.claimStatus({ client, from: source.addresses.nodus });
    if (check !== claimCheck || client !== nodusClient || source !== wallet || source.locked) return;
    const unresolved = history.some(row => row.address === source.addresses.nodus && adapters.nodus.isClaimRow(row) && !terminal(row.status));
    if (!status.claimable || unresolved) return;
    const amount = groupDigits(status.amountText.replace(/ NODUS$/, ''));
    portfolio.setAction(NODUS_ASSET.chain, {
      label: `Claim your allocation (${amount} NODUS)`,
      note: `An allocation of ${amount} NODUS is waiting for this wallet. Claiming it adds it to your NODUS balance.`,
      run: button => void startClaim(button)
    });
  } catch (error) {
    // Not silent (operator 2026-09-30 could not see the offer and had no way
    // to tell why): say the check failed and let it be retried.
    if (check !== claimCheck || client !== nodusClient || source !== wallet || source.locked) return;
    portfolio.setAction(NODUS_ASSET.chain, {
      label: 'Check for a NODUS allocation again',
      note: `Could not check whether an allocation is waiting for this wallet: ${error?.message || 'unknown error'}`,
      run: () => void refreshClaim()
    });
  }
}
// STAKING (0.1.29): the "Delegate NODUS" panel, shown while the connected
// module offers staking (src/nodus/client.js stakeable). Every read and
// every build goes through src/adapters/nodus.js (stakingOverview,
// prepareStake); a read started under an older stakeCheck is dropped.
let stakeCheck = 0, stakeView;
// The validator row whose delegation controls are open (operator
// 2026-10-03: clicking a validator opens its controls in that row — your
// delegation with "add more" / "withdraw", or an amount and "delegate" —
// instead of a separate form with a validator drop-down). Kept across the
// re-reads of refreshStaking, together with the amounts typed in it
// (renderStaking); one row at a time. A submitted delegate / add-more /
// withdraw closes it (closeStakeRow).
let expandedValidator;
const STAKE_KINDS = ['delegate', 'undelegate', 'stake'];
const ACTION_WORD = { claim: 'Claiming', delegate: 'Delegating', undelegate: 'Undelegating', stake: 'Bonding', name: 'Registering a name' };
const CONFIRM_TEXT = { claim: 'Confirm & claim', delegate: 'Confirm & delegate', undelegate: 'Confirm & undelegate', stake: 'Confirm & bond', name: 'Confirm & register' };
const nodusAmountText = units => groupDigits(formatUnits(units, NODUS_ASSET.decimals));
// Earn (0.1.31): the staking panel is reached from an "Earn" button beside
// Send / Receive, a navigation link and the NODUS portfolio row. All three
// exist only while the panel does.
function setEarnAvailable(available) {
  $('quick-earn').hidden = !available; $('nav-earn').hidden = !available;
  portfolio.setEarn(NODUS_ASSET.chain, available);
}
// The right-hand column shows EITHER the Send / Receive panel OR the Earn
// (staking) panel (operator, 2026-10-01): Earn swaps Send / Receive out,
// Send or Receive swaps it back. Earn mode needs staking to be available.
let earnMode = false;
function showEarn(on) {
  earnMode = !!on && !$('quick-earn').hidden;
  $('send-form').hidden = earnMode; $('stake-panel').hidden = !earnMode;
  $('quick-earn').setAttribute('aria-pressed', String(earnMode));
}
function hideStaking() {
  stakeCheck++; stakeView = undefined; expandedValidator = undefined; setEarnAvailable(false);
  showEarn(false); $('validator-list').replaceChildren(); $('delegation-list').replaceChildren(); $('unlisted-delegations').hidden = true;
  $('stake-status').textContent = '';
}
async function refreshStaking() {
  const client = nodusClient, source = wallet, check = ++stakeCheck;
  if (!client || !source || source.locked || !client.stakeable) { hideStaking(); return; }
  const current = () => check === stakeCheck && client === nodusClient && source === wallet && !source.locked;
  setEarnAvailable(true); $('stake-status').textContent = 'Reading witnesses and your delegations…';
  try {
    const view = await adapters.nodus.stakingOverview({ client, from: source.addresses.nodus });
    if (!current()) return;
    stakeView = view; renderStaking(view);
    $('stake-status').textContent = view.truncated ? 'The witness list is longer than this wallet shows; only the first witnesses are listed.' : '';
  } catch (error) {
    if (!current()) return;
    $('stake-status').textContent = `Could not read witnesses or delegations: ${error?.message || 'unknown error'} Use Refresh to try again.`;
  }
}
function renderStaking(view) {
  const { rules } = view;
  const minText = nodusAmountText(rules.minDelegation);
  const rate = bps => `${(bps / 100).toFixed(2).replace(/\.?0+$/, '')}%`;
  // Rows are laid out like portfolio holding rows (src/portfolio-view.js):
  // identity and figures on the left, status on the right. The whole row
  // header is one button that opens or closes the row's own delegation
  // controls below it.
  const el = (tag, className, text) => { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const mine = new Map(view.delegations.map(d => [d.validator, d]));
  if (expandedValidator && !view.validators.some(v => v.fingerprint === expandedValidator)) expandedValidator = undefined;
  // What was typed in the open row survives this redraw (a background
  // re-read, e.g. another transaction becoming final): only the amounts the
  // person edited — the withdraw box's pre-filled amount follows the new
  // figures — and only while the same row stays open. Keyboard focus and the
  // cursor position in that box come back too. Closing the row, or opening
  // another one, drops it.
  const drafts = new Map(); let focused;
  const shown = $('validator-list').querySelector('.stake-detail');
  if (expandedValidator && shown?.dataset.validator === expandedValidator) {
    for (const input of shown.querySelectorAll('input[data-field]')) {
      if (input.dataset.edited) drafts.set(input.dataset.field, input.value);
      if (input === document.activeElement) focused = { field: input.dataset.field, start: input.selectionStart, end: input.selectionEnd };
    }
  }
  const amountInput = (label, field, value = '') => {
    const input = document.createElement('input'); input.inputMode = 'decimal'; input.autocomplete = 'off'; input.spellcheck = false; input.placeholder = '0.00';
    input.dataset.field = field;
    if (drafts.has(field)) { input.value = drafts.get(field); input.dataset.edited = 'true'; } else input.value = value;
    input.addEventListener('input', () => { input.dataset.edited = 'true'; });
    input.setAttribute('aria-label', label); return input;
  };
  const actionButton = (text, run) => { const button = el('button', 'small', text); button.type = 'button'; button.onclick = () => void run(button); return button; };
  $('validator-list').replaceChildren(...(view.validators.length ? view.validators.map(v => {
    const short = adapters.nodus.shortKey(v.fingerprint), d = mine.get(v.fingerprint), open = expandedValidator === v.fingerprint;
    // Filled delegator places of the chain's per-validator cap; '?' when the
    // node's answer carries no count (an older node) — never shown as 0.
    const slots = `${v.delegators === null ? '?' : v.delegators}/${rules.maxDelegators}`;
    const full = v.delegators !== null && BigInt(v.delegators) >= rules.maxDelegators;
    const row = el('div', 'stake-row');
    row.title = v.fingerprint;
    const toggle = el('button', 'stake-row-toggle'); toggle.type = 'button';
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', `Witness ${short}${d ? `, your delegation ${nodusAmountText(d.amount)} NODUS` : ''}. ${open ? 'Close' : 'Open'} delegation controls`);
    const name = el('span', 'stake-main');
    name.append(el('strong', '', short),
      el('small', '', `own stake ${nodusAmountText(v.selfStake)} NODUS · delegated ${nodusAmountText(v.delegated)} NODUS · commission ${rate(v.commissionBps)} · delegators ${slots}`));
    if (d) name.append(el('small', 'stake-mine', `Your delegation: ${nodusAmountText(d.amount)} NODUS`));
    const badge = el('span', 'status-badge', v.statusText); badge.dataset.status = v.status;
    toggle.append(name, badge);
    toggle.dataset.validator = v.fingerprint;
    // The list is drawn again; keyboard focus returns to this row's header.
    toggle.onclick = () => {
      expandedValidator = open ? undefined : v.fingerprint; renderStaking(view);
      $('validator-list').querySelector(`button[data-validator="${v.fingerprint}"]`)?.focus({ preventScroll: true });
    };
    row.append(toggle);
    if (!open) return row;
    const detail = el('div', 'stake-detail');
    detail.dataset.validator = v.fingerprint;
    if (d) {
      detail.append(el('p', 'hint', `You have ${nodusAmountText(d.amount)} NODUS delegated to this witness.`));
      if (v.acceptsDelegation) {
        const more = amountInput(`Amount to add to your delegation with ${short}`, 'more');
        const add = el('span', 'stake-actions');
        add.append(more, actionButton('Review adding more', button => startStake('delegate', { validator: v.fingerprint, amount: more.value }, button)));
        detail.append(add, el('p', 'hint', 'Adding to your delegation can be any amount. A network fee is paid on top.'));
      } else detail.append(el('p', 'hint', `This witness does not take more delegations now (${v.statusText}).`));
      const back = amountInput(`Amount to withdraw from ${short}`, 'withdraw', formatUnits(d.amount, NODUS_ASSET.decimals));
      const withdraw = el('span', 'stake-actions');
      withdraw.append(back, actionButton('Review withdrawal', button => startStake('undelegate', { validator: v.fingerprint, amount: back.value }, button)));
      detail.append(withdraw, el('p', 'hint', `Withdrawing returns the NODUS to your address as a separate coin that stays locked for ${view.lockText} after the witness set next changes. Until then it cannot be sent or delegated again. Withdraw everything, or leave at least ${minText} NODUS delegated. The network fee is paid from your spendable NODUS.`));
    } else if (!v.acceptsDelegation) {
      detail.append(el('p', 'hint', `This witness does not take delegations now (${v.statusText}).`));
    } else if (full) {
      detail.append(el('p', 'hint', `All ${rules.maxDelegators} delegator places of this witness are taken. Choose another witness.`));
    } else {
      const amount = amountInput(`Amount to delegate to ${short}`, 'amount');
      const actions = el('span', 'stake-actions');
      actions.append(amount, actionButton('Review delegation', button => startStake('delegate', { validator: v.fingerprint, amount: amount.value }, button)));
      detail.append(actions, el('p', 'hint', `A new delegation is at least ${minText} NODUS. A network fee is paid on top. You review every detail before anything is sent.`));
    }
    row.append(detail);
    return row;
  }) : [el('p', 'stake-empty', 'No witnesses listed.')]));
  if (focused) {
    const input = $('validator-list').querySelector(`.stake-detail input[data-field="${focused.field}"]`);
    if (input) {
      input.focus({ preventScroll: true });
      if (focused.start !== null && focused.end !== null) input.setSelectionRange(Math.min(focused.start, input.value.length), Math.min(focused.end, input.value.length));
    }
  }
  // A delegation whose validator is not in the list above has no row to
  // live on; it is listed here (it cannot be withdrawn from this page: the
  // module needs the validator's key from the list).
  const unlisted = view.delegations.filter(d => !d.canUndelegate);
  $('unlisted-delegations').hidden = unlisted.length === 0;
  $('delegation-list').replaceChildren(...unlisted.map(d => {
    const row = el('div', 'stake-row');
    const name = el('span', 'stake-main');
    name.append(el('strong', '', `${nodusAmountText(d.amount)} NODUS`), el('small', '', `with ${adapters.nodus.shortKey(d.validator)}`));
    row.append(name);
    row.title = d.validator;
    const actions = el('span', 'stake-actions');
    actions.append(el('small', 'stake-note', '(this witness is not in the list above, so it cannot be withdrawn from here)'));
    row.append(actions);
    return row;
  }));
}
// An action button that starts preparing a transaction (Send's review,
// Register, Delegate / Add more / Withdraw, Claim) shows "Preparing…" and
// stays disabled from the press until the review or the result is shown
// or the preparation fails (operator 2026-10-03: the button looked active
// while the transaction was being prepared). The `busy` flag of each
// action stays the real guard against a second press; this is what the
// person sees. Returns the function that puts the button back; `enabled`
// says whether it is usable again then (default: yes).
function showPreparing(button, { text = 'Preparing…', enabled = () => true } = {}) {
  if (!button) return () => {};
  const saved = [...button.childNodes];
  button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = text;
  return () => { button.replaceChildren(...saved); button.removeAttribute('aria-busy'); button.disabled = !enabled(); };
}
// "Become a validator" was removed from the page (operator 2026-10-03); the
// module / adapter STAKE builder (prepareStake kind 'stake') stays.
async function startStake(kind, params, button) {
  if (busy || !wallet || !STAKE_KINDS.includes(kind)) return;
  // Activity lists the selected network's records: show NODUS, where the
  // transaction will be tracked. (selectChain closes any open review first.)
  if ($('chain').value !== NODUS_ASSET.chain) { $('chain').value = NODUS_ASSET.chain; selectChain(); }
  busy = true; const current = revision, client = nodusClient, restore = showPreparing(button);
  message('Preparing the transaction and network fee…');
  try {
    const locked = adapters.nodus.lockedInputs(history.filter(row => row.address === wallet.addresses.nodus));
    const transfer = await adapters.nodus.prepareStake({ client, from: wallet.addresses.nodus, kind, locked, ...params });
    if (current !== revision || !wallet || client !== nodusClient) { transfer.cancel(); return; }
    const title = kind === 'delegate' ? 'Review delegation' : kind === 'undelegate' ? 'Review undelegation' : 'Review witness bond';
    showReview(transfer, [...transfer.review, ['Review expires', new Date(transfer.expiresAt).toLocaleTimeString()]], title);
    message('Review every detail before confirming.');
  } catch (error) { if (current === revision) message(error.message, { category: 'stake', error: true }); }
  finally { busy = false; restore(); }
}
$('stake-refresh').onclick = () => void refreshStaking();
// A delegate / add-more / withdraw that was submitted (or whose broadcast
// outcome is uncertain) closes its validator row at once, dropping the
// amount typed there, and the list is read again now; checkRow reads it once
// more when the transaction's Activity record becomes final, so "Your
// delegation", the totals and the delegator places follow without a reload
// (operator 2026-10-03: after staking, the row stayed open and the page did
// not refresh).
function closeStakeRow() {
  expandedValidator = undefined;
  if (stakeView) renderStaking(stakeView);
  void refreshStaking();
}
// Opens the review dialog for a transfer-shaped object (a send, a claim from
// src/adapters/nodus.js prepareClaim, or a staking transaction from
// prepareStake) with its own entries.
function showReview(transfer, entries, title) {
  pending = transfer; $('review-details').replaceChildren();
  $('review-title').textContent = title;
  $('review-notice').textContent = `${networkFor(transfer.chain).stage || 'Mainnet'} transaction. ${ACTION_WORD[transfer.kind] || 'Sending'} cannot be undone.`;
  for (const [key, value] of entries) {
    const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = key; dd.textContent = value;
    if (key === 'Address check' || key === 'Name check' || key === 'Timing') dd.className = 'notice';
    $('review-details').append(dt, dd);
  }
  $('confirm-send').textContent = CONFIRM_TEXT[transfer.kind] || 'Confirm & send';
  $('confirm-send').disabled = true; $('review-error').textContent = ''; $('review-dialog').showModal();
  clearTimeout(confirmEnableTimer); confirmEnableTimer = setTimeout(() => { $('confirm-send').disabled = false; }, 600);
}
async function startClaim(button) {
  if (busy || !wallet) return;
  // Activity lists the selected network's records: show NODUS, where the
  // claim will be tracked. (selectChain closes any open review first.)
  if ($('chain').value !== NODUS_ASSET.chain) { $('chain').value = NODUS_ASSET.chain; selectChain(); }
  busy = true; const current = revision, client = nodusClient, restore = showPreparing(button);
  message('Preparing your claim…');
  try {
    const transfer = await adapters.nodus.prepareClaim({ client, from: wallet.addresses.nodus });
    if (current !== revision || !wallet || client !== nodusClient) { transfer.cancel(); return; }
    showReview(transfer, [...transfer.review, ['Review expires', new Date(transfer.expiresAt).toLocaleTimeString()]], 'Review claim');
    message('Review the claim before confirming.');
  } catch (error) { if (current === revision) message(error.message, { error: true }); }
  finally { busy = false; restore(); }
}
// CHAIN NAME (HF-4): the "Chain name" block of the NODUS receive panel and
// the "Register a name" action beside Send / Receive / Earn (a new coin is
// handled like the other coins: no panel of its own). Shown while the
// connected module resolves names (src/nodus/client.js nameable); the
// registration part only while it can also register (registrable) and this
// wallet holds no name. Every read and the build go through
// src/adapters/nodus.js (ownChainName, nameQuote, prepareName); a read
// started under an older nameCheck / nameQuoteCheck is dropped.
let nameCheck = 0, nameQuoteCheck = 0, nameQuoted, nameReady = false;
function showNameBlock() { $('name-block').hidden = !(nameReady && $('chain').value === NODUS_ASSET.chain); }
function clearNameQuote() {
  nameQuoteCheck++; nameQuoted = undefined;
  $('name-review').disabled = true; $('name-quote').textContent = '';
}
function hideName() {
  nameCheck++; nameReady = false; clearNameQuote(); raise('ownName', { name: '' });
  $('quick-name').hidden = true; $('name-block').hidden = true; $('name-fields').hidden = true;
  $('own-name').textContent = ''; $('name-prices').textContent = ''; $('name-input').value = '';
}
async function refreshName() {
  const client = nodusClient, source = wallet, check = ++nameCheck;
  if (!client || !source || source.locked || !client.nameable) { hideName(); return; }
  const current = () => check === nameCheck && client === nodusClient && source === wallet && !source.locked;
  nameReady = true; showNameBlock();
  $('own-name').textContent = 'Reading your chain name…';
  try {
    const own = await adapters.nodus.ownChainName({ client, from: source.addresses.nodus });
    if (!current()) return;
    // The page header shows the name only as the reverse lookup confirmed it
    // (decision 2026-10-02-onchain-names; Nodus Connect: src/connect-main.js).
    raise('ownName', { name: own.found ? own.name : '', confirmed: true });
    if (own.found) {
      $('own-name').textContent = `Your chain name is "${own.name}". People can send NODUS to you by typing this name instead of your address.`;
      $('name-fields').hidden = true; $('quick-name').hidden = true; clearNameQuote();
      return;
    }
    if (!client.registrable) {
      $('own-name').textContent = 'This wallet has no chain name. Registering one is not available in this version.';
      $('name-fields').hidden = true; $('quick-name').hidden = true;
      return;
    }
    $('own-name').textContent = 'This wallet has no chain name yet. A chain name lets people send NODUS to you by typing a short name instead of your long address. First come, first served; one name per wallet; it does not expire.';
    $('name-fields').hidden = false; $('quick-name').hidden = false;
    $('name-prices').textContent = 'Reading name prices…';
    try {
      const { prices } = adapters.nodus.parseNamePrices(await client.namePrices());
      if (current()) $('name-prices').textContent = `Prices by name length — ${adapters.nodus.namePriceList(prices)}. A network fee is added.`;
    } catch (error) {
      if (current()) $('name-prices').textContent = `Name prices could not be read: ${error?.message || 'unknown error'}`;
    }
  } catch (error) {
    if (!current()) return;
    raise('ownName', { name: '' });
    $('own-name').textContent = `Could not read your chain name: ${error?.message || 'unknown error'} Lock and reopen your wallet to retry.`;
    $('name-fields').hidden = true; $('quick-name').hidden = true;
  }
}
async function checkName() {
  const client = nodusClient, source = wallet;
  if (!client || !source || source.locked) return;
  clearNameQuote();
  const check = nameQuoteCheck, typed = $('name-input').value;
  const current = () => check === nameQuoteCheck && client === nodusClient && source === wallet && !source.locked;
  $('name-quote').textContent = 'Checking the name…';
  try {
    const quote = await adapters.nodus.nameQuote({ client, from: source.addresses.nodus, name: typed });
    if (!current()) return;
    if (quote.status === 'has-name') { $('name-quote').textContent = `This wallet already has the chain name "${quote.ownName}".`; void refreshName(); return; }
    if (quote.status === 'taken') { $('name-quote').textContent = `"${quote.name}" is already registered by someone else. Try another name.`; return; }
    nameQuoted = quote.name;
    const lowered = quote.name !== typed.trim() ? ` Names are lower-case, so it is registered as "${quote.name}".` : '';
    $('name-quote').textContent = `"${quote.name}" is available. Price: ${quote.priceText}. The network fee is shown on the review before you confirm.${lowered}`;
    $('name-review').disabled = false;
  } catch (error) { if (current()) $('name-quote').textContent = error?.message || 'The name could not be checked.'; }
}
async function startName() {
  if (busy || !wallet || !nameQuoted) return;
  if ($('chain').value !== NODUS_ASSET.chain) { $('chain').value = NODUS_ASSET.chain; selectChain(); }
  busy = true; const current = revision, client = nodusClient, name = nameQuoted;
  // Usable again only while a checked name is still quoted (clearNameQuote).
  const restore = showPreparing($('name-review'), { enabled: () => nameQuoted !== undefined });
  message('Preparing the name registration and network fee…');
  try {
    const locked = adapters.nodus.lockedInputs(history.filter(row => row.address === wallet.addresses.nodus));
    const transfer = await adapters.nodus.prepareName({ client, from: wallet.addresses.nodus, name, locked });
    if (current !== revision || !wallet || client !== nodusClient) { transfer.cancel(); return; }
    showReview(transfer, [...transfer.review, ['Review expires', new Date(transfer.expiresAt).toLocaleTimeString()]], 'Review name registration');
    message('Review every detail before confirming.');
  } catch (error) { if (current === revision) message(error.message, { category: 'names', error: true }); }
  finally { busy = false; restore(); }
}
$('name-input').addEventListener('input', clearNameQuote);
// The block sits inside #send-form: Enter checks the name, never submits a send.
$('name-input').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); void checkName(); } });
$('name-check').onclick = () => void checkName();
$('name-review').onclick = () => void startName();
function lock() {
  // Extensions close before the NODUS client (stopNodusSend raises
  // nodusClosing first), then the cross-site mark is dropped.
  stopNodusSend({ reselect: false }); nodusRetries = 0;
  siteLock.stop(); walletFresh = false;
  portfolio.clear();
  phraseFields.clear();
  nodusDerivation?.abort(); nodusDerivation = undefined;
  $('nodus-address-status').textContent = '';
  // stopNodusSend dropped the client before locking it, so its 'locked' never
  // reaches the bar: reset it here to the page's initial state.
  setNetStatus('connecting');
  cellframeDerivation?.abort(); cellframeDerivation = undefined;
  $('cellframe-address-status').textContent = '';
  stopIxiosAddress();
  revision++; vaultOperation++; activitySession = null; activityBlocked = false; latestKept = null; clearHistory(); clearAddressBook(); idleDeadline = 0; stopTracking(); closeReview(); disposeWallet(wallet); wallet = undefined; generatedPhrase = undefined;
  releaseSession(); $('session-conflict').hidden = true;
  $('discard-activity').hidden = true;
  $('phrase-form').hidden = true; $('wallet-open').hidden = true; $('welcome').hidden = false;
  history.length = 0; $('account-explorer').removeAttribute('href');
  $('activity').replaceChildren(); setReceiveAddress(''); $('balances').replaceChildren(); $('recipient').value = ''; $('amount').value = '';
  for (const id of ['unlock-password', 'vault-password', 'vault-confirm-password', 'vault-old-password']) $(id).value = '';
  $('vault-risk-confirm').checked = false; $('vault-save-status').textContent = '';
  updateVaultUI(); clearTimeout(lockTimer); message('Wallet locked. Restore your recovery phrase or unlock your saved wallet.');
  raise('locked');
  // The session log ends with the session (Device & settings → Logs);
  // `pagehide` runs this lock too.
  sessionLog.clear(); netLevelLogged = undefined;
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
    // Only the create flow reaches 'verify': words generated in this tab.
    const fresh = phraseStep === 'verify';
    if (fresh && normalizePhrase(phrase) !== generatedPhrase) throw new Error('The phrase does not match. Re-enter your saved backup.');
    // The other site (src/site-lock.js) must not have a wallet open.
    const otherSite = siteLock.otherOpen();
    if (otherSite) throw new Error(otherSite);
    // No key is derived until this tab holds the single-tab session lock.
    claimed = true; const session = await claimSession();
    if (operation !== vaultOperation) return;
    if (!session) { refuseOpen('phrase'); return; }
    if (session !== sessionRelease) return;
    wallet = deriveWallet(phrase); generatedPhrase = undefined; phraseFields.clear();
    walletFresh = fresh; siteLock.start();
    $('phrase-form').hidden = true; $('wallet-open').hidden = false; message('Wallet open. Portfolio balances load automatically.'); selectChain(); activity(); void showNodusAddress(); void showCellframeAddress(); showIxiosAddress(); focusOpenWallet();
  } catch (error) { if (operation === vaultOperation) message(error.message, { error: true }); }
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
  // A build without the NODUS module never connects: no network line at all.
  setNetStatus(nodusSendModuleFactory ? 'connecting' : 'off');
  const current = () => nodusDerivation === operation && source === wallet && !source.locked && !operation.signal.aborted;
  try {
    const { deriveNodusAddress } = await import('./nodus/derive.js');
    if (!current()) return;
    const address = await deriveNodusAddress(source.recoveryPhrase, { signal: operation.signal });
    if (!current()) return;
    source.addresses.nodus = address;
    if ($('chain').value === NODUS_ASSET.chain) setReceiveAddress(address);
    $('nodus-address-status').textContent = 'Derived locally from this wallet’s recovery phrase.';
    if (nodusSendModuleFactory) void startNodusSend(source, address);
    else raise('nodusUnavailable');
  } catch {
    if (current()) { $('nodus-address-status').textContent = 'Nodus address unavailable. Lock and reopen your wallet to retry.'; setNetStatus(nodusSendModuleFactory ? 'offline' : 'off'); raise('nodusUnavailable'); }
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
        if ($('chain').value === 'cellframe') { setReceiveAddress(address); renderHistory(); void loadHistory('cellframe'); }
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
  // "Mainnet" for every network but Nodus, whose `stage` is 'Testnet'.
  for (const label of document.querySelectorAll('.selected-network-stage')) label.textContent = c.stage || 'Mainnet';
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
  hideSaveRecipient(); renderRecipientBook();
  showNameBlock();
  renderHistory(); void loadHistory(chain);
}
$('chain').onchange = selectChain;
// Both shortcuts lead to the same Send / Receive panel: receive block on top,
// send block below it.
$('quick-send').onclick = () => {
  showEarn(false);
  $('send-block-title').focus({ preventScroll: true });
  $('send-block').scrollIntoView({ block: 'start' });
};
$('quick-receive').onclick = () => {
  showEarn(false);
  $('receive-title').focus({ preventScroll: true });
  $('receive-panel').scrollIntoView({ block: 'start' });
};
// Earn replaces the Send / Receive panel with the NODUS staking panel; the
// selected network moves to NODUS so Activity shows where a delegation is
// tracked.
$('quick-earn').onclick = () => {
  if ($('quick-earn').hidden) return;
  if ($('chain').value !== NODUS_ASSET.chain) { $('chain').value = NODUS_ASSET.chain; selectChain(); }
  showEarn(true);
  $('stake-title').focus({ preventScroll: true });
  $('stake-panel').scrollIntoView({ block: 'start' });
};
$('nav-earn').onclick = event => { event.preventDefault(); $('quick-earn').click(); };
// "Register a name" (HF-4): the NODUS receive block's "Chain name" part,
// reached like Receive; the selected network moves to NODUS.
$('quick-name').onclick = () => {
  if ($('quick-name').hidden) return;
  if ($('chain').value !== NODUS_ASSET.chain) { $('chain').value = NODUS_ASSET.chain; selectChain(); }
  showEarn(false);
  $('name-block').scrollIntoView({ block: 'start' });
  if (!$('name-fields').hidden) $('name-input').focus({ preventScroll: true });
  else $('name-title').focus({ preventScroll: true });
};
document.querySelector('.wallet-navigation a[href="#send-form"]').onclick = () => showEarn(false);
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
$('save-rpc').onclick = () => { if (!networkFor($('chain').value).rpcOptions) return; try { const chain = $('chain').value, endpoint = endpointUrl($('rpc-endpoint').value); if (chain === 'tron' && endpoint !== endpointUrl(CHAINS.tron.endpoint)) throw new Error('TRON requires the mainnet provider.'); endpoints[chain] = endpoint; revision++; closeReview(); stopTracking(); for (const row of visibleActivity()) row.endpoint = endpoints[$('chain').value]; trackActivity(); portfolio.changeEndpoint(chain, endpoint); message('RPC updated for this tab.'); } catch (error) { message(error.message, { error: true }); } };
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
  busy = true; const current = revision, restore = showPreparing($('review-button'));
  message('Preparing transfer and network fee…');
  try {
    const chain = $('chain').value;
    // NODUS: coins of this wallet's unresolved NODUS sends are not offered to
    // the builder (G7; src/adapters/nodus.js lockedInputs).
    const nodusLocked = chain === NODUS_ASSET.chain ? adapters.nodus.lockedInputs(history.filter(row => row.address === wallet.addresses.nodus)) : undefined;
    const transfer = await prepareTransfer({ wallet, chain, symbol: $('asset').value, to: $('recipient').value, amount: $('amount').value, endpoint: endpoints[chain], nodusLocked });
    if (current !== revision || !wallet) { transfer.cancel(); return; }
    let entries;
    if (transfer.review) {
      // NODUS: every value was decoded from the signed envelope (G1), not the form.
      entries = [...transfer.review, ['Review expires', new Date(transfer.expiresAt).toLocaleTimeString()]];
    } else {
      const isEvm = transfer.chain === 'ethereum' || transfer.chain === 'bsc';
      const details = { Network: `${CHAINS[transfer.chain].name} mainnet`, From: transfer.from };
      // HF-4 send to a chain name (src/wallet.js): the name, where the
      // address came from and the owner's Nodus ID, then the address itself.
      if (transfer.named) Object.assign(details, Object.fromEntries(adapters.nodus.nameReviewRows(transfer.named, { via: 'the address published in the owner’s signed profile' })));
      details.To = isEvm ? getAddress(transfer.to) : transfer.to;
      if (transfer.named) details[adapters.nodus.NAME_CHECK_ROW[0]] = adapters.nodus.NAME_CHECK_ROW[1];
      else if (isEvm && /^0x[0-9a-f]{40}$/.test(transfer.to)) details['Address check'] = 'No checksum in what you typed — compare the form above with your source character by character.';
      Object.assign(details, { Asset: transfer.symbol, Amount: transfer.amount, 'Network fee': transfer.fee });
      if (isEvm) details['Transaction number (nonce)'] = transfer.nonce;
      details['Review expires'] = new Date(transfer.expiresAt).toLocaleTimeString();
      entries = Object.entries(details);
    }
    showReview(transfer, entries, 'Review transfer'); message('Review every transfer detail before confirming.');
  } catch (error) { if (current === revision) message(error.message, { category: 'send', error: true }); }
  finally { busy = false; restore(); }
};
$('cancel-send').onclick = closeReview;
$('review-dialog').addEventListener('cancel', event => { if (busy) event.preventDefault(); else closeReview(); });
$('confirm-send').onclick = async () => {
  if (!pending || busy) return;
  busy = true; const transfer = pending, current = revision; pending = undefined; let record;
  // The action's name in the status line, now and once its record resolves
  // (followSubmission); the ID label is null where an explorer link is shown.
  const what = transfer.kind === 'delegate' ? 'Delegation' : transfer.kind === 'undelegate' ? 'Undelegation' : transfer.kind === 'stake' ? 'Witness bond'
    : transfer.kind === 'name' ? `Registration of the chain name "${transfer.name}"` : transfer.kind === 'claim' ? 'Claim' : 'Transfer';
  const idLabel = transfer.kind === 'claim' ? 'Claim ID' : transfer.kind ? 'Transaction ID' : CHAINS[transfer.chain] ? null : 'Transfer ID';
  const follow = () => { if (record) { submissionFollow = { record, what, idLabel, link: !idLabel, shown: null }; followSubmission(); } };
  $('confirm-send').disabled = true; $('cancel-send').disabled = true; $('review-error').textContent = 'Signing locally and broadcasting…';
  try {
    const hash = await transfer.confirm(async details => {
      record = recordActivity(transfer, details); history.push(record); if (current === revision) renderActivity(false);
      // The signed hash must be durable before the first network submission.
      await persistActivity({ required: true });
    });
    if (record) { record.note = 'Broadcast submitted; awaiting confirmation.'; if (current === revision) trackActivity(); }
    closeReview();
    // A submitted claim withdraws the offer while its record is unresolved.
    if (transfer.kind === 'claim') void refreshClaim();
    if (STAKE_KINDS.includes(transfer.kind)) closeStakeRow();
    if (current !== revision) return;
    // A staking row and its amount fields were closed by closeStakeRow above.
    if (transfer.kind === 'name') { $('name-input').value = ''; clearNameQuote(); }
    else if (!STAKE_KINDS.includes(transfer.kind)) { $('recipient').value = ''; $('amount').value = ''; }
    // A plain transfer: offer to save its recipient (a chain name it was
    // sent to is the suggested name).
    if (!transfer.kind) offerSaveRecipient(transfer.chain, transfer.to, transfer.named?.name || transfer.recipientName);
    if (transfer.kind) message(`${what} submitted; confirmation is pending. ${idLabel} ${hash}. Its status is tracked in Activity.`, { category: logCategoryFor(transfer.kind) });
    else {
      message('Broadcast submitted; confirmation is pending. ', { category: 'send' });
      if (CHAINS[transfer.chain]) $('wallet-status').append(explorerLink(transfer.chain, hash));
      else $('wallet-status').append(`Transfer ID ${hash}. Its status is tracked in Activity.`);
    }
    follow();
  } catch (error) {
    if (record) { record.status = 'unknown'; record.note = 'Broadcast outcome uncertain. Tracking the signed transaction; do not resend automatically.'; if (current === revision) trackActivity(); }
    closeReview();
    if (transfer.kind === 'claim') void refreshClaim();
    // Something may have reached the network (a record exists): close the
    // row as after a submission. Nothing was broadcast otherwise: the row
    // and its amount stay for another try.
    if (STAKE_KINDS.includes(transfer.kind)) { if (record) closeStakeRow(); else void refreshStaking(); }
    const uncertain = transfer.kind === 'claim'
      ? 'The outcome is tracked in Activity. An allocation is never paid out twice.'
      : transfer.chain === NODUS_ASSET.chain
      ? 'The outcome is tracked in Activity; its coins stay held until it is included or its expiry block passes.'
      : 'A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.';
    if (current === revision) { message(record ? `${error.message} ${uncertain}` : error.message, { category: logCategoryFor(transfer.kind), error: true }); follow(); }
  } finally { busy = false; $('cancel-send').disabled = false; }
};
function updateVaultUI() {
  try {
    const saved = localStorage.getItem(VAULT_KEY);
    const authenticated = !!saved && activitySession?.vault === saved;
    $('vault-password-controls').hidden = !!saved && !authenticated;
    $('vault-current-password').hidden = !authenticated;
    $('vault-password-label').textContent = authenticated ? 'New password (at least 16 characters)' : 'Password (at least 16 characters)';
    $('vault-confirm-label').textContent = authenticated ? 'Confirm new password' : 'Confirm password';
    $('vault-save').hidden = !!saved;
    $('vault-change').hidden = !authenticated;
    $('vault-storage-title').textContent = authenticated ? 'Change saved password' : saved ? 'Unlock saved wallet to change password' : 'Save wallet on this device (optional)';
    $('vault-save-explain').textContent = authenticated
      ? 'This wallet is already saved in this browser. To change its local password, enter your current password and your new password twice, tick the box, then press Change saved password. Your recovery words and wallet addresses stay the same.'
      : saved ? (wallet
        ? 'A wallet is already saved on this device. Lock this temporary session, then unlock the saved wallet with its current password before changing it.'
        : 'Unlock the saved wallet above with its current password before changing it.')
      : 'Saving keeps this wallet in this browser on this device, locked with a password you choose. Next time you open this page here, you unlock it with that password. Without saving, you type your 24 recovery words every time. To save: choose a password below, enter it again to confirm, tick the box, then press Save current wallet. A message under the button tells you when it is saved.';
    $('vault-storage-summary').textContent = authenticated
      ? 'Your recovery words and saved activity stay encrypted in this browser profile on this device. This is not a cloud backup. The wallet does not store your password or upload your recovery words.'
      : 'This saves an encrypted copy of your 24 recovery words in this browser profile on this device. It is not a cloud backup. The wallet does not store your password or upload your recovery words.';
    $('unlock-form').hidden = !!wallet || !saved;
    $('wallet-storage-state').textContent = authenticated
      ? 'Encrypted copy saved in this browser.'
      : saved ? 'Temporary session · the saved copy has not been unlocked here.' : 'Temporary session · this wallet has not been saved on this device. To keep it here, open “Save wallet on this device” below.';
  }
  catch {
    $('vault-password-controls').hidden = true;
    $('vault-current-password').hidden = true;
    $('vault-save').hidden = true; $('vault-change').hidden = true;
    $('vault-storage-title').textContent = 'Device storage unavailable';
    $('vault-save-explain').textContent = 'Device storage is unavailable. This wallet can only be used temporarily in this tab.';
    $('vault-status').textContent = 'Device storage is unavailable. Use a temporary wallet in this tab.';
    $('wallet-storage-state').textContent = 'Device storage is unavailable.';
  }
}
function focusOpenWallet(kept = {}) {
  updateVaultUI(); renderAddressBook();
  portfolio.open(wallet.addresses, endpoints, { kept });
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
    // The other site (src/site-lock.js) must not have a wallet open.
    const otherSite = siteLock.otherOpen();
    if (otherSite) throw new Error(otherSite);
    // The password is not even tried until this tab holds the single-tab session lock.
    claimed = true; const session = await claimSession();
    if (operation !== vaultOperation) return;
    if (!session) { refuseOpen('unlock'); return; }
    if (session !== sessionRelease) return;
    const saved = await decryptVault(text, password);
    if (operation !== vaultOperation || session !== sessionRelease || text !== localStorage.getItem(VAULT_KEY)) return;
    const restored = deriveWallet(saved.phrase); let key, balancesKey, historyKey, addressBookKey, rows = [], kept = {}, keptHistory = {}, keptBook = [], bookProblem = '', problem = '';
    try {
      key = await activityKeyFor(saved.phrase, saved.id);
      balancesKey = await balancesKeyFor(saved.phrase, saved.id);
      historyKey = await historyKeyFor(saved.phrase, saved.id);
      addressBookKey = await addressBookKeyFor(saved.phrase, saved.id);
      // A saved address book that does not authenticate or check out is not
      // shown; the next saved address replaces it (said in the panel).
      try { keptBook = await parseAddressBook(localStorage.getItem(ADDRESS_BOOK_KEY), saved.id, addressBookKey, ADDRESS_CHECKS); }
      catch { keptBook = []; bookProblem = 'The address book saved on this device could not be read. Saving an address replaces it.'; }
      // Saved history that does not authenticate is simply not shown.
      try { keptHistory = await parseHistory(localStorage.getItem(HISTORY_KEY), saved.id, historyKey); }
      catch { keptHistory = {}; }
      try { rows = await parseActivity(localStorage.getItem(ACTIVITY_KEY), saved.id, restored.addresses, key); }
      catch (error) { problem = error.message; }
      // Saved balances that do not authenticate are simply not shown.
      try { kept = await parseBalances(localStorage.getItem(BALANCES_KEY), saved.id, balancesKey); }
      catch { kept = {}; }
      if (operation !== vaultOperation || session !== sessionRelease || text !== localStorage.getItem(VAULT_KEY)) { disposeWallet(restored); return; }
    } catch (error) { disposeWallet(restored); throw error; }
    disposeWallet(wallet); wallet = restored; activitySession = { id: saved.id, key, balancesKey, historyKey, addressBookKey, vault: text }; activityBlocked = !!problem;
    historyByChain = keptHistory;
    addressBook = keptBook; addressBookNote = bookProblem; addressBookUnreadable = !!bookProblem;
    walletFresh = false; siteLock.start();
    history.length = 0; history.push(...rows);
    $('discard-activity').hidden = !problem; $('vault-status').textContent = problem || 'Saved activity authenticated.';
    $('welcome').hidden = true; $('phrase-form').hidden = true; $('wallet-open').hidden = false; updateVaultUI(); selectChain(); activity(); void showNodusAddress(); void showCellframeAddress(); showIxiosAddress(); message('Saved wallet unlocked locally.'); focusOpenWallet(kept);
  } catch (error) { if (operation === vaultOperation) $('vault-status').textContent = error.message; }
  finally { $('unlock-wallet').disabled = false; if (claimed) unclaimSession(); }
};
$('session-takeover').onclick = async () => {
  const operation = ++vaultOperation, flow = sessionConflictFlow;
  $('session-conflict').hidden = true;
  try {
    // The other site (src/site-lock.js) must not have a wallet open.
    const otherSite = siteLock.otherOpen();
    if (otherSite) throw new Error(otherSite);
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
  } catch (error) { if (operation === vaultOperation) message(error.message, { error: true }); }
};
// The outcome of saving (or of changing the password) is written in two
// places: #vault-status at the top of the wallet, and #vault-save-status
// right under the save buttons — where the person pressed (a tester saved
// and saw nothing: #vault-status is far above the button on the wallet
// page and, in Nodus Connect, sits on the start screen that is hidden
// while the wallet is open).
function saveResult(text, ok = false) {
  $('vault-status').textContent = text;
  $('vault-save-status').textContent = text;
  $('vault-save-status').classList.toggle('vault-save-ok', ok);
}
async function saveVault(change) {
  if (!wallet || wallet.locked) return;
  if (!$('vault-risk-confirm').checked) {
    saveResult('Not saved yet: before saving, read and accept the risks of storing an encrypted wallet on this device — tick the box just above the button, then press it again.');
    $('vault-risk-confirm').reportValidity();
    return;
  }
  if (!$('vault-confirm-password').value || $('vault-password').value !== $('vault-confirm-password').value) {
    saveResult('Not saved: the passwords do not match. Re-enter your chosen password in the confirmation field.');
    $('vault-confirm-password').focus();
    return;
  }
  const source = wallet, operation = ++vaultOperation;
  const password = $('vault-password').value, oldPassword = $('vault-old-password').value;
  $('vault-password').value = ''; $('vault-confirm-password').value = ''; $('vault-old-password').value = '';
  $('vault-save').disabled = true; $('vault-change').disabled = true;
  $('vault-save-status').textContent = '';
  const restore = showPreparing($(change ? 'vault-change' : 'vault-save'), { text: 'Saving…' });
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
    const balancesKey = await balancesKeyFor(source.recoveryPhrase, newId), historyKey = await historyKeyFor(source.recoveryPhrase, newId);
    const addressBookKey = await addressBookKeyFor(source.recoveryPhrase, newId);
    if (operation !== vaultOperation || wallet !== source || source.locked || localStorage.getItem(VAULT_KEY) !== previous) return;
    const stored = await withActivityLock(() => {
      if (operation !== vaultOperation || wallet !== source || source.locked || !$('vault-risk-confirm').checked || localStorage.getItem(VAULT_KEY) !== previous) return false;
      localStorage.setItem(VAULT_KEY, encrypted); activitySession = { id: newId, key, balancesKey, historyKey, addressBookKey, vault: encrypted }; return true;
    });
    if (!stored) {
      if (operation === vaultOperation && wallet === source && !source.locked && !$('vault-risk-confirm').checked) saveResult('Save canceled. The storage risks were not accepted; no new copy was saved.');
      return;
    }
    updateVaultUI();
    await persistActivity();
    // Balances read before the save are kept from now on as well.
    if (latestKept) persistBalances(latestKept);
    persistHistory();
    // The address book of this session (kept in memory until now) is saved
    // with the wallet from now on — unless the saved one could not be read
    // at unlock (a password change then leaves it as it is). An empty book
    // writes nothing here (each change is saved by commitAddressBook).
    if (!addressBookUnreadable && addressBook.length) {
      try { await persistAddressBook(); addressBookNote = ''; }
      catch { addressBookNote = 'The address book could not be saved on this device; it is kept until you lock.'; }
    }
    renderAddressBook();
    if (operation !== vaultOperation || wallet !== source || source.locked) return;
    $('vault-risk-confirm').checked = false;
    saveResult(change
      ? 'Local password changed. From now on, open this wallet with the new password.'
      : 'Encrypted wallet saved on this device. Next time, open this page in this browser and enter your password to unlock it. Keep your recovery words backed up as well.', true);
  } catch (error) { if (operation === vaultOperation) saveResult(`Not saved: ${error.message}`); }
  finally { restore(); $('vault-save').disabled = false; $('vault-change').disabled = false; }
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
    // The Messages history of this saved wallet (an IndexedDB database named
    // by the vault id, src/connect/store.js) goes in the same lock section.
    // The id is read from the saved text without the password; a damaged
    // text has no readable id, so its history cannot be found.
    let vaultId = null;
    try { vaultId = previous ? parseVault(previous).id : null; } catch { vaultId = null; }
    // An extension holding that history open in THIS tab (Messages on the
    // Nodus Connect page) closes it first, so the delete is not blocked.
    if (previous) raise('vaultDeleting');
    const messages = await withActivityLock(async () => {
      if (localStorage.getItem(VAULT_KEY) !== previous) throw new Error('Saved wallet changed before deletion.');
      localStorage.removeItem(VAULT_KEY); localStorage.removeItem(ACTIVITY_KEY); localStorage.removeItem(BALANCES_KEY); localStorage.removeItem(HISTORY_KEY); localStorage.removeItem(ADDRESS_BOOK_KEY);
      if (!previous) return 'none';
      if (!vaultId) return 'unknown';
      try { await deleteVaultHistory(vaultId, localStorage); return 'deleted'; }
      catch (error) { return error instanceof HistoryDeleteBlocked ? 'blocked' : 'failed'; }
    });
    $('vault-status').textContent = {
      none: 'Saved wallet and saved activity deleted from this device.',
      deleted: 'Saved wallet, saved activity and message history deleted from this device.',
      blocked: 'Saved wallet and saved activity deleted. Message history is still open in another tab; it is deleted when that tab is closed.',
      unknown: 'Saved wallet and saved activity deleted. The saved wallet was damaged, so its message history on this device could not be found and was not deleted.',
      failed: 'Saved wallet and saved activity deleted. Message history on this device could not be deleted.'
    }[messages];
    updateVaultUI(); renderAddressBook();
  }
  catch { $('vault-status').textContent = 'Device storage could not be deleted.'; }
  $('vault-delete-confirm').checked = false;
};

window.addEventListener('storage', event => { if (event.key === VAULT_KEY || event.key === null) { lock(); $('vault-status').textContent = 'Saved wallet changed in another tab. Unlock again to continue.'; } });
// Extensions get the wallet's one lock (src/wallet-extensions.js).
raise('attach', { lock: reason => { lock(); if (reason) message(reason); } });
// The session log: uncaught page errors (message only), and the Logs view
// in Device & settings (index.html, connect-site/index.html #session-logs).
// __APP_VERSION__: vite.config.js / vite.connect.config.js define.
logPageErrors(window);
mountSessionLogView({ panel: $('session-logs'), filter: $('session-log-filter'), output: $('session-log-text'), copy: $('session-log-copy'), download: $('session-log-download'), status: $('session-log-status') }, {
  version: typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : 'unknown', page: siteName() === 'connect' ? 'connect' : 'wallet'
});
