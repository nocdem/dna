import { getAddress } from 'ethers';
import { VAULT_KEY, ACTIVITY_KEY, parseVault, encryptVault, decryptVault, validateNewPassword } from './vault.js';
import { serializeActivity, parseActivity, activityKeyFor } from './activity-storage.js';
import { recordActivity, watchActivity, terminal } from './activity.js';
import { CHAINS, CELLFRAME } from './config.js';
import { CPUNK_ASSET } from './portfolio.js';
import { deriveWallet, disposeWallet, newPhrase, normalizePhrase } from './keys.js';
import { adapters, prepareTransfer } from './wallet.js';
import { endpointUrl } from './core.js';
import { createPhraseFields } from './phrase-fields.js';
import { createPortfolio } from './portfolio-view.js';
const $ = id => document.getElementById(id);
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
let activitySession = null, activityBlocked = false, historyWrites = Promise.resolve(), vaultOperation = 0;
const history = []; let stopTracking = () => {};
function withActivityLock(write) {
  if (!navigator.locks) return Promise.reject(new Error('This browser cannot safely save wallet activity across tabs. Use a browser with Web Locks support.'));
  return navigator.locks.request('nodus.wallet.storage', write);
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
if (CPUNK_ENABLED) endpoints.cellframe = CELLFRAME.endpoint;
const portfolio = createPortfolio({
  // cellframeReader is set by showCellframeAddress() before it ever reports an
  // address to the portfolio, so it is always ready by the time this branch runs.
  readBalances: (chain, address, endpoint, options) => chain === 'cellframe'
    ? cellframeReader(address, endpoint, options)
    : adapters[chain].balances(chain, address, endpoint, options),
  selectAsset(chain, symbol, action) {
    if (!wallet) return;
    $('chain').value = chain; selectChain(); $('asset').value = symbol;
    $(action === 'send' ? 'quick-send' : 'quick-receive').click();
  },
  cellframe: CPUNK_ENABLED ? { network: CELLFRAME, asset: CPUNK_ASSET } : undefined
});
const message = text => { $('wallet-status').textContent = text; };
for (const [key, chain] of Object.entries(CHAINS)) $('chain').add(new Option(chain.name, key));
if (CPUNK_ENABLED) {
  $('chain').add(new Option(CELLFRAME.name, 'cellframe'));
  // The default HTML text (kept for a disabled build, where it stays true
  // unedited) says CPUNK is "not included"; with the module enabled its
  // balance IS shown here, just never priced into the total.
  $('portfolio-scope').textContent = 'Supported assets on Ethereum, BNB Smart Chain, Solana, TRON and Cellframe. NODUS and CPUNK balances are shown, but only Ethereum, BNB Smart Chain, Solana and TRON count toward the estimated total.';
}
function expireIdle() {
  if (idleDeadline && Date.now() >= idleDeadline) { lock(); return true; }
  return false;
}
function activity() {
  if (expireIdle()) return;
  clearTimeout(lockTimer);
  const sensitive = wallet || !$('phrase-form').hidden || $('unlock-wallet').disabled || $('vault-save').disabled || ['unlock-password', 'vault-password', 'vault-old-password'].some(id => $(id).value);
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
  cellframeDerivation?.abort(); cellframeDerivation = undefined;
  $('cellframe-address-status').textContent = '';
  $('nodus-address').textContent = ''; $('nodus-status').textContent = ''; $('copy-nodus-address').disabled = true;
  revision++; vaultOperation++; activitySession = null; activityBlocked = false; idleDeadline = 0; stopTracking(); closeReview(); disposeWallet(wallet); wallet = undefined; generatedPhrase = undefined;
  $('discard-activity').hidden = true;
  $('phrase-form').hidden = true; $('wallet-open').hidden = true; $('welcome').hidden = false;
  history.length = 0; $('account-explorer').removeAttribute('href');
  $('activity').replaceChildren(); $('receive-address').textContent = ''; $('balances').replaceChildren(); $('recipient').value = ''; $('amount').value = '';
  for (const id of ['unlock-password', 'vault-password', 'vault-old-password']) $(id).value = '';
  $('vault-risk-confirm').checked = false;
  updateVaultUI(); clearTimeout(lockTimer); message('Wallet locked. Restore your recovery phrase or unlock your saved wallet.');
}
window.addEventListener('pagehide', lock);
function phraseForm(create) {
  phraseFields.clear();
  vaultOperation++; $('unlock-password').value = ''; $('unlock-form').hidden = true;
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
$('phrase-form').onsubmit = event => {
  event.preventDefault();
  if (phraseStep === 'backup') {
    phraseStep = 'verify'; phraseFields.set(undefined, false, { allowPaste: false });
    $('phrase-label').textContent = 'Re-enter your saved recovery phrase'; $('phrase-submit').textContent = 'Open wallet';
    $('phrase-entry-help').textContent = 'Type each word from your written backup; pasting is disabled here.';
    phraseFields.focus(); return;
  }
  try {
    const phrase = phraseFields.read();
    if (phraseStep === 'verify' && normalizePhrase(phrase) !== generatedPhrase) throw new Error('The phrase does not match. Re-enter your saved backup.');
    wallet = deriveWallet(phrase); generatedPhrase = undefined; phraseFields.clear();
    $('phrase-form').hidden = true; $('wallet-open').hidden = false; message('Wallet open. Portfolio balances load automatically.'); selectChain(); activity(); void showNodusAddress(); void showCellframeAddress(); focusOpenWallet();
  } catch (error) { message(error.message); }
};
async function showNodusAddress() {
  nodusDerivation?.abort();
  const operation = new AbortController(), source = wallet;
  nodusDerivation = operation;
  $('nodus-address').textContent = ''; $('copy-nodus-address').disabled = true;
  $('nodus-status').textContent = 'Calculating your Nodus address locally…';
  const current = () => nodusDerivation === operation && source === wallet && !source.locked && !operation.signal.aborted;
  try {
    const { deriveNodusAddress } = await import('./nodus/derive.js');
    if (!current()) return;
    const address = await deriveNodusAddress(source.recoveryPhrase, { signal: operation.signal });
    if (!current()) return;
    source.nodusAddress = address;
    $('nodus-address').textContent = address; $('copy-nodus-address').disabled = false;
    $('nodus-status').textContent = 'Derived locally from this wallet’s recovery phrase.';
  } catch {
    if (current()) $('nodus-status').textContent = 'Nodus address unavailable. Lock and reopen your wallet to retry.';
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
        if ($('chain').value === 'cellframe') $('receive-address').textContent = address;
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
$('copy-nodus-address').onclick = async () => {
  const source = wallet;
  if (!source || source.locked || !source.nodusAddress) return;
  try { await navigator.clipboard.writeText(source.nodusAddress); if (source === wallet && !source.locked) $('nodus-status').textContent = 'Nodus address copied.'; }
  catch { if (source === wallet && !source.locked) $('nodus-status').textContent = 'Copy unavailable. Select and copy the address above.'; }
};
function selectChain() {
  revision++; closeReview(); const chain = $('chain').value; const c = CHAINS[chain] || CELLFRAME;
  for (const label of document.querySelectorAll('.selected-network-name')) label.textContent = c.name;
  const address = wallet.addresses[chain];
  $('receive-address').textContent = address || ''; $('rpc-endpoint').value = endpoints[chain];
  $('asset').replaceChildren(...[c.symbol, ...c.tokens.map(t => t.symbol)].map(s => new Option(s, s)));
  $('solana-send-hint').hidden = chain !== 'solana';
  const explorers = { ethereum: 'https://etherscan.io/address/', bsc: 'https://bscscan.com/address/', solana: 'https://solscan.io/account/', tron: 'https://tronscan.org/#/address/' };
  if (explorers[chain]) { $('account-explorer').href = explorers[chain] + encodeURIComponent(address); $('account-explorer').hidden = false; }
  else { $('account-explorer').removeAttribute('href'); $('account-explorer').hidden = true; }
  trackActivity();
  $('recipient').value = ''; $('amount').value = '';
  $('send-fields').hidden = !!c.receiveOnly; $('send-disabled-note').hidden = !c.receiveOnly;
  $('cellframe-address-status').hidden = chain !== 'cellframe';
}
$('chain').onchange = selectChain;
$('quick-send').onclick = () => {
  $('send-title').focus({ preventScroll: true });
  $('send-form').scrollIntoView({ block: 'start' });
};
$('quick-receive').onclick = () => {
  $('receive-title').focus({ preventScroll: true });
  $('receive-panel').scrollIntoView({ block: 'start' });
};
$('lock').onclick = lock;
$('copy-address').onclick = async () => {
  const address = wallet.addresses[$('chain').value];
  if (!address) { message('Address not available yet.'); return; }
  try { await navigator.clipboard.writeText(address); message('Address copied.'); }
  catch { message('Copy unavailable. Select and copy the address above.'); }
};
$('save-rpc').onclick = () => { try { const chain = $('chain').value, endpoint = endpointUrl($('rpc-endpoint').value); if (chain === 'tron' && endpoint !== endpointUrl(CHAINS.tron.endpoint)) throw new Error('TRON requires the mainnet provider.'); endpoints[chain] = endpoint; revision++; closeReview(); stopTracking(); for (const row of visibleActivity()) row.endpoint = endpoints[$('chain').value]; trackActivity(); portfolio.changeEndpoint(chain, endpoint); message('RPC updated for this tab.'); } catch (error) { message(error.message); } };
$('send-form').onsubmit = async event => {
  event.preventDefault(); if (busy) return;
  // Belt-and-suspenders: the send fields are hidden/disabled for a receive-only
  // network already, and prepareTransfer() has no 'cellframe' adapter to route
  // to either (src/wallet.js is unchanged), so this can only be reached by a
  // script bypassing the UI, not a real user.
  if ($('chain').value === 'cellframe') { message('Sending CPUNK is not available in this release. You can receive to the address above.'); return; }
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
  event.preventDefault(); const operation = ++vaultOperation;
  const password = $('unlock-password').value; $('unlock-password').value = ''; $('unlock-wallet').disabled = true;
  try {
    const text = localStorage.getItem(VAULT_KEY); if (!text) throw new Error('No saved wallet on this device.');
    const saved = await decryptVault(text, password);
    if (operation !== vaultOperation || text !== localStorage.getItem(VAULT_KEY)) return;
    const restored = deriveWallet(saved.phrase); let key, rows = [], problem = '';
    try {
      key = await activityKeyFor(saved.phrase, saved.id);
      try { rows = await parseActivity(localStorage.getItem(ACTIVITY_KEY), saved.id, restored.addresses, key); }
      catch (error) { problem = error.message; }
      if (operation !== vaultOperation || text !== localStorage.getItem(VAULT_KEY)) { disposeWallet(restored); return; }
    } catch (error) { disposeWallet(restored); throw error; }
    disposeWallet(wallet); wallet = restored; activitySession = { id: saved.id, key, vault: text }; activityBlocked = !!problem;
    history.length = 0; history.push(...rows);
    $('discard-activity').hidden = !problem; $('vault-status').textContent = problem || 'Saved activity authenticated.';
    $('welcome').hidden = true; $('phrase-form').hidden = true; $('wallet-open').hidden = false; updateVaultUI(); selectChain(); activity(); void showNodusAddress(); void showCellframeAddress(); message('Saved wallet unlocked locally.'); focusOpenWallet();
  } catch (error) { if (operation === vaultOperation) $('vault-status').textContent = error.message; }
  finally { $('unlock-wallet').disabled = false; }
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
