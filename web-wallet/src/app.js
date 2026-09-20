import { VAULT_KEY, ACTIVITY_KEY, parseVault, encryptVault, decryptVault, validateNewPassword } from './vault.js';
import { serializeActivity, parseActivity, activityKeyFor } from './activity-storage.js';
import { recordActivity, watchActivity } from './activity.js';
import { CHAINS } from './config.js';
import { deriveWallet, disposeWallet, newPhrase, normalizePhrase } from './keys.js';
import { adapters, prepareTransfer } from './wallet.js';
import { endpointUrl } from './core.js';
import { attachPhraseSuggestions } from './phrase-suggestions.js';
const $ = id => document.getElementById(id);
const clearPhraseSuggestions = attachPhraseSuggestions($('phrase'), $('phrase-suggestions'));
let wallet, pending, generatedPhrase, phraseStep, revision = 0, busy = false, lockTimer, idleDeadline = 0;
let cpunkRequest, nodusDerivation;
let activitySession = null, activityBlocked = false, historyWrites = Promise.resolve(), vaultOperation = 0;
const history = []; let stopTracking = () => {};
function visibleActivity() { return wallet ? history.filter(row => row.chain === $('chain').value && row.address === wallet.addresses[row.chain]) : []; }
function persistActivity({ required = false } = {}) {
  const session = activitySession, source = wallet;
  if (!session || !source) return Promise.resolve();
  const rows = history.filter(row => row.address === source.addresses[row.chain]).map(row => ({ ...row }));
  const current = () => session === activitySession && source === wallet && !source.locked && localStorage.getItem(VAULT_KEY) === session.vault;
  const changed = () => { if (required) throw new Error('Wallet storage changed before broadcast. Review the transfer again.'); };
  // Serialize writes; an older encryption must not overwrite a newer record.
  historyWrites = historyWrites.catch(() => {}).then(async () => {
    if (!current()) return changed();
    if (activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
    const encrypted = await serializeActivity(session.id, rows, session.key);
    if (!current()) return changed();
    localStorage.setItem(ACTIVITY_KEY, encrypted);
  });
  return historyWrites;
}
function renderActivity(save = true) {
  if (save) void persistActivity().catch(error => { $('vault-status').textContent = error.message; });
  $('activity').replaceChildren(...visibleActivity().map(row => {
    const div = document.createElement('div'), link = document.createElement('a');
    div.textContent = `${row.amount} ${row.symbol} → ${row.to} · ${row.status} · ${row.readError || row.note} `;
    link.href = CHAINS[row.chain].explorer + encodeURIComponent(row.hash); link.textContent = 'View transaction'; link.target = '_blank'; link.rel = 'noopener noreferrer'; div.append(link); return div;
  }));
}
function trackActivity() { stopTracking(); renderActivity(); if (wallet) stopTracking = watchActivity(visibleActivity, renderActivity); }
const endpoints = Object.fromEntries(Object.entries(CHAINS).map(([key, chain]) => [key, chain.endpoint]));
const message = text => { $('wallet-status').textContent = text; };
for (const [key, chain] of Object.entries(CHAINS)) $('chain').add(new Option(chain.name, key));
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
function closeReview() { pending?.cancel(); pending = undefined; $('review-dialog').close(); }
function lock() {
  clearPhraseSuggestions();
  nodusDerivation?.abort(); nodusDerivation = undefined;
  cpunkRequest?.abort(); cpunkRequest = undefined;
  if ($('cpunk-assets')) {
    $('cpunk-assets').open = false; $('cpunk-address').value = '';
    $('cpunk-result').textContent = 'No address selected.';
    $('cpunk-connection').textContent = 'Connection not checked.';
  }
  $('nodus-address').textContent = ''; $('nodus-status').textContent = ''; $('copy-nodus-address').disabled = true;
  revision++; vaultOperation++; activitySession = null; activityBlocked = false; idleDeadline = 0; stopTracking(); closeReview(); disposeWallet(wallet); wallet = undefined; generatedPhrase = undefined; $('phrase').value = '';
  $('discard-activity').hidden = true;
  $('phrase-form').hidden = true; $('wallet-open').hidden = true; $('welcome').hidden = false;
  $('activity').replaceChildren(); $('receive-address').textContent = ''; $('balances').replaceChildren(); $('recipient').value = ''; $('amount').value = '';
  for (const id of ['unlock-password', 'vault-password', 'vault-old-password']) $(id).value = '';
  updateVaultUI(); clearTimeout(lockTimer); message('Wallet locked. Restore your recovery phrase or unlock your saved wallet.');
}
window.addEventListener('pagehide', lock);
function phraseForm(create) {
  clearPhraseSuggestions();
  vaultOperation++; $('unlock-form').hidden = true;
  phraseStep = create ? 'backup' : 'restore';
  generatedPhrase = create ? newPhrase() : undefined;
  $('welcome').hidden = true; $('phrase-form').hidden = false; $('backup-confirm').checked = false;
  $('phrase').value = generatedPhrase || ''; $('phrase').readOnly = create;
  $('phrase-label').textContent = create ? 'Write down your 24-word recovery phrase privately' : 'Enter your 24-word Nodus recovery phrase';
  $('phrase-help').textContent = 'This phrase controls your funds. It stays local; an encrypted copy is stored only if you choose to save it. Keep an offline backup. This screen clears after 10 minutes of inactivity.';
  $('phrase-submit').textContent = create ? 'I saved it — verify backup' : 'Open wallet'; message(''); $('phrase').focus();
  activity();
}
$('create').onclick = () => phraseForm(true);
$('restore').onclick = () => phraseForm(false);
$('phrase-cancel').onclick = lock;
$('phrase-form').onsubmit = event => {
  event.preventDefault();
  if (phraseStep === 'backup') {
    clearPhraseSuggestions();
    phraseStep = 'verify'; $('phrase').value = ''; $('phrase').readOnly = false;
    $('phrase-label').textContent = 'Re-enter your saved recovery phrase'; $('phrase-submit').textContent = 'Open wallet'; $('phrase').focus(); return;
  }
  try {
    if (phraseStep === 'verify' && normalizePhrase($('phrase').value) !== generatedPhrase) throw new Error('The phrase does not match. Re-enter your saved backup.');
    wallet = deriveWallet($('phrase').value); generatedPhrase = undefined; $('phrase').value = ''; clearPhraseSuggestions();
    $('phrase-form').hidden = true; $('wallet-open').hidden = false; message('Wallet open. Balances are fetched only when you select Refresh.'); selectChain(); activity(); void showNodusAddress();
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
$('copy-nodus-address').onclick = async () => {
  const source = wallet;
  if (!source || source.locked || !source.nodusAddress) return;
  try { await navigator.clipboard.writeText(source.nodusAddress); if (source === wallet && !source.locked) $('nodus-status').textContent = 'Nodus address copied.'; }
  catch { if (source === wallet && !source.locked) $('nodus-status').textContent = 'Copy unavailable. Select and copy the address above.'; }
};
function selectChain() {
  revision++; closeReview(); const chain = $('chain').value; const c = CHAINS[chain];
  $('receive-address').textContent = wallet.addresses[chain]; $('rpc-endpoint').value = endpoints[chain];
  $('asset').replaceChildren(...[c.symbol, ...c.tokens.map(t => t.symbol)].map(s => new Option(s, s)));
  const explorers = { ethereum: 'https://etherscan.io/address/', bsc: 'https://bscscan.com/address/', solana: 'https://solscan.io/account/', tron: 'https://tronscan.org/#/address/' };
  $('account-explorer').href = explorers[chain] + encodeURIComponent(wallet.addresses[chain]); trackActivity();
  $('balances').textContent = 'Select Refresh to read balances.'; $('recipient').value = ''; $('amount').value = '';
}
$('chain').onchange = selectChain;
$('lock').onclick = lock;
$('copy-address').onclick = async () => { try { await navigator.clipboard.writeText(wallet.addresses[$('chain').value]); message('Address copied.'); } catch { message('Copy unavailable. Select and copy the address above.'); } };
$('save-rpc').onclick = () => { try { const chain = $('chain').value, endpoint = endpointUrl($('rpc-endpoint').value); if (chain === 'tron' && endpoint !== CHAINS.tron.endpoint) throw new Error('TRON requires the mainnet provider.'); endpoints[chain] = endpoint; revision++; closeReview(); stopTracking(); for (const row of visibleActivity()) row.endpoint = endpoints[$('chain').value]; trackActivity(); $('balances').textContent = 'Endpoint changed. Refresh to read balances.'; message('RPC updated for this tab.'); } catch (error) { message(error.message); } };
$('refresh').onclick = async () => {
  const current = ++revision, chain = $('chain').value, address = wallet.addresses[chain];
  $('balances').textContent = 'Reading balances…';
  try {
    const rows = await adapters[chain].balances(chain, address, endpoints[chain]);
    if (current !== revision || !wallet) return;
    $('balances').replaceChildren(...rows.map(row => { const line = document.createElement('div'); const name = document.createElement('span'); name.textContent = row.symbol; const amount = document.createElement('strong'); amount.textContent = row.error || row.balance; line.append(name, amount); return line; }));
    message(`Balances read at ${new Date().toLocaleTimeString()}.`);
  } catch (error) { if (current === revision) $('balances').textContent = error.message; }
};
$('send-form').onsubmit = async event => {
  event.preventDefault(); if (busy) return;
  busy = true; $('review-button').disabled = true; const current = revision;
  message('Preparing transfer and network fee…');
  try {
    const transfer = await prepareTransfer({ wallet, chain: $('chain').value, symbol: $('asset').value, to: $('recipient').value, amount: $('amount').value, endpoint: endpoints[$('chain').value] });
    if (current !== revision || !wallet) { transfer.cancel(); return; }
    pending = transfer; $('review-details').replaceChildren();
    for (const [key, value] of Object.entries({ Network: `${CHAINS[transfer.chain].name} mainnet`, From: transfer.from, To: transfer.to, Asset: transfer.symbol, Amount: transfer.amount, 'Network fee': transfer.fee, 'Review expires': new Date(transfer.expiresAt).toLocaleTimeString() })) {
      const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = key; dd.textContent = value; $('review-details').append(dt, dd);
    }
    $('confirm-send').disabled = false; $('review-error').textContent = ''; $('review-dialog').showModal(); message('Review every transfer detail before confirming.');
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
    $('review-dialog').close();
    if (current !== revision) return;
    message('Broadcast submitted; confirmation is pending. ');
    const link = document.createElement('a'); link.href = CHAINS[transfer.chain].explorer + encodeURIComponent(hash); link.textContent = `View transaction ${hash}`; link.target = '_blank'; link.rel = 'noopener noreferrer'; $('wallet-status').append(link);
  } catch (error) {
    if (record) { record.status = 'unknown'; record.note = 'Broadcast outcome uncertain. Tracking the signed transaction; do not resend automatically.'; if (current === revision) trackActivity(); }
    $('review-dialog').close();
    if (current === revision) message(`${error.message} A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.`);
  } finally { busy = false; $('cancel-send').disabled = false; }
};
if (import.meta.env.VITE_ENABLE_CPUNK !== 'false') {
import('./adapters/cpunk.js').then(({ readCpunk }) => {
$('cpunk-derive').onclick = async () => {
  if (!wallet || wallet.locked) { $('cpunk-result').textContent = 'Create or restore your wallet first.'; return; }
  const current = revision, source = wallet;
  $('cpunk-derive').disabled = true;
  try {
    const { deriveCpunkAddress } = await import('./cpunk/derive.js');
    if (current !== revision || source !== wallet || source.locked) return;
    const address = await deriveCpunkAddress(source.recoveryPhrase);
    if (current !== revision || source !== wallet || source.locked) return;
    $('cpunk-address').value = address; $('cpunk-address').dispatchEvent(new Event('input'));
    $('cpunk-result').textContent = 'Address derived locally. Select Refresh CPUNK balance to query it.';
  } catch (error) { if (current === revision) $('cpunk-result').textContent = error.message; }
  finally { $('cpunk-derive').disabled = false; }
};
$('cpunk-form').onsubmit = async event => {
  event.preventDefault(); cpunkRequest?.abort(); const controller = new AbortController(); cpunkRequest = controller;
  $('cpunk-connection').textContent = 'Connecting…'; $('cpunk-result').textContent = 'Reading CPUNK…';
  try {
    const result = await readCpunk({ address: $('cpunk-address').value.trim(), endpoint: $('cpunk-endpoint').value.trim(), signal: controller.signal });
    if (!controller.signal.aborted) { $('cpunk-connection').textContent = 'Connected · last read succeeded.'; $('cpunk-result').textContent = `${result.balance} CPUNK · Backbone · Read at ${new Date(result.observedAt).toLocaleTimeString()}`; }
  } catch (error) { if (!controller.signal.aborted) { $('cpunk-connection').textContent = 'Read failed · connection not verified.'; $('cpunk-result').textContent = error.message; } }
};
for (const id of ['cpunk-address', 'cpunk-endpoint']) $(id).addEventListener('input', () => { cpunkRequest?.abort(); $('cpunk-connection').textContent = 'Connection not checked for this input.'; $('cpunk-result').textContent = 'Input changed. Read the balance again.'; });

}).catch(() => { $('cpunk-result').textContent = 'CPUNK module could not load. Reload to retry.'; });
} else { document.querySelector('.cpunk').remove(); }

function updateVaultUI() {
  try { $('unlock-form').hidden = !!wallet || !localStorage.getItem(VAULT_KEY); }
  catch { $('vault-status').textContent = 'Device storage is unavailable. Use a temporary wallet in this tab.'; }
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
    $('welcome').hidden = true; $('phrase-form').hidden = true; $('wallet-open').hidden = false; updateVaultUI(); selectChain(); activity(); void showNodusAddress(); message('Saved wallet unlocked locally.');
  } catch (error) { if (operation === vaultOperation) $('vault-status').textContent = error.message; }
  finally { $('unlock-wallet').disabled = false; }
};
async function saveVault(change) {
  if (!wallet || wallet.locked) return;
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
      const saved = await decryptVault(previous, oldPassword);
      if (saved.phrase !== source.recoveryPhrase) throw new Error('Unlock the saved wallet before changing its password.');
      id = saved.id;
    }
    if (operation !== vaultOperation || wallet !== source || source.locked) return;
    const encrypted = await encryptVault(source.recoveryPhrase, password, id);
    const newId = parseVault(encrypted).id, key = await activityKeyFor(source.recoveryPhrase, newId);
    if (operation !== vaultOperation || wallet !== source || source.locked || localStorage.getItem(VAULT_KEY) !== previous) return;
    localStorage.setItem(VAULT_KEY, encrypted); activitySession = { id: newId, key, vault: encrypted }; updateVaultUI();
    await persistActivity();
    if (operation !== vaultOperation || wallet !== source || source.locked) return;
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
  try {
    localStorage.removeItem(ACTIVITY_KEY); activityBlocked = false; $('discard-activity').hidden = true;
    await persistActivity(); $('vault-status').textContent = 'Unreadable local history discarded. Check the account explorer before resending any previous payment.';
  } catch (error) { $('vault-status').textContent = error.message; }
};
$('vault-delete').onclick = () => {
  if (!$('vault-delete-confirm').checked) { $('vault-status').textContent = 'Confirm that you have your backup before deleting.'; return; }
  vaultOperation++; activitySession = null; activityBlocked = false; $('discard-activity').hidden = true;
  try { localStorage.removeItem(VAULT_KEY); localStorage.removeItem(ACTIVITY_KEY); $('vault-status').textContent = 'Saved wallet and saved activity deleted from this device.'; updateVaultUI(); }
  catch { $('vault-status').textContent = 'Device storage could not be deleted.'; }
  $('vault-delete-confirm').checked = false;
};

window.addEventListener('storage', event => { if (event.key === VAULT_KEY) { lock(); $('vault-status').textContent = 'Saved wallet changed in another tab. Unlock again to continue.'; } });
