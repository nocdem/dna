import { CHAINS } from './config.js';
import { deriveWallet, disposeWallet, newPhrase, normalizePhrase } from './keys.js';
import { adapters, prepareTransfer } from './wallet.js';
import { endpointUrl } from './core.js';
const $ = id => document.getElementById(id);
let wallet, pending, generatedPhrase, phraseStep, revision = 0, busy = false, lockTimer;
let cpunkRequest;
const endpoints = Object.fromEntries(Object.entries(CHAINS).map(([key, chain]) => [key, chain.endpoint]));
const message = text => { $('wallet-status').textContent = text; };
for (const [key, chain] of Object.entries(CHAINS)) $('chain').add(new Option(chain.name, key));
function activity() { clearTimeout(lockTimer); if (wallet) lockTimer = setTimeout(lock, 10 * 60 * 1000); }
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, activity);
function closeReview() { pending?.cancel(); pending = undefined; $('review-dialog').close(); }
function lock() {
  revision++; closeReview(); disposeWallet(wallet); wallet = undefined; generatedPhrase = undefined; $('phrase').value = '';
  $('phrase-form').hidden = true; $('wallet-open').hidden = true; $('welcome').hidden = false;
  $('receive-address').textContent = ''; $('balances').replaceChildren(); $('recipient').value = ''; $('amount').value = '';
  clearTimeout(lockTimer); message('Wallet locked. Restore with your recovery phrase to reopen.');
}
window.addEventListener('pagehide', lock);
function phraseForm(create) {
  phraseStep = create ? 'backup' : 'restore';
  generatedPhrase = create ? newPhrase() : undefined;
  $('welcome').hidden = true; $('phrase-form').hidden = false; $('backup-confirm').checked = false;
  $('phrase').value = generatedPhrase || ''; $('phrase').readOnly = create;
  $('phrase-label').textContent = create ? 'Write down your recovery phrase privately' : 'Enter your recovery phrase';
  $('phrase-help').textContent = 'This phrase controls your funds. It is never sent to an RPC or stored by this app. Keep an offline backup; we cannot recover it.';
  $('phrase-submit').textContent = create ? 'I saved it — verify backup' : 'Open wallet'; message(''); $('phrase').focus();
}
$('create').onclick = () => phraseForm(true);
$('restore').onclick = () => phraseForm(false);
$('phrase-cancel').onclick = lock;
$('phrase-form').onsubmit = event => {
  event.preventDefault();
  if (phraseStep === 'backup') {
    phraseStep = 'verify'; $('phrase').value = ''; $('phrase').readOnly = false;
    $('phrase-label').textContent = 'Re-enter your saved recovery phrase'; $('phrase-submit').textContent = 'Open wallet'; $('phrase').focus(); return;
  }
  try {
    if (phraseStep === 'verify' && normalizePhrase($('phrase').value) !== generatedPhrase) throw new Error('The phrase does not match. Re-enter your saved backup.');
    wallet = deriveWallet($('phrase').value); generatedPhrase = undefined; $('phrase').value = '';
    $('phrase-form').hidden = true; $('wallet-open').hidden = false; message('Wallet open. Balances are fetched only when you select Refresh.'); selectChain(); activity();
  } catch (error) { message(error.message); }
};
function selectChain() {
  revision++; closeReview(); const chain = $('chain').value; const c = CHAINS[chain];
  $('receive-address').textContent = wallet.addresses[chain]; $('rpc-endpoint').value = endpoints[chain];
  $('asset').replaceChildren(...[c.symbol, ...c.tokens.map(t => t.symbol)].map(s => new Option(s, s)));
  $('balances').textContent = 'Select Refresh to read balances.'; $('recipient').value = ''; $('amount').value = '';
}
$('chain').onchange = selectChain;
$('lock').onclick = lock;
$('copy-address').onclick = async () => { try { await navigator.clipboard.writeText(wallet.addresses[$('chain').value]); message('Address copied.'); } catch { message('Copy unavailable. Select and copy the address above.'); } };
$('save-rpc').onclick = () => { try { endpoints[$('chain').value] = endpointUrl($('rpc-endpoint').value); revision++; closeReview(); $('balances').textContent = 'Endpoint changed. Refresh to read balances.'; message('RPC updated for this tab.'); } catch (error) { message(error.message); } };
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
  busy = true; const transfer = pending, current = revision; pending = undefined;
  $('confirm-send').disabled = true; $('cancel-send').disabled = true; $('review-error').textContent = 'Signing locally and broadcasting…';
  try {
    const hash = await transfer.confirm();
    $('review-dialog').close();
    if (current !== revision) return;
    message('Broadcast submitted; confirmation is pending. ');
    const link = document.createElement('a'); link.href = CHAINS[transfer.chain].explorer + encodeURIComponent(hash); link.textContent = `View transaction ${hash}`; link.target = '_blank'; link.rel = 'noopener noreferrer'; $('wallet-status').append(link);
  } catch (error) {
    $('review-dialog').close();
    if (current === revision) message(`${error.message} A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.`);
  } finally { busy = false; $('cancel-send').disabled = false; }
};
if (import.meta.env.VITE_ENABLE_CPUNK !== 'false') {
import('./adapters/cpunk.js').then(({ readCpunk }) => {
$('cpunk-form').onsubmit = async event => {
  event.preventDefault(); cpunkRequest?.abort(); const controller = new AbortController(); cpunkRequest = controller;
  $('cpunk-connection').textContent = 'Connecting…'; $('cpunk-result').textContent = 'Reading CPUNK…';
  try {
    const result = await readCpunk({ address: $('cpunk-address').value.trim(), endpoint: $('cpunk-endpoint').value.trim() || import.meta.env.VITE_CPUNK_ENDPOINT || '', signal: controller.signal });
    if (!controller.signal.aborted) { $('cpunk-connection').textContent = 'Connected · last read succeeded.'; $('cpunk-result').textContent = `${result.balance} CPUNK · Backbone · Read at ${new Date(result.observedAt).toLocaleTimeString()}`; }
  } catch (error) { if (!controller.signal.aborted) { $('cpunk-connection').textContent = 'Read failed · connection not verified.'; $('cpunk-result').textContent = error.message; } }
};
for (const id of ['cpunk-address', 'cpunk-endpoint']) $(id).addEventListener('input', () => { cpunkRequest?.abort(); $('cpunk-connection').textContent = 'Connection not checked for this input.'; $('cpunk-result').textContent = 'Input changed. Read the balance again.'; });

}).catch(() => { $('cpunk-result').textContent = 'CPUNK module could not load. Reload to retry.'; });
} else { document.querySelector('.cpunk').remove(); document.querySelector('.layout').classList.add('single'); }
