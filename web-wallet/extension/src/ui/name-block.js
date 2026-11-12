// src/app.js:1652-1738: the receive-panel chain name and registration action.
// All lookups and preparations use the background's single Nodus client.
import { debugLog } from '../../../src/debug-log.js';
export function mountNameBlock({ root, ui, selected, run, showReview }) {
  const $ = id => root.querySelector('#' + id);
  let generation = 0, quoteCheck = 0, quoted, identity, disposed = false;
  function clearQuote() { quoteCheck++; quoted = undefined; $('name-review').disabled = true; $('name-quote').textContent = ''; }
  function resetGreeting() { $('wallet-heading').hidden = false; $('wallet-title').textContent = 'Welcome back'; $('wallet-register-name').hidden = true; }
  // The name kept from the last use (the background's public state; unconfirmed) on the greeting and the name line, with
  // no lookup: shown at once after unlock, also while the Nodus connection is opening or unavailable.
  function showKept(kept) {
    $('name-fields').hidden = true;
    $('wallet-title').textContent = `Welcome back, ${kept}`;
    $('own-name').textContent = `Your chain name is "${kept}" (last known; confirming…). People can send NODUS to you by typing this name instead of your address.`;
    debugLog('identity', 'kept-name-shown');
  }
  async function refresh() {
    const check = ++generation; clearQuote(); resetGreeting();
    const current = () => !disposed && check === generation;
    // The name kept from the last use (the background's public state; unconfirmed) is shown at once; the lookup below
    // confirms or replaces it.
    const kept = ui.state.nodus?.keptOwnName;
    if (kept) showKept(kept);
    else $('own-name').textContent = 'Reading your chain name…';
    $('name-fields').hidden = true;
    try {
      const own = await ui.request('getOwnName'); if (!current()) return;
      if (kept) debugLog('identity', own.found ? (own.name === kept ? 'kept-name-confirmed' : 'kept-name-replaced') : 'kept-name-removed');
      if (own.found) {
        $('wallet-title').textContent = `Welcome back, ${own.name}`;
        $('own-name').textContent = `Your chain name is "${own.name}". People can send NODUS to you by typing this name instead of your address.`; return;
      }
      $('wallet-title').textContent = 'Welcome back';
      if (!ui.state.nodus.registrable) { $('own-name').textContent = 'This wallet has no chain name. Registering one is not available in this version.'; return; }
      $('wallet-register-name').hidden = false;
      $('own-name').textContent = 'This wallet has no chain name yet. A chain name lets people send NODUS to you by typing a short name instead of your long address. First come, first served; one name per wallet; it does not expire.';
      $('name-fields').hidden = false; $('name-prices').textContent = 'Reading name prices…';
      try { const prices = await ui.request('getNamePrices'); if (current()) $('name-prices').textContent = `Prices by name length — ${prices.text}. A network fee is added.`; }
      catch (error) { if (current()) $('name-prices').textContent = `Name prices could not be read: ${error.message}`; }
    } catch (error) {
      if (!current()) return;
      $('own-name').textContent = kept ? `Your chain name is "${kept}" (last known; it could not be confirmed now: ${error.message}) Lock and reopen your wallet to retry.`
        : `Could not read your chain name: ${error.message} Lock and reopen your wallet to retry.`;
    }
  }
  async function checkName() {
    clearQuote(); const check = quoteCheck, typed = $('name-input').value;
    $('name-quote').textContent = 'Checking the name…';
    try {
      const quote = await ui.request('quoteName', [typed]); if (disposed || check !== quoteCheck) return;
      if (quote.status === 'has-name') { $('name-quote').textContent = `This wallet already has the chain name "${quote.ownName}".`; void refresh(); return; }
      if (quote.status === 'taken') { $('name-quote').textContent = `"${quote.name}" is already registered by someone else. Try another name.`; return; }
      quoted = quote.name;
      const lowered = quote.name !== typed.trim() ? ` Names are lower-case, so it is registered as "${quote.name}".` : '';
      $('name-quote').textContent = `"${quote.name}" is available. Price: ${quote.priceText}. The network fee is shown on the review before you confirm.${lowered}`;
      $('name-review').disabled = false;
    } catch (error) { if (!disposed && check === quoteCheck) $('name-quote').textContent = error.message || 'The name could not be checked.'; }
  }
  $('name-input').addEventListener('input', clearQuote);
  $('name-input').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); void run(checkName); } });
  $('name-check').onclick = () => run(checkName);
  $('name-review').onclick = () => run(async () => {
    if (!quoted) return; const check = quoteCheck, review = await ui.request('prepareName', [quoted]);
    if (disposed || check !== quoteCheck) { await ui.cancelNodusSend(review.id); return; }
    showReview(review, { chain: 'nodus', title: 'Review name registration' });
  });
  $('wallet-register-name').onclick = () => { $('name-title').focus({ preventScroll: true }); $('name-block').scrollIntoView({ block: 'start' }); $('name-input').focus({ preventScroll: true }); };
  return { refresh, update() {
    // Shown once the client can read names; before that only while a kept (unconfirmed) name is there to show.
    const state = ui.state, visible = selected() === 'nodus' && (state.nodus?.nameable || Boolean(state.nodus?.keptOwnName));
    $('name-block').hidden = !visible;
    const key = `${state.addresses.nodus}:${state.nodus?.connection}:${state.nodus?.state}:${state.nodus?.nameable}:${state.nodus?.registrable}`;
    if (key !== identity) { identity = key; generation++; clearQuote(); resetGreeting(); if (state.nodus?.nameable) void refresh(); else if (state.nodus?.keptOwnName) showKept(state.nodus.keptOwnName); }
  }, sent() { $('name-input').value = ''; clearQuote(); void refresh(); }, dispose() { disposed = true; generation++; clearQuote(); resetGreeting(); } };
}
