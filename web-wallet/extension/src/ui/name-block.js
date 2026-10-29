// src/app.js:1652-1738: the receive-panel chain name and registration action.
// All lookups and preparations use the background's single Nodus client.
export function mountNameBlock({ root, ui, selected, run, showReview }) {
  const $ = id => root.querySelector('#' + id);
  let generation = 0, quoteCheck = 0, quoted, identity, disposed = false;
  function clearQuote() { quoteCheck++; quoted = undefined; $('name-review').disabled = true; $('name-quote').textContent = ''; }
  function clearGreeting() { $('wallet-heading').hidden = true; $('wallet-title').textContent = ''; $('wallet-register-name').hidden = true; }
  async function refresh() {
    const check = ++generation; clearQuote(); clearGreeting();
    const current = () => !disposed && check === generation;
    $('own-name').textContent = 'Reading your chain name…'; $('name-fields').hidden = $('quick-name').hidden = true;
    try {
      const own = await ui.request('getOwnName'); if (!current()) return;
      if (own.found) {
        $('wallet-title').textContent = `Welcome back, ${own.name}`; $('wallet-heading').hidden = false;
        $('own-name').textContent = `Your chain name is "${own.name}". People can send NODUS to you by typing this name instead of your address.`; return;
      }
      if (!ui.state.nodus.registrable) { $('own-name').textContent = 'This wallet has no chain name. Registering one is not available in this version.'; return; }
      $('wallet-title').textContent = 'Welcome back'; $('wallet-heading').hidden = false; $('wallet-register-name').hidden = false;
      $('own-name').textContent = 'This wallet has no chain name yet. A chain name lets people send NODUS to you by typing a short name instead of your long address. First come, first served; one name per wallet; it does not expire.';
      $('name-fields').hidden = false; $('quick-name').hidden = selected() !== 'nodus'; $('name-prices').textContent = 'Reading name prices…';
      try { const prices = await ui.request('getNamePrices'); if (current()) $('name-prices').textContent = `Prices by name length — ${prices.text}. A network fee is added.`; }
      catch (error) { if (current()) $('name-prices').textContent = `Name prices could not be read: ${error.message}`; }
    } catch (error) { if (current()) $('own-name').textContent = `Could not read your chain name: ${error.message} Lock and reopen your wallet to retry.`; }
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
  $('quick-name').onclick = () => { $('name-title').focus({ preventScroll: true }); $('name-block').scrollIntoView({ block: 'start' }); $('name-input').focus({ preventScroll: true }); };
  return { refresh, update() {
    const state = ui.state, visible = selected() === 'nodus' && state.nodus?.nameable;
    $('name-block').hidden = !visible;
    const key = `${state.addresses.nodus}:${state.nodus?.connection}:${state.nodus?.state}:${state.nodus?.nameable}:${state.nodus?.registrable}`;
    if (key !== identity) { identity = key; generation++; clearQuote(); clearGreeting(); if (state.nodus?.nameable) void refresh(); else $('quick-name').hidden = true; }
    $('quick-name').hidden = !visible || $('name-fields').hidden;
  }, sent() { $('name-input').value = ''; clearQuote(); void refresh(); }, dispose() { disposed = true; generation++; clearQuote(); clearGreeting(); } };
}
