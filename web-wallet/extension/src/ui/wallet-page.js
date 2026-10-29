// src/app.js:609-620: public balance reads injected into createPortfolio.
// Nothing in this adapter holds a wallet, phrase, client or signing key.
export function portfolioReaders(ui) {
  return {
    async readBalances(chain) {
      const methods = { nodus: 'getNodusBalances', ethereum: 'getEvmBalances', bsc: 'getEvmBalances',
        solana: 'getSolanaBalances', tron: 'getTronBalances', cellframe: 'getCpunkBalance', ixios: 'getIxiosBalance' };
      if (!methods[chain]) throw new Error('Unsupported balance network.');
      const value = await ui.request(methods[chain], ['ethereum', 'bsc'].includes(chain) ? [chain] : []);
      return chain === 'cellframe' ? [{ symbol: 'CPUNK', balance: value.balance }] : value;
    },
    async readPrices() {
      const value = await ui.request('getPrices');
      return Object.fromEntries(Object.entries(value).map(([key, quote]) => [key, { units: BigInt(quote.units), observedAt: quote.observedAt }]));
    },
  };
}

// index.html:79 and src/app.js:2692-2725. The extension deletes through its
// one background lock, because it has no temporary unsaved session.
export function mountDeleteWallet({ document, root, status, ui, run }) {
  const template = document.createElement('template');
  template.innerHTML = '<details class="danger-zone"><summary>Delete saved wallet from this device</summary><p class="hint">Deleting removes the encrypted wallet and saved activity here. It does not move funds. You need your recovery backup to restore.</p><label class="check"><input id="vault-delete-confirm" type="checkbox"> I have my recovery backup and want to delete this device’s saved wallet.</label><button id="vault-delete" class="secondary" type="button">Delete saved wallet</button></details>';
  root.append(template.content.cloneNode(true));
  const $ = id => root.querySelector('#' + id);
  $('vault-delete').onclick = () => {
    if (!$('vault-delete-confirm').checked) { status.textContent = 'Confirm that you have your backup before deleting.'; return; }
    return run(async () => { await ui.request('deleteVault'); await ui.refresh(); status.textContent = 'Saved wallet and saved activity deleted from this device.'; });
  };
}

// src/app.js:2598-2667 (change branch). The required consent and password
// checks stay in the page; authentication and re-encryption stay in BG.
export function mountSavedSettings({ root, ui, run }) {
  const $ = id => root.querySelector('#' + id);
  $('vault-change').onclick = () => {
    if (!$('vault-risk-confirm').checked) {
      $('vault-save-status').textContent = 'Not saved yet: before saving, read and accept the risks of storing an encrypted wallet on this device — tick the box just above the button, then press it again.';
      $('vault-risk-confirm').reportValidity(); return;
    }
    if (!$('vault-confirm-password').value || $('vault-password').value !== $('vault-confirm-password').value) {
      $('vault-save-status').textContent = 'Not saved: the passwords do not match. Re-enter your chosen password in the confirmation field.'; $('vault-confirm-password').focus(); return;
    }
    let previous = $('vault-old-password').value, password = $('vault-password').value;
    $('vault-old-password').value = $('vault-password').value = $('vault-confirm-password').value = '';
    return run(async () => {
      try {
        await ui.request('changePassword', [previous, password]);
        $('vault-risk-confirm').checked = false;
        $('vault-save-status').textContent = 'Local password changed. From now on, open this wallet with the new password.';
      } catch (error) { $('vault-save-status').textContent = `Not saved: ${error.message}`; }
      finally { previous = password = null; }
    });
  };
}
