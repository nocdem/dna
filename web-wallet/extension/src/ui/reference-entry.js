import { mountWalletPage } from './app.js';
import { mountReferenceWallet } from './wallet-screen.js';
import { WALLET_MARKUP } from './wallet-markup.js';
import { mountDeleteWallet } from './wallet-page.js';

function renderEntry({ document, root, status, state, create, restore, unlock, ui, run }) {
  const template = document.createElement('template'); template.innerHTML = WALLET_MARKUP;
  root.className = ''; root.replaceChildren(template.content.cloneNode(true));
  const $ = id => root.querySelector('#' + id);
  $('wallet-status').replaceWith(status);
  $('wallet-boot-status').hidden = true;
  $('welcome').hidden = state.isInitialized;
  $('unlock-form').hidden = !state.isInitialized;
  $('create').disabled = $('restore').disabled = $('unlock-wallet').disabled = false;
  $('create').onclick = create; $('restore').onclick = restore;
  $('unlock-form').onsubmit = event => {
    event.preventDefault(); const entered = $('unlock-password').value; $('unlock-password').value = ''; return unlock(entered);
  };
  if (state.isInitialized) mountDeleteWallet({ document, root, status, ui, run });
}

// The existing lifecycle owns onboarding, trusted approvals, secret clearing
// and lock. Every unlocked wallet page uses the web wallet's screen.
export const mountReferencePage = options => mountWalletPage({ ...options, renderOpenWallet: mountReferenceWallet, renderEntry });

if (globalThis.document && globalThis.chrome?.runtime) void mountReferencePage();
