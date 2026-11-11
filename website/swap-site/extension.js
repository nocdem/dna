// The Nodus Connect extension's EXISTING site methods only (nothing new: the new methods are in adapter.js).
// Discovery follows the extension's own site connector, web-wallet/extension/site-sdk/index.mjs:20-37:
// EIP-6963, rdns io.nodusnetwork.wallet, name "Nodus Wallet". The site SDK itself is not imported: it loads a
// verify-only wasm module this site never uses (the site does not check the bot, givens items 65, 69).
// Methods used: nodus_requestAccounts, eth_requestAccounts, nodus_signMessage (permissions.js:20-35).

import { hexOfText } from './swap-logic.js';

const RDNS = 'io.nodusnetwork.wallet';
const NAME = 'Nodus Wallet';

export function createExtension({ window = globalThis.window, waitMs = 800 } = {}) {
  let found = null;
  function listen() {
    window.addEventListener('eip6963:announceProvider', event => {
      const d = event.detail;
      if (d?.info?.rdns === RDNS && d.info.name === NAME && typeof d.provider?.request === 'function') found = d.provider;
    });
    window.dispatchEvent(new window.Event('eip6963:requestProvider'));
  }
  listen();
  async function provider() {
    if (found) return found;
    window.dispatchEvent(new window.Event('eip6963:requestProvider'));
    await new Promise(resolve => setTimeout(resolve, waitMs));
    return found;
  }
  return {
    provider,
    // -> { nodus: { address (128 hex), publicKey ("0x" + 5184 hex) }, ethereum: "0x.." } or throws; the provider's
    // own error (code 4001 rejected, 4100 data notice not accepted) is passed on unchanged.
    async connect() {
      const p = await provider();
      if (!p) { const e = new Error('The Nodus Connect extension was not found.'); e.code = 'no_extension'; throw e; }
      const nodus = await p.request({ method: 'nodus_requestAccounts' });
      const eth = await p.request({ method: 'eth_requestAccounts' });
      const n = Array.isArray(nodus) ? nodus[0] : null, e = Array.isArray(eth) ? eth[0] : null;
      if (!n?.address || !n?.publicKey || typeof e !== 'string') throw new Error('The extension returned no account.');
      return { nodus: { address: n.address, publicKey: n.publicKey }, ethereum: e.toLowerCase() };
    },
    // nodus_signMessage as the site SDK sends it (index.mjs:43-51): params [0x + hex of the text bytes, the
    // account's address]; the answer is "0x" + 9254 hex (nodus.js:509-510).
    async signNodusText(text, address) {
      const p = await provider();
      if (!p) { const e = new Error('The Nodus Connect extension was not found.'); e.code = 'no_extension'; throw e; }
      return p.request({ method: 'nodus_signMessage', params: [`0x${hexOfText(text)}`, address] });
    },
  };
}
