// Ixios as a wallet network, alongside Cellframe (src/config.js CELLFRAME) and
// its unpriced asset (src/portfolio.js CPUNK_ASSET), but kept in this module:
// src/app.js references these only inside literal top-level
// `if (import.meta.env.VITE_ENABLE_IXIOS === 'true')` blocks, so a build with
// the flag off tree-shakes them away and carries no Ixios text in its JavaScript.
//
// Not part of CHAINS: src/wallet.js has no 'ixios' adapter, so nothing can be
// sent here. `receiveOnly` gives it the single Receive action and hides the send
// fields, exactly as for Cellframe. Its balance is read like Cellframe's, by
// src/ixios/balance.js against `endpoint` (or the RPC the user picks from
// `rpcOptions` or enters as a custom HTTPS endpoint).
const IXIOS_RPC = 'https://ixios-rpc.innova.limited';
export const IXIOS_NETWORK = {
  name: 'Ixios', symbol: 'IXIOS', decimals: 18, icon: 'ixios.png', tokens: [], receiveOnly: true,
  endpoint: IXIOS_RPC, rpcOptions: [{ url: IXIOS_RPC, label: 'Ixios public RPC' }],
  // Shown under the hidden send fields when Ixios is the selected network, in
  // the style of Cellframe's (index.html's default #send-disabled-note text).
  sendNote: 'Sending IXIOS is not available in this release. The Ixios network does not accept this address type yet.',
};
// Unpriced like CPUNK_ASSET: no priceId, so it never enters PRICE_URL and never
// counts toward the USD total or its completeness.
export const IXIOS_ASSET = { chain: 'ixios', symbol: 'IXIOS', decimals: 18, key: 'ixios:IXIOS' };
