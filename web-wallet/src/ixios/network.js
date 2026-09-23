// Ixios as a wallet network, alongside Cellframe (src/config.js CELLFRAME) and
// its unpriced asset (src/portfolio.js CPUNK_ASSET), but kept in this module:
// src/app.js references these only inside literal top-level
// `if (import.meta.env.VITE_ENABLE_IXIOS === 'true')` blocks, so a build with
// the flag off tree-shakes them away and carries no Ixios text in its JavaScript.
//
// Not part of CHAINS: src/wallet.js has no 'ixios' adapter, so nothing can be
// sent here. `receiveOnly` gives it the single Receive action and hides the send
// fields. `notActive` means its balance is never read: Ixios RPC v1.0.5 returns
// 0 for every 48-byte address, which would show a false "0 IXIOS" balance.
// `endpoint`/`rpcOptions` exist only for the shared network-settings UI; no
// request is made to them.
const IXIOS_RPC = 'https://ixios-rpc.innova.limited';
export const IXIOS_NETWORK = {
  name: 'Ixios', symbol: 'IXIOS', decimals: 18, icon: 'ixios.png', tokens: [], receiveOnly: true, notActive: true,
  endpoint: IXIOS_RPC, rpcOptions: [{ url: IXIOS_RPC, label: 'Ixios public RPC' }],
  // Shown under the hidden send fields when Ixios is the selected network
  // (Cellframe keeps index.html's default #send-disabled-note text).
  sendNote: 'Do not send IXIOS to this address yet. The Ixios network has not switched on quantum-safe addresses; funds sent here before it does may be lost. Sending and receiving will be enabled in a later release.',
};
// Unpriced like CPUNK_ASSET: no priceId, so it never enters PRICE_URL and never
// counts toward the USD total or its completeness.
export const IXIOS_ASSET = { chain: 'ixios', symbol: 'IXIOS', decimals: 18, key: 'ixios:IXIOS' };
