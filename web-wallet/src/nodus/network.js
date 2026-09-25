// Nodus as a wallet network, listed first in the network selector, the
// portfolio badges and filters, and the asset list, in the same shape as Ixios
// (src/ixios/network.js) and Cellframe (src/config.js CELLFRAME).
//
// Not part of CHAINS: src/wallet.js has no 'nodus' adapter, so nothing can be
// sent here. `receiveOnly` gives it the single Receive action and hides the
// send fields, exactly as for Cellframe and Ixios. The address is derived
// locally from the recovery phrase (src/nodus/derive.js, via app.js
// showNodusAddress()).
//
// No balance source exists yet: there is no `endpoint` and no `rpcOptions`, and
// `balanceUnavailable` keeps the portfolio from ever reading a balance for it —
// its row shows "Balance not shown yet", never an amount, a zero or a read error.
export const NODUS_NETWORK = {
  name: 'Nodus', symbol: 'NODUS', decimals: 8, icon: 'nodus.svg', tokens: [], receiveOnly: true, balanceUnavailable: true,
  // Shown under the hidden send fields when Nodus is the selected network.
  sendNote: 'Sending NODUS is not available in this release.',
};
// Unpriced like CPUNK_ASSET and IXIOS_ASSET: no priceId, so it never enters
// PRICE_URL and never counts toward the USD total or its completeness.
export const NODUS_ASSET = { chain: 'nodus', symbol: 'NODUS', decimals: 8, key: 'nodus:NODUS' };
