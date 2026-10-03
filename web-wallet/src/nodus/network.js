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
// No balance source exists yet (unless a send module is ready, below): there
// is no `endpoint` and no `rpcOptions`, and
// `balanceUnavailable` keeps the portfolio from ever reading a balance for it —
// its row shows "Balance not shown yet", never an amount, a zero or a read error.
// `stage`: the label shown next to the network name where the other networks
// show "Mainnet" (src/app.js selectChain) — the send module is pinned to the
// Nodus testnet (src/nodus/send-module.js NODUS_SEND_NETWORK).
export const NODUS_NETWORK = {
  name: 'Nodus', symbol: 'NODUS', decimals: 8, icon: 'nodus.svg', tokens: [], receiveOnly: true, balanceUnavailable: true, stage: 'Testnet',
  // Shown under the hidden send fields when Nodus is the selected network.
  sendNote: 'Sending NODUS is not available in this release.',
};
// The NODUS send skeleton (src/nodus/client.js, src/adapters/nodus.js) swaps in
// the sendable variant ONLY while a loaded send module reports 'ready' for the
// open wallet; any other state — above all "no module" (src/nodus/send-module.js
// holds null until package (c3) lands) — keeps NODUS_NETWORK above unchanged.
// Still no endpoint and no rpcOptions: the module reaches the chain itself.
const NODUS_SEND_NETWORK = { ...NODUS_NETWORK, receiveOnly: false, balanceUnavailable: false, sendNote: undefined };
// With a send module in the build (`module`), NODUS is receive-only only
// while the connection is being made or made again (src/app.js
// startNodusSend, RECONNECT), so its note says that instead of "not
// available in this release".
const NODUS_CONNECTING_NETWORK = { ...NODUS_NETWORK, sendNote: 'Connecting to the Nodus network… Sending NODUS becomes available as soon as the connection is ready.' };
export function nodusNetworkFor(ready, { module = false } = {}) {
  return ready === true ? NODUS_SEND_NETWORK : module === true ? NODUS_CONNECTING_NETWORK : NODUS_NETWORK;
}
// Unpriced like CPUNK_ASSET and IXIOS_ASSET: no priceId, so it never enters
// PRICE_URL and never counts toward the USD total or its completeness.
export const NODUS_ASSET = { chain: 'nodus', symbol: 'NODUS', decimals: 8, key: 'nodus:NODUS' };
