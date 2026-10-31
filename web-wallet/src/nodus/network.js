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
  networkGroup: 'pq',
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
// `tokens`: the pinned tokens the send module reports while ready
// (client.tokenPins(): [{ tokenId, name, symbol, decimals, available }],
// src/app.js setNodusReady) — the ONE source, the module's pin table
// (design docs/plans/2026-10-22-connect-native-tokens-design.md §6 item 2);
// network.js carries no token of its own. Each is listed on the NODUS network
// with the same fields; `available: false` = the node's metadata for it did
// not equal the pin in this session ("unavailable right now", operator
// "tUSDT'yi kapat"): shown, never sendable. Anything not shaped like a pin is
// dropped here (a malformed module answer shows no token).
const HEX128 = /^[0-9a-f]{128}$/;
export function nodusTokens(pins) {
  if (!Array.isArray(pins)) return [];
  const seen = new Set(), out = [];
  for (const p of pins) {
    // A pin is listed once, and only if the WHOLE entry is well-formed (an
    // entry refused for its symbol never shadows a later valid one).
    if (!p || typeof p.tokenId !== 'string' || !HEX128.test(p.tokenId) || p.tokenId === NODUS_TOKEN_ID || seen.has(p.tokenId)) continue;
    if (typeof p.symbol !== 'string' || !/^[A-Za-z0-9]{1,12}$/.test(p.symbol) || p.symbol === 'NODUS' || typeof p.name !== 'string' || p.name === '') continue;
    if (!Number.isInteger(p.decimals) || p.decimals < 0 || p.decimals > 18) continue;
    seen.add(p.tokenId);
    out.push(Object.freeze({ tokenId: p.tokenId, name: p.name, symbol: p.symbol, decimals: p.decimals, available: p.available === true }));
  }
  return Object.freeze(out);
}
export function nodusNetworkFor(ready, { module = false, tokens = [] } = {}) {
  if (ready !== true) return module === true ? NODUS_CONNECTING_NETWORK : NODUS_NETWORK;
  const listed = nodusTokens(tokens);
  return listed.length ? { ...NODUS_SEND_NETWORK, tokens: listed } : NODUS_SEND_NETWORK;
}
// The token id of NODUS itself in a send's asset identity: 128 zeros, the
// all-zero token id of the chain (a coin of token id 0 is native).
export const NODUS_TOKEN_ID = '0'.repeat(128);
// Unpriced like CPUNK_ASSET and IXIOS_ASSET: no priceId, so it never enters
// PRICE_URL and never counts toward the USD total or its completeness.
export const NODUS_ASSET = { chain: 'nodus', symbol: 'NODUS', decimals: 8, key: 'nodus:NODUS', tokenId: NODUS_TOKEN_ID };
