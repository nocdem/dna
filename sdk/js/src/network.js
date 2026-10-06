// Network settings: which node(s) to connect to, which server keys to accept
// and which chain to expect — the wallet's NODUS_SEND_NETWORK shape
// (web-wallet/src/nodus/send-module.js), checked by the wallet's own
// validateNodusSendNetwork. The default is the wallet's testnet constants,
// imported (never restated here).
//
// What the wallet's check allows, and therefore what the SDK allows:
// endpoints are IPv4 dotted quads (no host names), 1..8 of them, tried in
// order; scheme 'wss' anywhere, 'ws' ONLY when every endpoint is 127.0.0.1
// (the localhost harness); 1..64 distinct pins (SHA3-512 of an accepted
// server's ML-DSA-87 public key). A server whose key is not pinned, or a node
// that reports another chain id, is refused by the module (fail-closed).
import { NODUS_SEND_NETWORK, NODUS_EVM_NETWORK, validateNodusSendNetwork, validateNodusEvmNetwork } from './wallet.js';

export const DEFAULT_NETWORK = NODUS_SEND_NETWORK;
export const DEFAULT_EVM_NETWORK = NODUS_EVM_NETWORK;

// "wss://203.0.113.7:443" | "ws://127.0.0.1:14005" -> { scheme, host, port }
export function parseEndpoint(text) {
  if (typeof text !== 'string') throw new Error('A node endpoint is text: wss://<IPv4>:<port> or ws://127.0.0.1:<port>.');
  const m = /^(wss|ws):\/\/([0-9.]+):(\d{1,5})\/?$/.exec(text.trim());
  if (!m) throw new Error('A node endpoint is wss://<IPv4>:<port> or ws://127.0.0.1:<port> (no host names).');
  return { scheme: m[1], host: m[2], port: Number(m[3]) };
}

// The network the SDK connects with: `network` (a whole settings object —
// default DEFAULT_NETWORK) with, when `endpoint` is given, its scheme and
// endpoint list replaced by that ONE endpoint (chain id and pins kept).
// Returned checked and frozen; throws on anything the wallet refuses.
export function resolveNetwork({ network = DEFAULT_NETWORK, endpoint } = {}) {
  let net = network;
  if (endpoint !== undefined) {
    const e = parseEndpoint(endpoint);
    net = { ...network, scheme: e.scheme, endpoints: [{ host: e.host, port: e.port }] };
  }
  return validateNodusSendNetwork(net);
}

// The EVM leg's ruleset identity (send-module.js NODUS_EVM_NETWORK); null =
// smart contracts off. The module compares it with the bytes it was compiled
// with and refuses any other value (nodus-send-wasm.c nsw_evm_net_set).
export function resolveEvmNetwork(evm = DEFAULT_EVM_NETWORK) {
  return evm === null ? null : validateNodusEvmNetwork(evm);
}
