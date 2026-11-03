// One table of the send / history flags that the trusted extension, the web wallet
// and Connect share for the post-quantum networks (operator 2026-11-03: "extansiuin
// ve connect ayni olmak zlrunda"; decisions/2026-10-31-wallet-three-surfaces.md:
// reuse shared source, platform-specific presentation). Each surface reads this
// table from its own capability file (extension/src/constants/capabilities.js,
// src/pq/wallet-capabilities.js) and keeps its own notes and exceptions there.
// A chain or network missing here keeps the flags of the shared base table
// (src/capabilities.js). The one network outside this table keeps its gate in the
// extension file, so that no web bundle carries its text.
const gate = (send, history) => Object.freeze(history === undefined ? { send } : { send, history });
export const PQ_SEND_GATES = Object.freeze({
  qtc: Object.freeze({ networks: Object.freeze({ mainnet: gate(true, true) }), otherwise: gate(false, true) }),
  ckb: Object.freeze({ networks: Object.freeze({ mainnet: gate(true, true) }), otherwise: gate(false, true) }),
  xion: Object.freeze({ networks: Object.freeze({ mainnet: gate(true) }), otherwise: gate(false) }),
  splendor: Object.freeze({ networks: Object.freeze({ mainnet: gate(true) }), otherwise: gate(false) }),
  asentum: Object.freeze({ networks: Object.freeze({ testnet: gate(true, true) }) }),
  soqucoin: Object.freeze({ networks: Object.freeze({ mainnet: gate(true, true) }) }),
  algorand: Object.freeze({ networks: Object.freeze({ mainnet: gate(true) }) })
});
// Chains whose local submissions the wallet-activity page lists (history flag above).
export const PQ_PAGE_HISTORY_CHAINS = Object.freeze(['asentum', 'ckb', 'qtc']);
// The flags this table sets for (chain, networkId), or undefined to keep the base table.
export function pqSendGate(chain, networkId) {
  if (typeof chain !== 'string' || !Object.hasOwn(PQ_SEND_GATES, chain)) return undefined;
  const rows = PQ_SEND_GATES[chain];
  return typeof networkId === 'string' && Object.hasOwn(rows.networks, networkId) ? rows.networks[networkId] : rows.otherwise;
}
