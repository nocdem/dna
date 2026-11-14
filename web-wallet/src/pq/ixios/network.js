// Ixios as a wallet network, alongside Cellframe (src/config.js CELLFRAME) and
// its unpriced asset (src/portfolio.js CPUNK_ASSET), but kept in this module.
//
// Not part of CHAINS: src/wallet.js reaches Ixios through its own branch
// (src/pq/ixios-transfer.js), not an adapter. Whether Send is offered is
// `receiveOnly`, set per network from the shared send gate (the table in
// src/pq/send-gates.js). Its balance is read like Cellframe's, by
// src/pq/ixios/balance.js against `endpoint` (or the RPC the user picks from
// `rpcOptions` or enters as a custom HTTPS endpoint).
//
// This module also holds the fixed values of both Ixios networks (IXIOS_NETWORKS
// below): everything that differs between the main network and the test network.
// It imports nothing from the other Ixios modules.
const IXIOS_RPC = 'https://ixios-rpc.innova.limited';
export const IXIOS_NETWORK = {
  networkGroup: 'pq',
  name: 'Ixios', symbol: 'IXIOS', decimals: 18, icon: 'ixios.png', tokens: [], receiveOnly: true,
  endpoint: IXIOS_RPC, rpcOptions: [{ url: IXIOS_RPC, label: 'Ixios public RPC' }],
  // Fail-closed base: no send and no send note of its own. Each surface sets receiveOnly and the note from the shared send
  // gate (src/pq/wallet-capabilities.js walletIxiosNetwork; the extension's extensionNetworkConfig).
};
// Unpriced like CPUNK_ASSET: no priceId, so it never enters PRICE_URL and never
// counts toward the USD total or its completeness.
export const IXIOS_ASSET = { chain: 'ixios', symbol: 'IXIOS', decimals: 18, key: 'ixios:IXIOS' };

// The networks, by id. Numbers, not BigInt, so an entry can cross a message port; modules convert with BigInt() where
// they compare heights. Identity is the genesis hash (block 1's parentHash), never the chain id alone. The main entry is
// the wallet's long-standing constants. Observed on the test node: the `ixios_` method names (no `eth_` name exists
// there), chain id 3, the genesis hash, and no `getCode`, which is why `getProof` is the account-code query. Not
// observed: Aegis height 300 is the reference's value for chain id 3; the height the running node uses is not
// established. Nothing is detected or chosen from a node answer: a network's method names are fixed here.
const network = (id, label, endpoint, rpcLabel, genesisHash, chainId, aegisHeight, rpcNamespace, codeQuery) => Object.freeze({
  id, label, endpoint, rpcOptions: Object.freeze([Object.freeze({ url: endpoint, label: rpcLabel })]),
  genesisHash, chainId, aegisHeight, rpcNamespace, codeQuery,
});
export const IXIOS_NETWORKS = Object.freeze({
  mainnet: network('mainnet', 'Mainnet', IXIOS_RPC, 'Ixios public RPC', '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f', 1, 32400000, 'eth', 'getCode'),
  testnet: network('testnet', 'Testnet', 'https://nx-rpc.ixoflow.io', 'Ixios test network RPC', '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe', 3, 300, 'ixios', 'getProof'),
});
// Fails closed: an id that is not in the table is never mapped to a default network.
export function ixiosNetwork(id) {
  if (typeof id !== 'string' || !Object.hasOwn(IXIOS_NETWORKS, id)) throw new Error('Unknown Ixios network.');
  return IXIOS_NETWORKS[id];
}
export const ixiosMethod = (entry, name) => `${entry.rpcNamespace}_${name}`;

// Account-code check for a network whose `codeQuery` is `getProof`: the account has no code exactly when the answer's
// `codeHash` is the zero hash (no such account) or the hash of empty code (Keccak-256 of nothing). Any other well-formed
// hash means code. The answer must be an object for the requested address with a 32-byte hex `codeHash`, else it throws.
// Like `getCode`, the answer is the provider's; the accountProof in it is not checked against a state root.
export const IXIOS_EMPTY_CODE_HASH = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const ZERO_HASH = '0x' + '00'.repeat(32);
export function ixiosProofCodeEmpty(address, answer) {
  if (typeof address !== 'string' || !answer || typeof answer !== 'object' || typeof answer.address !== 'string' || answer.address.toLowerCase() !== address.toLowerCase()
    || typeof answer.codeHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(answer.codeHash)) throw new Error('Invalid Ixios account code.');
  const hash = answer.codeHash.toLowerCase();
  return hash === ZERO_HASH || hash === IXIOS_EMPTY_CODE_HASH;
}
