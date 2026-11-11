import { CHAINS } from '../../../src/config.js';

// Ethereum Sepolia for websites (operator 2026-11-10, givens item 81: "Her site
// eklentiyi Sepolia'ya geçirebilsin."; plan 2026-11-08-swap-bot-plan.nodus1.md
// section 18 change 6). It is defined here, in the extension, and not in the
// shared src/config.js CHAINS table: that table is read by the web wallet and
// Connect and iterates into their asset lists, so a new entry there would add a
// Sepolia asset to both (WALLET SURFACES: fewest shared edits).
// Values from the pinned chain list
// /home/nocdem/refs/ethereum-lists-chains-2b31d670/_data/chains/eip155-11155111.json:
// name :2, chainId :30, rpc "https://ethereum-sepolia-rpc.publicnode.com" :13,
// nativeCurrency ETH / 18 decimals :25-26, explorer etherscan-sepolia :35-36.
// The test USDT (givens item 77) is deployed later and its address is not
// known here, so no token is listed; a site names the token contract it pays.
export const SEPOLIA = Object.freeze({
  name: 'Ethereum Sepolia', symbol: 'ETH', decimals: 18, chainId: 11155111,
  endpoint: 'https://ethereum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.etherscan.io/tx/',
  rpcOptions: Object.freeze([Object.freeze({ url: 'https://ethereum-sepolia-rpc.publicnode.com', label: 'PublicNode' })]),
  tokens: Object.freeze([]), testnet: true,
});

// Every network the extension's EVM provider can have selected, by chain key.
export const EVM_NETWORKS = Object.freeze({ ethereum: CHAINS.ethereum, bsc: CHAINS.bsc, sepolia: SEPOLIA });
export const EVM_CHAINS = Object.freeze(Object.keys(EVM_NETWORKS));
// The networks the wallet's own screens (balances, send, RPC choice) and the
// saved endpoint state cover. Sepolia is reached only through a website's
// switch: it has no saved endpoint and no wallet send or balance screen.
export const WALLET_EVM_CHAINS = Object.freeze(['ethereum', 'bsc']);
// A chain key's receive address: Sepolia uses the Ethereum account.
export const evmAddressKey = chain => (chain === 'sepolia' ? 'ethereum' : chain);
