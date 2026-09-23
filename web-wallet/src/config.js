// Mainnet definitions based on native headers, with browser RPCs and issuer-verified DAI.
// Provider/identity references and deployment corrections: README.md.
import { CPUNK_ENDPOINT } from './cpunk-protocol.js';
// A private-submission note is shown to the user when they pick that provider
// in the RPC select (index.html #rpc-choice / app.js populateRpcChoice()).
const PRIVATE_SUBMISSION_NOTE = 'private submission — transactions are not visible in the public mempool until mined';
export const CHAINS = {
  ethereum: { name: 'Ethereum', symbol: 'ETH', decimals: 18, chainId: 1, endpoint: 'https://ethereum-rpc.publicnode.com', explorer: 'https://etherscan.io/tx/', icon: 'eth.svg', rpcOptions: [
    { url: 'https://ethereum-rpc.publicnode.com', label: 'PublicNode' },
    { url: 'https://eth.drpc.org', label: 'dRPC' },
    { url: 'https://eth-mainnet.public.blastapi.io', label: 'Blast API' },
    { url: 'https://rpc.flashbots.net', label: 'Flashbots Protect', note: PRIVATE_SUBMISSION_NOTE },
    { url: 'https://rpc.mevblocker.io', label: 'MEV Blocker', note: PRIVATE_SUBMISSION_NOTE }], tokens: [
    { symbol: 'USDT', decimals: 6, address: '0xdAC17F958D2ee523a2206206994597C13D831ec7' },
    { symbol: 'USDC', decimals: 6, address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
    { symbol: 'DAI', decimals: 18, address: '0x6B175474E89094C44Da98b954EedeAC495271d0F' }] },
  bsc: { name: 'BNB Smart Chain', symbol: 'BNB', decimals: 18, chainId: 56, endpoint: 'https://bsc-dataseed.binance.org', explorer: 'https://bscscan.com/tx/', icon: 'bnb.svg', rpcOptions: [
    { url: 'https://bsc-dataseed.binance.org', label: 'Binance (dataseed)' },
    { url: 'https://bsc-dataseed1.binance.org', label: 'Binance (dataseed1)' },
    { url: 'https://bsc-dataseed2.binance.org', label: 'Binance (dataseed2)' },
    { url: 'https://bsc-dataseed3.binance.org', label: 'Binance (dataseed3)' },
    { url: 'https://bsc-dataseed4.binance.org', label: 'Binance (dataseed4)' },
    { url: 'https://bsc-dataseed1.defibit.io', label: 'Defibit' },
    { url: 'https://bsc-dataseed1.ninicoin.io', label: 'Ninicoin' },
    { url: 'https://bsc-rpc.publicnode.com', label: 'PublicNode' }], tokens: [
    { symbol: 'USDT', decimals: 18, address: '0x55d398326f99059fF775485246999027B3197955' },
    { symbol: 'USDC', decimals: 18, address: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d' }] },
  solana: { genesisHash: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d', name: 'Solana', symbol: 'SOL', decimals: 9, endpoint: 'https://public.rpc.solanavibestation.com', explorer: 'https://solscan.io/tx/', icon: 'sol.svg', rpcOptions: [
    { url: 'https://public.rpc.solanavibestation.com', label: 'Solana Vibe Station' }], tokens: [
    { symbol: 'USDT', decimals: 6, address: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB' },
    { symbol: 'USDC', decimals: 6, address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' }] },
  tron: { genesisHash: '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc', name: 'TRON', symbol: 'TRX', decimals: 6, endpoint: 'https://api.trongrid.io', explorer: 'https://tronscan.org/#/transaction/', icon: 'trx.svg', rpcOptions: [
    { url: 'https://api.trongrid.io', label: 'TronGrid' }], tokens: [
    { symbol: 'USDT', decimals: 6, address: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' },
    { symbol: 'USDC', decimals: 6, address: 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8' },
    { symbol: 'USDD', decimals: 18, address: 'TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn' }] },
};
// Read-only Cellframe network, shown alongside the sendable chains above but kept
// out of CHAINS: src/wallet.js's adapter map has no 'cellframe' entry, so
// prepareTransfer() cannot route a send to it (it rejects before assetFor() is
// reached), and this network carries no priced token list. `receiveOnly` drives
// the UI's send-form disabling and single Receive button for its assets.
export const CELLFRAME = { name: 'Cellframe', symbol: 'CPUNK', decimals: 18, endpoint: CPUNK_ENDPOINT, icon: 'cellframe.svg', rpcOptions: [{ url: CPUNK_ENDPOINT, label: 'CPUNK network' }], tokens: [], receiveOnly: true };
export function assetFor(chain, symbol) {
  const c = CHAINS[chain];
  if (!c) throw new Error('Unsupported chain.');
  if (symbol === c.symbol) return { symbol, decimals: c.decimals };
  const token = c.tokens.find(t => t.symbol === symbol);
  if (!token) throw new Error('Unsupported asset.');
  return token;
}
