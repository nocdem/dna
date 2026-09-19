// Mainnet definitions mirrored from messenger/blockchain/*/*_wallet.h and *_token.h.
export const CHAINS = {
  ethereum: { name: 'Ethereum', symbol: 'ETH', decimals: 18, chainId: 1, endpoint: 'https://eth.llamarpc.com', explorer: 'https://etherscan.io/tx/', tokens: [
    { symbol: 'USDT', decimals: 6, address: '0xdAC17F958D2ee523a2206206994597C13D831ec7' },
    { symbol: 'USDC', decimals: 6, address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
    { symbol: 'DAI', decimals: 18, address: '0x6B175474E89094C44Da98b954EescdeCB5AF3F' }] },
  bsc: { name: 'BNB Smart Chain', symbol: 'BNB', decimals: 18, chainId: 56, endpoint: 'https://bsc-dataseed.binance.org', explorer: 'https://bscscan.com/tx/', tokens: [
    { symbol: 'USDT', decimals: 18, address: '0x55d398326f99059fF775485246999027B3197955' },
    { symbol: 'USDC', decimals: 18, address: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d' }] },
  solana: { name: 'Solana', symbol: 'SOL', decimals: 9, endpoint: 'https://api.mainnet-beta.solana.com', explorer: 'https://solscan.io/tx/', tokens: [
    { symbol: 'USDT', decimals: 6, address: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB' },
    { symbol: 'USDC', decimals: 6, address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' }] },
  tron: { name: 'TRON', symbol: 'TRX', decimals: 6, endpoint: 'https://api.trongrid.io', explorer: 'https://tronscan.org/#/transaction/', tokens: [
    { symbol: 'USDT', decimals: 6, address: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' },
    { symbol: 'USDC', decimals: 6, address: 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8' },
    { symbol: 'USDD', decimals: 18, address: 'TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn' }] },
};
export function assetFor(chain, symbol) {
  const c = CHAINS[chain];
  if (!c) throw new Error('Unsupported chain.');
  if (symbol === c.symbol) return { symbol, decimals: c.decimals };
  const token = c.tokens.find(t => t.symbol === symbol);
  if (!token) throw new Error('Unsupported asset.');
  return token;
}
