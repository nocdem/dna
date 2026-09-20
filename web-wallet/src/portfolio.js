import { CHAINS } from './config.js';
import { request, formatUnits } from './core.js';

const nativeIds = { ethereum: 'ethereum', bsc: 'binancecoin', solana: 'solana', tron: 'tron' };
export const BALANCE_MAX_AGE = 5 * 60 * 1000;
export const PRICE_MAX_AGE = 15 * 60 * 1000;
export const ASSETS = Object.entries(CHAINS).flatMap(([chain, c]) => [
  { chain, symbol: c.symbol, decimals: c.decimals, priceId: `coingecko:${nativeIds[chain]}` },
  ...c.tokens.map(t => ({ chain, ...t, priceId: `${chain}:${t.address}` }))
].map(asset => ({ ...asset, key: `${chain}:${asset.symbol}` })));
export const PRICE_URL = `https://coins.llama.fi/prices/current/${ASSETS.map(a => a.priceId).join(',')}`;
const USD_SCALE = 100000000n;

export function balanceUnits(value, decimals) {
  if (typeof value !== 'string' || value.length > 90 || !/^(0|[1-9]\d*)(\.\d+)?$/.test(value)) throw new Error('Invalid balance.');
  const [whole, fraction = ''] = value.split('.');
  if (fraction.length > decimals) throw new Error('Invalid balance precision.');
  const units = BigInt(whole + fraction.padEnd(decimals, '0'));
  if (units >= 2n ** 256n) throw new Error('Balance out of range.');
  return units;
}
export function chainBalances(chain, rows, observedAt = Date.now()) {
  const expected = ASSETS.filter(a => a.chain === chain);
  if (!Array.isArray(rows) || rows.length > 100) throw new Error('Invalid balance response.');
  return Object.fromEntries(expected.map(asset => {
    const matches = rows.filter(row => row?.symbol === asset.symbol);
    try {
      if (matches.length !== 1 || matches[0].error) throw new Error();
      const units = balanceUnits(matches[0].balance, asset.decimals);
      return [asset.key, { state: 'ready', units, observedAt }];
    } catch { return [asset.key, { state: 'error', error: 'Balance unavailable' }]; }
  }));
}
export function parsePrices(data, now = Date.now()) {
  if (!data?.coins || typeof data.coins !== 'object' || Array.isArray(data.coins)) throw new Error('Price response unavailable.');
  const quotes = {};
  for (const asset of ASSETS) {
    const row = data.coins[asset.priceId];
    if (!row || typeof row.price !== 'number' || !Number.isFinite(row.price) || row.price <= 0 || row.price > 1e9 ||
        typeof row.confidence !== 'number' || !Number.isFinite(row.confidence) || row.confidence < .9 || row.confidence > 1 ||
        !Number.isSafeInteger(row.timestamp) || Math.abs(row.timestamp) > 1e12 ||
        typeof row.symbol !== 'string' || row.symbol.toUpperCase() !== asset.symbol ||
        (asset.address && row.decimals !== asset.decimals)) continue;
    const observedAt = row.timestamp * 1000;
    if (now - observedAt > PRICE_MAX_AGE || observedAt - now > 60000) continue;
    const units = BigInt(row.price.toFixed(8).replace('.', ''));
    if (units <= 0n) continue;
    quotes[asset.key] = { units, observedAt };
  }
  return quotes;
}
export async function readPrices({ signal, fetcher } = {}) {
  return parsePrices(await request(PRICE_URL, undefined, { signal, fetcher }));
}
export function portfolioSnapshot(balances, quotes, now = Date.now()) {
  const rows = ASSETS.map(asset => {
    const balance = balances[asset.key] || { state: 'idle' }, quote = quotes[asset.key];
    const freshBalance = balance.state === 'ready' && now - balance.observedAt <= BALANCE_MAX_AGE && balance.observedAt <= now;
    const freshPrice = quote && now - quote.observedAt <= PRICE_MAX_AGE && quote.observedAt <= now + 60000;
    const usd = freshBalance && (balance.units === 0n || freshPrice)
      ? balance.units * (quote?.units || 0n) / (10n ** BigInt(asset.decimals)) : null;
    return { ...asset, ...balance, state: balance.state === 'ready' && !freshBalance ? 'stale' : balance.state,
      balance: freshBalance ? formatUnits(balance.units, asset.decimals) : null, usd,
      positive: freshBalance && balance.units > 0n, priceMissing: freshBalance && balance.units > 0n && !freshPrice };
  });
  const known = rows.filter(row => row.usd !== null), total = known.reduce((sum, row) => sum + row.usd, 0n);
  const complete = known.length === rows.length;
  const state = rows.every(r => r.state === 'idle') ? 'idle' : rows.some(r => r.state === 'loading') ? 'loading' : complete ? 'complete' : 'partial';
  return { rows, complete, state, known: known.length, total: complete || total > 0n ? total : null,
    positive: known.some(row => row.positive), missingBalances: rows.filter(r => r.balance === null).length,
    missingPrices: rows.filter(r => r.priceMissing).length };
}
export function groupAssets(rows, filter = 'all') {
  const groups = new Map();
  for (const row of rows.filter(r => filter === 'all' || r.chain === filter)) {
    if (!groups.has(row.symbol)) groups.set(row.symbol, []);
    groups.get(row.symbol).push(row);
  }
  return [...groups].map(([symbol, entries]) => {
    const known = entries.filter(row => row.balance !== null);
    const units = known.reduce((sum, row) => sum + row.units * (10n ** BigInt(18 - row.decimals)), 0n);
    const valued = entries.filter(row => row.usd !== null), usd = valued.reduce((sum, row) => sum + row.usd, 0n);
    return { symbol, rows: entries, balance: known.length ? formatUnits(units, 18) : null,
      partialBalance: known.length !== entries.length, partialValue: valued.length !== entries.length,
      usd: valued.length === entries.length || usd > 0n ? usd : null, positive: valued.some(row => row.positive) };
  }).sort((a, b) => {
    const order = ['USDT', 'USDC', 'ETH', 'BNB', 'SOL', 'TRX', 'DAI', 'USDD'];
    return order.indexOf(a.symbol) - order.indexOf(b.symbol);
  });
}
export function usdText(units, positive = false) {
  if (units === null) return '—';
  if (units < USD_SCALE / 100n && (units > 0n || positive)) return '<$0.01';
  const cents = (units + USD_SCALE / 200n) / (USD_SCALE / 100n);
  return '$' + (cents / 100n).toLocaleString('en-US') + '.' + String(cents % 100n).padStart(2, '0');
}
