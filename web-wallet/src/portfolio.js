import { PQ_ENTRIES } from './pq/networks.js';
import { validatedAssetPrices } from './pq/prices.js';
import { CHAINS } from './config.js';
import { request, formatUnits } from './core.js';

const nativeIds = { ethereum: 'ethereum', bsc: 'binancecoin', solana: 'solana', tron: 'tron' };
export const BALANCE_MAX_AGE = 5 * 60 * 1000;
export const PRICE_MAX_AGE = 15 * 60 * 1000;
export const ASSETS = Object.entries(CHAINS).flatMap(([chain, c]) => [
  { chain, symbol: c.symbol, decimals: c.decimals, priceId: `coingecko:${nativeIds[chain]}` },
  ...c.tokens.map(t => ({ chain, ...t, priceId: `${chain}:${t.address}` }))
].map(asset => ({ ...asset, key: `${chain}:${asset.symbol}` })));
export const PRICE_ASSETS = [...ASSETS, ...PQ_ENTRIES.map(({ asset }) => asset).filter(asset => asset.priceId)];
export const PRICE_URL = `https://coins.llama.fi/prices/current/${PRICE_ASSETS.map(a => a.priceId).join(',')}`;
// Read-only Cellframe/CPUNK balance row. Unpriced by design: no priceId, so it
// never enters PRICE_URL and is always excluded from the USD total (see the
// `priced` scoping in portfolioSnapshot below), matching the README promise
// that CPUNK has no price display. Merged into the live app's asset list only
// by portfolio-view.js when the CPUNK module is enabled.
export const CPUNK_ASSET = { chain: 'cellframe', symbol: 'CPUNK', decimals: 18, key: 'cellframe:CPUNK' };
const USD_SCALE = 100000000n;

export function balanceUnits(value, decimals) {
  if (typeof value !== 'string' || value.length > 90 || !/^(0|[1-9]\d*)(\.\d+)?$/.test(value)) throw new Error('Invalid balance.');
  const [whole, fraction = ''] = value.split('.');
  if (fraction.length > decimals) throw new Error('Invalid balance precision.');
  const units = BigInt(whole + fraction.padEnd(decimals, '0'));
  if (units >= 2n ** 256n) throw new Error('Balance out of range.');
  return units;
}
// The buttons of one holding row (src/portfolio-view.js): a receive-only
// network offers Receive only, and so does an UNAVAILABLE token (its metadata
// did not equal the pin: never offered for Send); Earn follows `earn`.
export function holdingActions(network, row, earn = false) {
  // The CURRENT pins decide too (network.tokens[].available), not only the
  // last balance read's flag: a pin that turned unavailable hides Send at once.
  const pinned = network.tokens?.find(t => t.symbol === row.symbol);
  return [...(network.receiveOnly || row.unavailable === true || pinned?.available === false ? ['Receive'] : ['Send', 'Receive']), ...(earn ? ['Earn'] : [])];
}
// The status line for a selected asset that is unavailable right now
// (src/app.js applyAssetGate): the selection is kept, Review is refused.
export function unavailableAssetNote(symbol) { return `${symbol} is unavailable right now — choose another asset`; }
// True when two asset lists hold the same keys in the same order: a network
// definition change that keeps them (pin availability) needs no re-read
// (src/portfolio-view.js setNetwork `keepRead`).
export function sameAssetKeys(before, after) { return before.length === after.length && after.every((a, i) => a.key === before[i].key); }
// Only fixed labels and a validated HTTP status leave this boundary. Provider
// messages may contain addresses, endpoints or other sensitive data.
export function balanceErrorDetail(error) {
  if (Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599) return `HTTP ${error.status}`;
  const message = typeof error?.message === 'string' ? error.message : '';
  if (/^(?:RPC is connected to the wrong network|Algorand provider is connected to the wrong network)\.$/.test(message)) return 'Wrong network';
  if (/^(?:CPUNK connection timed out\. Try again later\.|Request timed out\.)$/.test(message) || error?.name === 'TimeoutError') return 'Connection timed out';
  if (message === 'RPC unavailable. Check the HTTPS endpoint, browser CORS access and connection.') return 'Connection unavailable';
  if (/^(?:Invalid balance response|RPC returned invalid JSON|RPC returned no result|RPC response identifier or version does not match)\.$/.test(message)) return 'Invalid response';
  return 'Balance unavailable';
}
export function unavailableBalanceLabel(chain) {
  return chain === 'nodus' ? 'Nodus not ready' : 'No balance reader';
}
export function chainBalances(chain, rows, observedAt = Date.now(), assets = ASSETS) {
  const expected = assets.filter(a => a.chain === chain);
  if (!Array.isArray(rows) || rows.length > 100) throw new Error('Invalid balance response.');
  return Object.fromEntries(expected.map(asset => {
    const matches = rows.filter(row => row?.symbol === asset.symbol);
    try {
      if (matches.length !== 1 || matches[0].error) throw new Error();
      const units = balanceUnits(matches[0].balance, asset.decimals);
      return [asset.key, { state: 'ready', units, observedAt }];
    } catch {
      // `unavailable`: the row's reader says the asset itself cannot be used
      // right now (a pinned token whose chain metadata does not equal the
      // pin, src/adapters/nodus.js balances) — shown as such, not as a read
      // failure; never a zero.
      return [asset.key, { state: 'error', error: 'Balance unavailable', ...(matches.length === 1 && matches[0].unavailable === true ? { unavailable: true } : {}) }];
    }
  }));
}
export function parsePrices(data, now = Date.now()) {
  return validatedAssetPrices(data, PRICE_ASSETS, now, PRICE_MAX_AGE);
}
export async function readPrices({ signal, fetcher } = {}) {
  return parsePrices(await request(PRICE_URL, undefined, { signal, fetcher }));
}
// `kept`: assetKey -> { units, observedAt } — the last balance read for this
// wallet (this session, or saved encrypted with a saved wallet: decision
// 2026-10-02-device-cache-only-when-saved). A row with no current balance
// shows it with its read time (`keptAt`), like the app's wallet cache
// (messenger/database/wallet_cache.h: stale-while-revalidate); it is never
// priced, never part of the total and still counts as a missing balance.
// `balanceMaxAge`: how old a read balance may be and still count (default
// BALANCE_MAX_AGE; longer while the balances are read again automatically,
// src/portfolio-view.js setAutoRefresh — never shorter than the default).
export function portfolioSnapshot(balances, quotes, now = Date.now(), assets = ASSETS, kept = {}, { balanceMaxAge = BALANCE_MAX_AGE } = {}) {
  const maxAge = Math.max(BALANCE_MAX_AGE, balanceMaxAge);
  const rows = assets.map(asset => {
    // An asset with no balance source yet (NODUS, flagged by portfolio-view.js)
    // is always 'unsupported', whatever `balances` holds: never read, never an
    // amount, a zero or an error, and never priced.
    // While it is unavailable only for a moment (NODUS while the connection is
    // made again), the last balance read for this address is shown as last
    // read (0.1.96, operator 2026-10-12: "disconnect olduktan sonra reconnect
    // olana kadar en son balansları yüklese") — never priced, never in the total.
    if (asset.balanceUnavailable) {
      const last = typeof kept[asset.key]?.units === 'bigint' ? kept[asset.key] : undefined;
      return { ...asset, state: 'unsupported', balance: last ? formatUnits(last.units, asset.decimals) : null,
        ...(last ? { units: last.units, keptAt: last.observedAt } : {}), usd: null, positive: false, priceMissing: false };
    }
    const balance = balances[asset.key] || { state: 'idle' }, quote = quotes[asset.key];
    const priced = asset.priceId !== undefined;
    const freshBalance = balance.state === 'ready' && now - balance.observedAt <= maxAge && balance.observedAt <= now;
    const freshPrice = quote && now - quote.observedAt <= PRICE_MAX_AGE && quote.observedAt <= now + 60000;
    // Unpriced assets (e.g. CPUNK) never resolve a USD value, even at a known zero
    // balance: there is no price feed for them to be consistent against.
    const usd = priced && freshBalance && (balance.units === 0n || freshPrice)
      ? balance.units * (quote?.units || 0n) / (10n ** BigInt(asset.decimals)) : null;
    const last = !freshBalance && typeof kept[asset.key]?.units === 'bigint' ? kept[asset.key] : undefined;
    // A kept balance is valued at once when a price was kept with it (or the fresh price, which then replaces the kept
    // one): the total shows the last read value while the fresh reads are made. A kept balance whose price was never
    // kept stays out of the total.
    // It counts only while that asset's fresh read is still to come (idle) or running (loading): once the read FAILED, or
    // the read balance has aged out, the asset leaves the total as before (its row still shows the last read value and time).
    const waiting = balance.state === 'idle' || balance.state === 'loading';
    const keptPrice = last && priced && waiting && typeof last.price?.units === 'bigint' ? (freshPrice ? quote : last.price) : undefined;
    const keptUsd = keptPrice ? last.units * keptPrice.units / (10n ** BigInt(asset.decimals)) : null;
    return { ...asset, ...balance, state: balance.state === 'ready' && !freshBalance ? 'stale' : balance.state,
      balance: freshBalance ? formatUnits(balance.units, asset.decimals) : last ? formatUnits(last.units, asset.decimals) : null,
      ...(last ? { units: last.units, keptAt: last.observedAt } : {}), usd: usd ?? keptUsd,
      ...(keptUsd !== null && usd === null ? { keptUsd: true, keptPriceAt: keptPrice.observedAt } : {}),
      positive: freshBalance && balance.units > 0n, priceMissing: priced && freshBalance && balance.units > 0n && !freshPrice };
  });
  const priced = rows.filter(row => row.priceId !== undefined);
  const known = priced.filter(row => row.usd !== null), total = known.reduce((sum, row) => sum + row.usd, 0n);
  const complete = known.length === priced.length;
  // The rows whose value comes from a kept balance: the total is then the last read value, as old as the oldest of
  // their balance reads (the label says so until every row is read again).
  const keptKnown = known.filter(row => row.keptUsd);
  // 'unsupported' rows are never read, so they take no part in the load state.
  const tracked = rows.filter(r => r.state !== 'unsupported');
  const state = tracked.every(r => r.state === 'idle') ? 'idle' : tracked.some(r => r.state === 'loading') ? 'loading' : complete ? 'complete' : 'partial';
  // The "X balances / Y prices unavailable" hero summary, like the total and
  // completeness above, is scoped to the priced assets only: an unpriced
  // asset's own load state is already visible on its own row and never was
  // part of "the estimate covers only the 14 configured balances".
  return { rows, complete, state, known: known.length, total: complete || total > 0n ? total : null,
    positive: known.some(row => row.positive || (row.keptUsd && row.units > 0n)),
    keptCount: keptKnown.length, keptAt: keptKnown.length ? Math.min(...keptKnown.map(row => Math.min(row.keptAt, row.keptPriceAt))) : undefined,
    missingBalances: priced.filter(r => r.balance === null || r.keptAt !== undefined).length,
    missingPrices: priced.filter(r => r.priceMissing).length };
}
// The listing order (0.1.102, operator 2026-10-12): NODUS first, then the
// stablecoins in this order, then every other coin by its network's name
// (`networkNames`: chain key -> shown name; "BNB Smart Chain", "Cellframe",
// "Ethereum", "Ixios", "Solana", "TRON"), compared case-insensitively code
// unit by code unit (no locale), so the order is the same on every device.
const STABLECOINS = ['USDT', 'USDC', 'DAI', 'USDD'];
// Zero balances hidden (0.1.113, operator 2026-10-13: "sıfır olan bakiyeleri
// göstermenin bir anlamı yok … settings olması lazım … Hiç olmayan … Kaç dolar
// olduğu değil, bir şey olup olmadığı önemli"): with `hideZero`, a row whose
// amount was read as exactly 0 is left out — by the amount, never by its
// dollar value (an unpriced asset that is held stays). A row whose amount is
// not known (reading, failed, not read) stays: it may hold something. NODUS
// always stays (the wallet's own asset; Send / Receive start there). An asset
// whose every row is left out disappears; one held on some networks shows
// only those.
export function zeroRow(row) {
  return row.symbol !== 'NODUS' && row.balance !== null && row.units === 0n;
}
export function groupAssets(rows, filter = 'all', networkNames = {}, { hideZero = false } = {}) {
  const groups = new Map();
  for (const row of rows.filter(r => (filter === 'all' || r.chain === filter) && !(hideZero && zeroRow(r)))) {
    if (!groups.has(row.symbol)) groups.set(row.symbol, []);
    groups.get(row.symbol).push(row);
  }
  return [...groups].map(([symbol, entries]) => {
    const known = entries.filter(row => row.balance !== null);
    const units = known.reduce((sum, row) => sum + row.units * (10n ** BigInt(18 - row.decimals)), 0n);
    const valued = entries.filter(row => row.usd !== null), usd = valued.reduce((sum, row) => sum + row.usd, 0n);
    const priced = entries.some(row => row.priceId !== undefined);
    return { symbol, rows: entries, balance: known.length ? formatUnits(units, 18) : null,
      partialBalance: known.length !== entries.length, partialValue: valued.length !== entries.length,
      usd: priced ? (valued.length === entries.length || usd > 0n ? usd : null) : null, positive: valued.some(row => row.positive) };
  }).sort((a, b) => {
    const rank = g => g.symbol === 'NODUS' ? 0 : STABLECOINS.includes(g.symbol) ? 1 + STABLECOINS.indexOf(g.symbol) : 1 + STABLECOINS.length;
    const name = g => String(networkNames[g.rows[0].chain] ?? g.rows[0].chain).toLowerCase();
    const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
    return rank(a) - rank(b) || cmp(name(a), name(b)) || cmp(a.symbol, b.symbol);
  });
}
// Display form of a decimal balance string (formatUnits output, e.g.
// "20123456.123456789012345678"): thousands separators and at most 6
// fractional digits, TRUNCATED (never rounded up — the wallet must not show
// more than is held), trailing zeros removed; a positive amount below 0.000001
// reads "<0.000001". Display only: the exact string stays the value used for
// sending and review, and is shown on hover (title). Operator 2026-09-30:
// 18-decimal balances (CPUNK, ETH) wrapped mid-number and looked like a
// separate label ("… 28 ETH").
export const DISPLAY_DECIMALS = 6;
export function displayAmount(value) {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(String(value));
  if (!match) return String(value);
  const whole = match[1].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = (match[2] ?? '').slice(0, DISPLAY_DECIMALS).replace(/0+$/, '');
  if (!fraction && /^0+$/.test(match[1]) && /[1-9]/.test(match[2] ?? '')) return `<0.${'0'.repeat(DISPLAY_DECIMALS - 1)}1`;
  return fraction ? `${whole}.${fraction}` : whole;
}
export function usdText(units, positive = false) {
  if (units === null) return '—';
  if (units < USD_SCALE / 100n && (units > 0n || positive)) return '<$0.01';
  const cents = (units + USD_SCALE / 200n) / (USD_SCALE / 100n);
  return '$' + (cents / 100n).toLocaleString('en-US') + '.' + String(cents % 100n).padStart(2, '0');
}

// Show only displayable nonzero holdings when the filter is enabled.
const displayedHolding = row => row.balance != null && typeof row.units === 'bigint' && row.units !== 0n;
export function zeroNetwork(rows) {
  return !rows.some(displayedHolding);
}
export function groupNetworks(rows, { hideZero = false } = {}) {
  const groups = new Map();
  for (const row of rows) {
    if (hideZero && !displayedHolding(row)) continue;
    if (!groups.has(row.chain)) groups.set(row.chain, []);
    groups.get(row.chain).push(row);
  }
  return [...groups].map(([chain, rows]) => ({ chain, rows }));
}
