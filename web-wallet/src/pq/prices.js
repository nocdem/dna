// Exact native identities, not symbol searches. Provider listings verified
// 2026-11-02: coingecko.com/en/coins/{algorand,nervos-network,tidecoin,soqucoin,xion}.
// A listing is NOT a promise that the existing Llama feed serves a fresh quote.
// QTC's ticker is ambiguous; SPLD/ASE have no verified mapping here.
export const PQ_PRICE_IDS = Object.freeze({
  algorand: 'coingecko:algorand', ckb: 'coingecko:nervos-network',
  tidecoin: 'coingecko:tidecoin', soqucoin: 'coingecko:soqucoin', xion: 'coingecko:xion',
});

export function validatedAssetPrices(data, assets, now, maxAge) {
  if (!data?.coins || typeof data.coins !== 'object' || Array.isArray(data.coins)) throw new Error('Price response unavailable.');
  const quotes = {};
  for (const asset of assets) {
    if (!asset.priceId || asset.testnet) continue;
    const row = data.coins[asset.priceId];
    if (!row || typeof row.price !== 'number' || !Number.isFinite(row.price) || row.price <= 0 || row.price > 1e9 ||
        typeof row.confidence !== 'number' || !Number.isFinite(row.confidence) || row.confidence < .9 || row.confidence > 1 ||
        !Number.isSafeInteger(row.timestamp) || Math.abs(row.timestamp) > 1e12 ||
        typeof row.symbol !== 'string' || row.symbol.toUpperCase() !== asset.symbol ||
        (asset.address && row.decimals !== asset.decimals)) continue;
    const observedAt = row.timestamp * 1000;
    if (now - observedAt > maxAge || observedAt - now > 60000) continue;
    const units = BigInt(row.price.toFixed(8).replace('.', ''));
    if (units <= 0n) continue;
    quotes[asset.key] = { units, observedAt };
  }
  return quotes;
}
