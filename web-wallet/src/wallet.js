import * as evm from './adapters/evm.js';
import * as solana from './adapters/solana.js';
import * as tron from './adapters/tron.js';
import { CHAINS, assetFor } from './config.js';
import { amountUnits, endpointUrl } from './core.js';
export const adapters = { ethereum: evm, bsc: evm, solana, tron };
export async function prepareTransfer({ wallet, chain, symbol, to, amount, endpoint }, implementations = adapters) {
  if (!wallet || !implementations[chain]) throw new Error('Open a wallet first.');
  const asset = assetFor(chain, symbol), units = amountUnits(amount, asset.decimals);
  endpoint = endpointUrl(endpoint || CHAINS[chain].endpoint);
  const prepared = await implementations[chain].prepare({ wallet, chain, to: to.trim(), asset, units, endpoint });
  let used = false;
  return { endpoint, chain, symbol, to: to.trim(), amount, from: wallet.addresses[chain], fee: prepared.fee, expiresAt: prepared.expiresAt,
    cancel() { used = true; },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true; // A failed/ambiguous broadcast must never be retried automatically.
      if (!Number.isFinite(prepared.expiresAt) || Date.now() >= prepared.expiresAt) throw new Error('Review expired. Prepare the transfer again.');
      return prepared.send(onBroadcast);
    } };
}
