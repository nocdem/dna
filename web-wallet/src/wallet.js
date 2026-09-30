import * as evm from './adapters/evm.js';
import * as solana from './adapters/solana.js';
import * as tron from './adapters/tron.js';
import * as nodus from './adapters/nodus.js';
import { CHAINS, assetFor } from './config.js';
import { amountUnits, endpointUrl } from './core.js';
import { NODUS_ASSET } from './nodus/network.js';
// `nodus` is reached only through the NODUS send module's client
// (wallet.nodusClient, set by src/app.js while the module reports 'ready');
// without it prepare() refuses, so the entry changes nothing until then.
export const adapters = { ethereum: evm, bsc: evm, solana, tron, nodus };
function reviewed(prepared, fields) {
  let used = false;
  return { ...fields, fee: prepared.fee, expiresAt: prepared.expiresAt,
    cancel() { used = true; },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true; // A failed/ambiguous broadcast must never be retried automatically.
      if (!Number.isFinite(prepared.expiresAt) || Date.now() >= prepared.expiresAt) throw new Error('Review expired. Prepare the transfer again.');
      return prepared.send(onBroadcast);
    } };
}
export async function prepareTransfer({ wallet, chain, symbol, to, amount, endpoint, nodusLocked }, implementations = adapters) {
  if (!wallet || !implementations[chain]) throw new Error('Open a wallet first.');
  if (chain === NODUS_ASSET.chain) {
    // Recipient, amount, fee and expiry are decoded from the signed envelope by
    // the module, never taken from the form (design G1); `review` lists them.
    const prepared = await implementations.nodus.prepare({ client: wallet.nodusClient, from: wallet.addresses.nodus, to, amount, locked: nodusLocked });
    return reviewed(prepared, { endpoint: undefined, chain, symbol: prepared.symbol, to: prepared.to, amount: prepared.amount, from: wallet.addresses.nodus, review: prepared.review });
  }
  const asset = assetFor(chain, symbol), units = amountUnits(amount, asset.decimals);
  endpoint = endpointUrl(endpoint || CHAINS[chain].endpoint);
  const prepared = await implementations[chain].prepare({ wallet, chain, to: to.trim(), asset, units, endpoint });
  return reviewed(prepared, { endpoint, chain, symbol, to: to.trim(), amount, from: wallet.addresses[chain], nonce: prepared.nonce });
}
