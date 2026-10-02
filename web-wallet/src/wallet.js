import * as evm from './adapters/evm.js';
import * as solana from './adapters/solana.js';
import * as tron from './adapters/tron.js';
import * as nodus from './adapters/nodus.js';
import { CHAINS, assetFor } from './config.js';
import { amountUnits, endpointUrl } from './core.js';
import { NODUS_ASSET } from './nodus/network.js';
import { chainName } from './nodus/names.js';
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
    return reviewed(prepared, { endpoint: undefined, chain, symbol: prepared.symbol, to: prepared.to, recipientName: prepared.recipientName, amount: prepared.amount, from: wallet.addresses.nodus, review: prepared.review });
  }
  const asset = assetFor(chain, symbol), units = amountUnits(amount, asset.decimals);
  endpoint = endpointUrl(endpoint || CHAINS[chain].endpoint);
  // HF-4 send to a chain name (design docs/plans/2026-10-02-onchain-names-
  // design.md rev 4 §2 "Clients"): text that is NOT an address of this
  // network but is a chain name resolves to the address its owner published
  // in a signature-checked profile (src/adapters/nodus.js
  // resolveNameAddress, through the NODUS module). An address always wins;
  // a name that does not resolve is an error, never a fallback.
  const typed = typeof to === 'string' ? to.trim() : '';
  const name = implementations[chain].isRecipientAddress?.(typed) ? null : chainName(typed);
  if (name && typeof implementations.nodus?.resolveNameAddress !== 'function') throw new Error('Chain names are not available in this wallet version.');
  const named = name ? await implementations.nodus.resolveNameAddress({ client: wallet.nodusClient, chain, name }) : undefined;
  const recipient = named ? named.address : typed;
  const prepared = await implementations[chain].prepare({ wallet, chain, to: recipient, asset, units, endpoint });
  return reviewed(prepared, { endpoint, chain, symbol, to: recipient, named, amount, from: wallet.addresses[chain], nonce: prepared.nonce });
}
