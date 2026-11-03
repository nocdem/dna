import {prepareAsentumReview} from './pq/asentum-transfer.js';
import * as evm from './adapters/evm.js';
import * as solana from './adapters/solana.js';
import * as tron from './adapters/tron.js';
import * as nodus from './adapters/nodus.js';
import { CHAINS, assetFor } from './config.js';
import { amountUnits, endpointUrl } from './core.js';
import { NODUS_ASSET } from './nodus/network.js';
import { chainName } from './nodus/names.js';
import { prepareSoquTransfer } from './pq/soqu-transfer.js';
import { prepareAlgorandTransfer } from './pq/algorand-transfer.js';
import { prepareSplendorReview } from './pq/splendor-transfer.js';
import { prepareSplendorTransfer } from './pq/splendor-prepare.js';
import { prepareCkbTransfer } from './pq/ckb-transfer.js';
import { formatUnits } from './core.js';
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
// `asset`: the send form's asset identity { chain, tokenId } (design 2026-10-22-
// connect-native-tokens-design.md §6 item 1). For NODUS it is REQUIRED and its
// chain must be the chain being sent on: no hop defaults to native, so a
// missing or malformed tokenId refuses here, before any module call. The
// other networks still take their asset by `symbol`.
export async function prepareTransfer({ wallet, chain, symbol, asset: identity, to, amount, endpoint, nodusLocked, networkId = 'mainnet', maxFeePerGas, ckbUnresolved, signal }, implementations = adapters) {
  if (chain === 'asentum') {
    if(symbol!=='ASE'||networkId!=='testnet')throw new Error('Choose Asentum testnet ASE.');
    const units=amountUnits(amount,18),recipient=typeof to==='string'?to.trim():to;
    const transfer=await prepareAsentumReview({wallet,to:recipient,amount:String(units),maxFeePerGas,networkId,signal});
    return {...transfer,chain,symbol,amount:formatUnits(units,18),amountAtoms:String(units),endpoint:'https://testnet.asentum.com',fee:`Up to ${formatUnits(BigInt(transfer.maximumFee),18)} ASE`,review:[['Network','Asentum testnet'],['From',transfer.from],['To',transfer.to],['Asset','ASE'],['Amount',formatUnits(units,18)],['Maximum network fee',`${formatUnits(BigInt(transfer.maximumFee),18)} ASE`],['Fee policy','Explicit user maximum; finalized base fee may change'],['Authorization','Native ML-DSA-65']]};
  }
  if (chain === 'splendor') {
    if (symbol !== 'SPLD' || !['mainnet','testnet'].includes(networkId)) throw new Error('Choose a supported Splendor network and SPLD.');
    const units=amountUnits(amount,18),from=wallet?.addresses?.splendor,recipient=typeof to==='string'?to.trim():to;
    // The node's current mempool minimum is a snapshot, not a guarantee. The
    // exact quoted fee is shown for approval and rechecked on confirm.
    const quote=await prepareSplendorTransfer({networkId,from,to:recipient,amount:String(units),fee:'0',timestamp:String(Math.floor(Date.now()/1000)),signal});
    const transfer=await prepareSplendorReview({wallet,to:recipient,amount:String(units),fee:quote.minimumFee,networkId,signal});
    const url=networkId==='mainnet'?'https://quantum-rpc.splendor.org':'https://quantum-rpc-testnet.splendor.org';
    return {...transfer,chain,symbol,amount:formatUnits(units,18),amountAtoms:String(units),feeAtoms:transfer.fee,endpoint:url,
      fee:`${formatUnits(BigInt(transfer.fee),18)} SPLD`,review:[['Network',`Splendor ${networkId}`],['From',transfer.from],['To',transfer.to],['Asset','SPLD'],['Amount',formatUnits(units,18)],['Network fee',`${formatUnits(BigInt(transfer.fee),18)} SPLD`],['Fee policy','Node-reported current minimum; may change before admission'],['Authorization','Native ML-DSA-65']]};
  }
  if (chain === 'soqucoin') {
    if (symbol !== 'SOQ' || networkId !== 'mainnet') throw new Error('Choose verified Soqucoin mainnet SOQ.');
    const units = amountUnits(amount, 8);
    const transfer = await prepareSoquTransfer({ wallet, to: typeof to === 'string' ? to.trim() : to,
      amountAtoms: String(units), networkId, signal });
    return { ...transfer, chain, symbol, amount: formatUnits(units, 8), endpoint: 'https://mainnet-rpc.soqu.org',
      fee: `${formatUnits(BigInt(transfer.feeAtoms), 8)} SOQ`,
      review: [['Network', 'Soqucoin mainnet'], ['From', transfer.from], ['To', transfer.to], ['Asset', 'SOQ'],
        ['Amount', formatUnits(units, 8)], ['Network fee', `${formatUnits(BigInt(transfer.feeAtoms), 8)} SOQ`],
        ['Fee policy', `${transfer.feeRate} shors/vByte; native transparent inputs only`],
        ['Authorization', 'ML-DSA-44; node-verified mature UTXOs']] };
  }
  if (chain === 'algorand') {
    if (symbol !== 'ALGO' || networkId !== 'mainnet') throw new Error('Choose verified Algorand mainnet ALGO.');
    const units = amountUnits(amount, 6);
    const transfer = await prepareAlgorandTransfer({ wallet, to: typeof to === 'string' ? to.trim() : to,
      amountAtoms: String(units), maxFeeAtoms: '10000', networkId, signal });
    return { ...transfer, chain, symbol, amount: formatUnits(units, 6), endpoint: 'https://mainnet-api.algonode.cloud',
      fee: `${formatUnits(BigInt(transfer.feeAtoms), 6)} ALGO`,
      review: [['Network', 'Algorand mainnet'], ['From', transfer.from], ['To', transfer.to], ['Asset', 'ALGO'],
        ['Amount', formatUnits(units, 6)], ['Network fee', `${formatUnits(BigInt(transfer.feeAtoms), 6)} ALGO`],
        ['Authorization', 'Native Falcon-1024; direct account only']] };
  }
  if (chain === 'ckb') {
    if (!wallet?.addresses?.ckb) throw new Error('Open a wallet first.');
    if (symbol !== 'CKB' || networkId !== 'mainnet') throw new Error('Choose CKB mainnet.');
    // Same controller, limits and order as the extension (src/pq/ckb-transfer.js).
    return prepareCkbTransfer({ wallet, to: typeof to === 'string' ? to.trim() : to, amountAtoms: amountUnits(amount, 8), networkId, unresolved: ckbUnresolved, signal });
  }
  if (!wallet || !implementations[chain]) throw new Error('Open a wallet first.');
  if (chain === NODUS_ASSET.chain) {
    if (!identity || identity.chain !== NODUS_ASSET.chain || typeof identity.tokenId !== 'string' || !/^[0-9a-f]{128}$/.test(identity.tokenId)) throw new Error('Choose the asset to send.');
    // Recipient, amount, fee and expiry are decoded from the signed envelope by
    // the module, never taken from the form (design G1); `review` lists them.
    const prepared = await implementations.nodus.prepare({ client: wallet.nodusClient, from: wallet.addresses.nodus, to, amount, tokenId: identity.tokenId, locked: nodusLocked });
    // The prepared transfer must be for the asset that was asked for.
    if (prepared.tokenId !== identity.tokenId) throw new Error('The prepared transfer is not for the asset you chose. Nothing was sent.');
    return reviewed(prepared, { endpoint: undefined, chain, symbol: prepared.symbol, tokenId: prepared.tokenId, to: prepared.to, recipientName: prepared.recipientName, amount: prepared.amount, from: wallet.addresses.nodus, review: prepared.review });
  }
  const asset = assetFor(chain, symbol), units = amountUnits(amount, asset.decimals);
  endpoint = endpointUrl(endpoint || CHAINS[chain].endpoint);
  // HF-4 send to a chain name (design docs/plans/2026-10-02-onchain-names-
  // design.md rev 4 §2 "Clients"): text that is NOT an address of this
  // network but is a chain name resolves to the address its owner published
  // in a signature-checked profile (src/adapters/nodus.js
  // resolveNameAddress, through the NODUS module). An address always wins;
  // a name that does not resolve is an error, never a fallback.
  // ADDRESS-SHAPED text (the adapter's looksLikeAddress: TRON 34 chars
  // starting T/t or 41+40 hex; EVM 0x/0X…) is never a name: if it is not a
  // valid address it is refused here, before any lookup.
  const typed = typeof to === 'string' ? to.trim() : '';
  const impl = implementations[chain];
  const shaped = impl.looksLikeAddress?.(typed) === true;
  if (shaped && typeof impl.isRecipientAddress === 'function' && !impl.isRecipientAddress(typed)) throw new Error(`Invalid ${CHAINS[chain].name} address.`);
  const name = shaped || impl.isRecipientAddress?.(typed) ? null : chainName(typed);
  if (name && typeof implementations.nodus?.resolveNameAddress !== 'function') throw new Error('Chain names are not available in this wallet version.');
  const named = name ? await implementations.nodus.resolveNameAddress({ client: wallet.nodusClient, chain, name }) : undefined;
  const recipient = named ? named.address : typed;
  const prepared = await implementations[chain].prepare({ wallet, chain, to: recipient, asset, units, endpoint });
  return reviewed(prepared, { endpoint, chain, symbol, to: recipient, named, amount, from: wallet.addresses[chain], nonce: prepared.nonce });
}
