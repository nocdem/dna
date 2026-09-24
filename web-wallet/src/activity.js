import { CHAINS } from './config.js';
import { rpc, request } from './core.js';
const TRON_GENESIS = '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc';
export const terminal = status => ['confirmed', 'failed', 'expired'].includes(status);
export function validHash(chain, hash) {
  return typeof hash === 'string' && (chain === 'solana' ? /^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(hash) : chain === 'tron' ? /^[0-9a-f]{64}$/i.test(hash) : /^0x[0-9a-f]{64}$/i.test(hash));
}
export function recordActivity(transfer, details) {
  if (!validHash(transfer.chain, details.hash)) throw new Error('Invalid transaction identifier.');
  return { chain: transfer.chain, address: transfer.from, to: transfer.to, symbol: transfer.symbol, amount: transfer.amount, endpoint: transfer.endpoint, hash: details.hash, lastValidBlockHeight: details.lastValidBlockHeight, expiration: details.expiration, createdAt: new Date().toISOString(), status: 'pending', note: 'Broadcast outcome pending.' };
}
export async function checkActivity(row, { signal, call = rpc, post = request } = {}) {
  const c = CHAINS[row.chain], endpoint = row.endpoint;
  const rpcCall = (method, params) => call(endpoint, method, params, { signal });
  const tron = (path, body) => post(`${endpoint}${path}`, body, { signal });
  if (!c || !validHash(row.chain, row.hash)) throw new Error('Invalid activity record.');
  if (row.chain === 'ethereum' || row.chain === 'bsc') {
    if (BigInt(await rpcCall('eth_chainId', [])) !== BigInt(c.chainId)) throw new Error('Wrong network.');
    const receipt = await rpcCall('eth_getTransactionReceipt', [row.hash]);
    if (receipt === null) return { status: 'pending', note: 'Not included, or previous inclusion was reorganized. Check explorer before resending.' };
    if (receipt.transactionHash?.toLowerCase() !== row.hash.toLowerCase() || !/^0x[0-9a-f]+$/i.test(receipt.blockNumber) || !/^0x[0-9a-f]{64}$/i.test(receipt.blockHash) || !['0x0', '0x1'].includes(receipt.status)) throw new Error('Invalid transaction receipt.');
    const block = await rpcCall('eth_getBlockByNumber', [receipt.blockNumber, false]);
    if (!block || block.hash?.toLowerCase() !== receipt.blockHash.toLowerCase()) return { status: 'pending', note: 'Inclusion changed; waiting for a canonical receipt.' };
    const finalized = await rpcCall('eth_getBlockByNumber', ['finalized', false]);
    if (!finalized?.number || BigInt(finalized.number) < BigInt(receipt.blockNumber)) return { status: 'included', note: receipt.status === '0x0' ? 'Execution failed; awaiting finality.' : 'Included; awaiting finality.' };
    return { status: receipt.status === '0x1' ? 'confirmed' : 'failed', note: 'Receipt is in a finalized canonical block.' };
  }
  if (row.chain === 'solana') {
    if (await rpcCall('getGenesisHash', []) !== '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp') throw new Error('Wrong network.');
    const result = await rpcCall('getSignatureStatuses', [[row.hash], { searchTransactionHistory: true }]);
    if (!Array.isArray(result?.value) || result.value.length !== 1) throw new Error('Invalid signature status.');
    const status = result.value[0];
    if (status) {
      if (!Object.hasOwn(status, 'err') || !['processed', 'confirmed', 'finalized'].includes(status.confirmationStatus)) throw new Error('Unrecognized signature status.');
      if (status.confirmationStatus === 'finalized') return { status: status.err === null ? 'confirmed' : 'failed', note: status.err === null ? 'Finalized on Solana.' : 'Execution failed on Solana (finalized).' };
      return { status: 'included', note: status.err === null ? 'Observed; awaiting finality.' : 'Execution error observed; awaiting finality.' };
    }
    if (Number.isSafeInteger(row.lastValidBlockHeight)) {
      const height = await rpcCall('getBlockHeight', [{ commitment: 'finalized' }]);
      if (!Number.isSafeInteger(height)) throw new Error('Invalid block height.');
      if (height > row.lastValidBlockHeight) return { status: 'expired', note: 'Not found in history after the finalized blockhash validity window. Verify explorer before resending.' };
    }
    return { status: 'pending', note: 'No finalized signature found yet.' };
  }
  if (endpoint !== CHAINS.tron.endpoint) throw new Error('TRON tracking requires the mainnet provider.');
  if ((await tron('/wallet/getblockbynum', { num: 0 })).blockID !== TRON_GENESIS) throw new Error('Wrong TRON network.');
  const tx = await tron('/walletsolidity/gettransactionbyid', { value: row.hash });
  if (tx.txID) {
    if (tx.txID.toLowerCase() !== row.hash.toLowerCase() || !Array.isArray(tx.ret) || tx.ret.length !== 1 || typeof tx.ret[0].contractRet !== 'string') throw new Error('Invalid solidified transaction.');
    return { status: tx.ret[0].contractRet === 'SUCCESS' ? 'confirmed' : 'failed', note: 'Execution result from a solidified TRON transaction.' };
  }
  if (Object.keys(tx).length) throw new Error('Unrecognized TRON transaction response.');
  return { status: 'pending', note: 'Not solidified. Check explorer before resending; no absence-based failure is assumed.' };
}
// A tracker never submits transactions. Stop aborts in-flight reads and future polling.
export function watchActivity(rows, onChange, { interval = 12000, check = checkActivity } = {}) {
  const controller = new AbortController(); let timer;
  async function tick() {
    for (const row of rows()) {
      if (controller.signal.aborted) return;
      if (terminal(row.status)) continue;
      try {
        const update = await check(row, { signal: controller.signal });
        if (controller.signal.aborted) return;
        Object.assign(row, update, { checkedAt: new Date().toISOString(), readError: null });
      } catch (error) { if (controller.signal.aborted) return; row.readError = `Status unavailable: ${error.message}`; }
      onChange();
    }
    if (!controller.signal.aborted) timer = setTimeout(tick, interval);
  }
  void tick(); return () => { controller.abort(); clearTimeout(timer); };
}
