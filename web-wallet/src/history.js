// Account history per network — incoming and outgoing transfers of this
// wallet's addresses, read from the same sources the DNA Connect app uses
// (messenger/src/api/engine/dna_engine_wallet.c dna_handle_get_transactions):
//   ethereum  Blockscout txlist + tokentx (messenger/blockchain/ethereum/eth_rpc.c:363-395, :650-660)
//   tron      TronGrid /v1/accounts/<a>/transactions (+ /trc20) (messenger/blockchain/tron/trx_rpc.c:351)
//   solana    getSignaturesForAddress + getTransaction, known signatures skipped (dna_engine_wallet.c:942-963)
//   cellframe tx_history (messenger/blockchain/cellframe/cellframe_rpc.c:371-387), CPUNK rows only
//   bsc       none — the app has it switched off too (dna_engine_wallet.c:887: no working explorer API)
//
// Everything a provider returns is UNTRUSTED DATA: every field is checked
// here, amounts are integers formatted with the decimals of the wallet's own
// asset list (never a symbol or decimals the provider names), and a row that
// does not check out is dropped. The page shows rows with textContent only.
//
// Requests are few because public providers limit them (operator
// 2026-10-02): ethereum 2, tron 2, cellframe 1, solana 1 + one getTransaction
// per signature not seen before (paced by rpc-transport.js). A refused
// request (HTTP 429 included) is reported, never retried here.
import { getAddress, formatUnits } from 'ethers';
import { TronWeb } from 'tronweb';
import { CHAINS } from './config.js';
import { request, rpc, endpointUrl } from './core.js';
import { CPUNK_ENDPOINT, validateCellframeAddress, boundedJson } from './cpunk-protocol.js';

export const HISTORY_LIMIT = 50;           // rows per network kept and shown (the app's offset/limit 50)
export const SOLANA_SIGNATURES = 20;       // newest signatures looked at per read
export const HISTORY_SOURCES = { ethereum: 'Blockscout', tron: 'TronGrid', solana: 'Solana RPC', cellframe: 'Cellframe RPC' };
const BLOCKSCOUT = 'https://eth.blockscout.com/api';
const DIGITS = /^(0|[1-9]\d{0,77})$/;

export class HistoryUnavailable extends Error {}

// One row: { chain, hash, time (ms), dir 'in' | 'out' | 'self', symbol,
// amount (decimal string), peer ('' when unknown), status 'confirmed' | 'failed' }.
function row(chain, hash, time, dir, symbol, units, decimals, peer, failed) {
  return { chain, hash, time, dir, symbol, amount: formatUnits(units, decimals), peer: peer || '', status: failed ? 'failed' : 'confirmed' };
}
const direction = (from, to, self) => from === self && to === self ? 'self' : from === self ? 'out' : 'in';
const seconds = value => (typeof value === 'string' && /^\d{1,12}$/.test(value)) || (Number.isSafeInteger(value) && value >= 0) ? Number(value) * 1000 : null;
const millis = value => Number.isSafeInteger(value) && value > 0 && value < 1e14 ? value : null;
const sortRows = rows => rows.sort((a, b) => b.time - a.time || (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0)).slice(0, HISTORY_LIMIT);

function plainError(error) {
  const message = String(error?.message || '');
  if (/HTTP 429/.test(message)) return new HistoryUnavailable('The history provider is limiting requests right now. Try again in a few minutes.');
  if (/cancelled/.test(message)) return new HistoryUnavailable('History read cancelled.');
  return new HistoryUnavailable('History could not be read right now. Try again later.');
}

// ── Ethereum: Blockscout (2 requests) ───────────────────────────────────
export function parseBlockscout(native, tokens, address) {
  const self = getAddress(address).toLowerCase(), out = [];
  const listed = new Map(CHAINS.ethereum.tokens.map(t => [t.address.toLowerCase(), t]));
  const list = data => Array.isArray(data?.result) ? data.result.slice(0, 200) : [];
  for (const tx of list(native)) {
    const hash = tx?.hash, time = seconds(tx?.timeStamp), from = String(tx?.from || '').toLowerCase(), to = String(tx?.to || '').toLowerCase();
    if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash) || time === null || !/^0x[0-9a-f]{40}$/.test(from) || !(to === '' || /^0x[0-9a-f]{40}$/.test(to)) ||
        typeof tx.value !== 'string' || !DIGITS.test(tx.value) || (from !== self && to !== self)) continue;
    if (tx.value === '0') continue;             // a contract call (a token send is listed by tokentx)
    out.push(row('ethereum', hash.toLowerCase(), time, direction(from, to, self), 'ETH', BigInt(tx.value), 18, from === self ? to : from, tx.isError === '1' || tx.txreceipt_status === '0'));
  }
  for (const tx of list(tokens)) {
    const token = listed.get(String(tx?.contractAddress || '').toLowerCase());
    const hash = tx?.hash, time = seconds(tx?.timeStamp), from = String(tx?.from || '').toLowerCase(), to = String(tx?.to || '').toLowerCase();
    if (!token || typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash) || time === null || !/^0x[0-9a-f]{40}$/.test(from) || !/^0x[0-9a-f]{40}$/.test(to) ||
        typeof tx.value !== 'string' || !DIGITS.test(tx.value) || (from !== self && to !== self)) continue;
    out.push(row('ethereum', hash.toLowerCase(), time, direction(from, to, self), token.symbol, BigInt(tx.value), token.decimals, from === self ? to : from, false));
  }
  return sortRows(out);
}
async function ethereumHistory(address, options) {
  const a = getAddress(address).toLowerCase();
  const url = (action, contract = '') => `${BLOCKSCOUT}?module=account&action=${action}&address=${a}${contract ? `&contractaddress=${contract}` : ''}&startblock=0&endblock=99999999&page=1&offset=${HISTORY_LIMIT}&sort=desc`;
  // One after the other, not in parallel: one request in flight per provider.
  // Tokens are asked per listed contract, as the app does (eth_rpc.c:650-660):
  // an unfiltered tokentx of a busy address carries every spam token and
  // passed the 256 KiB response bound (measured 2026-10-02).
  const native = await blockscout(url('txlist'), options);
  const tokens = { result: [] };
  for (const token of CHAINS.ethereum.tokens) tokens.result.push(...((await blockscout(url('tokentx', token.address), options)).result || []));
  return parseBlockscout(native, tokens, address);
}
// Blockscout answers "no transactions" with status "0"; core.js request()
// would not refuse that, but the shape is checked here.
async function blockscout(url, options) {
  const data = await request(url, undefined, options);
  if (!data || (data.status !== '1' && data.status !== '0') || !(Array.isArray(data.result) || data.result === null)) throw new Error('Unexpected history response.');
  return data;
}

// ── TRON: TronGrid (2 requests) ─────────────────────────────────────────
const tronAddress = value => {
  if (typeof value !== 'string') return null;
  try {
    const text = /^41[0-9a-fA-F]{40}$/.test(value) ? TronWeb.address.fromHex(value) : value;
    return TronWeb.isAddress(text) ? text : null;
  } catch { return null; }
};
export function parseTronGrid(native, tokens, address) {
  const out = [];
  const listed = new Map(CHAINS.tron.tokens.map(t => [t.address, t]));
  const list = data => Array.isArray(data?.data) ? data.data.slice(0, 200) : [];
  for (const tx of list(native)) {
    const contract = Array.isArray(tx?.raw_data?.contract) && tx.raw_data.contract.length === 1 ? tx.raw_data.contract[0] : null;
    if (!contract || contract.type !== 'TransferContract') continue;
    const v = contract.parameter?.value, from = tronAddress(v?.owner_address), to = tronAddress(v?.to_address), time = millis(tx.block_timestamp);
    if (typeof tx.txID !== 'string' || !/^[0-9a-f]{64}$/.test(tx.txID) || !from || !to || time === null || !Number.isSafeInteger(v.amount) || v.amount <= 0 || (from !== address && to !== address)) continue;
    const ret = tx.ret?.[0]?.contractRet;
    out.push(row('tron', tx.txID, time, direction(from, to, address), 'TRX', BigInt(v.amount), 6, from === address ? to : from, ret !== undefined && ret !== 'SUCCESS'));
  }
  for (const tx of list(tokens)) {
    const token = listed.get(tx?.token_info?.address), from = tronAddress(tx?.from), to = tronAddress(tx?.to), time = millis(tx?.block_timestamp);
    if (!token || typeof tx.transaction_id !== 'string' || !/^[0-9a-f]{64}$/.test(tx.transaction_id) || !from || !to || time === null ||
        typeof tx.value !== 'string' || !DIGITS.test(tx.value) || (from !== address && to !== address)) continue;
    out.push(row('tron', tx.transaction_id, time, direction(from, to, address), token.symbol, BigInt(tx.value), token.decimals, from === address ? to : from, false));
  }
  return sortRows(out);
}
async function tronHistory(address, endpoint, options) {
  if (!TronWeb.isAddress(address)) throw new Error('Invalid TRON address.');
  const base = `${endpoint.replace(/\/$/, '')}/v1/accounts/${address}/transactions`;
  const native = await request(`${base}?only_confirmed=true&limit=${HISTORY_LIMIT}`, undefined, options);
  const tokens = await request(`${base}/trc20?only_confirmed=true&limit=${HISTORY_LIMIT}`, undefined, options);
  if (!Array.isArray(native?.data) || !Array.isArray(tokens?.data)) throw new Error('Unexpected history response.');
  return parseTronGrid(native, tokens, address);
}

// ── Solana: signatures + one getTransaction per NEW signature ───────────
export function parseSolanaTransaction(signature, tx, address) {
  const keys = tx?.transaction?.message?.accountKeys, meta = tx?.meta, time = seconds(tx?.blockTime);
  if (!Array.isArray(keys) || !meta || time === null) return [];
  const pubkeys = keys.map(k => typeof k === 'string' ? k : k?.pubkey);
  const failed = meta.err !== null && meta.err !== undefined, out = [];
  const index = pubkeys.indexOf(address);
  if (index >= 0 && Array.isArray(meta.preBalances) && Array.isArray(meta.postBalances)) {
    const pre = meta.preBalances[index], post = meta.postBalances[index], fee = index === 0 && Number.isSafeInteger(meta.fee) ? meta.fee : 0;
    if (Number.isSafeInteger(pre) && Number.isSafeInteger(post)) {
      const delta = BigInt(post) - BigInt(pre) + BigInt(fee);   // the fee is not part of the transfer
      if (delta !== 0n) {
        // The other side of a plain system transfer, when there is one.
        const transfer = (tx.transaction.message.instructions || []).find(i => i?.program === 'system' && i?.parsed?.type === 'transfer' &&
          (i.parsed.info?.source === address || i.parsed.info?.destination === address));
        const peer = transfer ? (transfer.parsed.info.source === address ? transfer.parsed.info.destination : transfer.parsed.info.source) : '';
        out.push(row('solana', signature, time, delta > 0n ? 'in' : 'out', 'SOL', delta > 0n ? delta : -delta, 9, typeof peer === 'string' ? peer : '', failed));
      }
    }
  }
  // Listed tokens: the change of this owner's token balance per mint.
  for (const token of CHAINS.solana.tokens) {
    const amount = list => {
      let total = 0n;
      for (const b of Array.isArray(list) ? list : []) {
        if (b?.owner !== address || b?.mint !== token.address) continue;
        const raw = b?.uiTokenAmount?.amount;
        if (typeof raw !== 'string' || !DIGITS.test(raw) || b.uiTokenAmount.decimals !== token.decimals) return null;
        total += BigInt(raw);
      }
      return total;
    };
    const pre = amount(meta.preTokenBalances), post = amount(meta.postTokenBalances);
    if (pre === null || post === null || pre === post) continue;
    out.push(row('solana', signature, time, post > pre ? 'in' : 'out', token.symbol, post > pre ? post - pre : pre - post, token.decimals, '', failed));
  }
  return out;
}
// `known`: signature -> rows already read (from the cache); only the others
// are fetched.
async function solanaHistory(address, endpoint, options, known) {
  const signatures = await rpc(endpoint, 'getSignaturesForAddress', [address, { limit: SOLANA_SIGNATURES, commitment: 'finalized' }], options);
  if (!Array.isArray(signatures)) throw new Error('Unexpected history response.');
  const out = [];
  for (const s of signatures.slice(0, SOLANA_SIGNATURES)) {
    const signature = s?.signature;
    if (typeof signature !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(signature)) continue;
    if (known.has(signature)) { out.push(...known.get(signature)); continue; }
    const tx = await rpc(endpoint, 'getTransaction', [signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'finalized' }], options);
    out.push(...parseSolanaTransaction(signature, tx, address));
  }
  return sortRows(out);
}

// ── Cellframe: tx_history (1 request), CPUNK rows only ──────────────────
export function parseCellframeHistory(data, address) {
  const list = Array.isArray(data?.result?.[0]) ? data.result[0].slice(2, 2 + 1000) : [];
  const out = [];
  for (const tx of list) {
    const item = Array.isArray(tx?.data) ? tx.data[0] : null;
    const hash = tx?.hash, time = Date.parse(tx?.tx_created);
    if (!item || typeof hash !== 'string' || !/^0x[0-9A-Fa-f]{64}$/.test(hash) || !Number.isFinite(time) || item.token !== 'CPUNK') continue;
    const recv = item.tx_type === 'recv', send = item.tx_type === 'send';
    const datoshi = recv ? item.recv_datoshi : send ? item.send_datoshi : undefined;
    const peer = recv ? item.source_address : item.destination_address;
    if (!(recv || send) || typeof datoshi !== 'string' || !DIGITS.test(datoshi) || datoshi === '0') continue;
    let other = '';
    try { other = typeof peer === 'string' ? validateCellframeAddress(peer) : ''; } catch { other = ''; }
    out.push(row('cellframe', hash.toLowerCase(), time, recv ? 'in' : 'out', 'CPUNK', BigInt(datoshi), 18, other, tx.status !== 'ACCEPTED'));
  }
  return sortRows(out);
}
async function cellframeHistory(address, endpoint, options) {
  validateCellframeAddress(address);
  const body = { method: 'tx_history', params: [`tx_history;-net;Backbone;-addr;${address}`], id: '1', version: '2' };
  const combined = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000);
  // text/plain: a CORS simple request (the RPC refuses the preflight;
  // src/adapters/cpunk.js). The answer can list up to 1000 rows, so it is
  // read with its own 1 MiB bound (boundedJson) like the balance read.
  const response = await fetch(endpointUrl(endpoint || CPUNK_ENDPOINT), { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: JSON.stringify(body), signal: combined, credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store' });
  return parseCellframeHistory(await boundedJson(response, 1024 * 1024), address);
}

// Reads one network's history. `known` (solana only): signature -> rows.
export async function readHistory(chain, address, { endpoint, signal, known = new Map() } = {}) {
  const options = { signal };
  try {
    if (chain === 'ethereum') return await ethereumHistory(address, options);
    if (chain === 'tron') return await tronHistory(address, endpoint || CHAINS.tron.endpoint, options);
    if (chain === 'solana') return await solanaHistory(address, endpoint || CHAINS.solana.endpoint, options, known);
    if (chain === 'cellframe') return await cellframeHistory(address, endpoint, options);
  } catch (error) { throw plainError(error); }
  throw new HistoryUnavailable('History is not available for this network here. Use the account explorer.');
}
export const historySupported = chain => Object.hasOwn(HISTORY_SOURCES, chain);

// Rows kept from an earlier read (saved encrypted, src/activity-storage.js)
// are checked again before they are shown; anything else throws.
const HASHES = { ethereum: /^0x[0-9a-f]{64}$/, tron: /^[0-9a-f]{64}$/, solana: /^[1-9A-HJ-NP-Za-km-z]{64,88}$/, cellframe: /^0x[0-9a-f]{64}$/ };
const symbolsOf = chain => chain === 'cellframe' ? ['CPUNK'] : [CHAINS[chain].symbol, ...CHAINS[chain].tokens.map(t => t.symbol)];
export function checkHistoryRows(chain, rows) {
  if (!historySupported(chain) || !Array.isArray(rows) || rows.length > HISTORY_LIMIT) throw new Error('Invalid saved history.');
  return rows.map(r => {
    if (!r || r.chain !== chain || typeof r.hash !== 'string' || !HASHES[chain].test(r.hash) || !Number.isSafeInteger(r.time) || r.time <= 0 ||
        !['in', 'out', 'self'].includes(r.dir) || !symbolsOf(chain).includes(r.symbol) || typeof r.amount !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(r.amount) ||
        typeof r.peer !== 'string' || !/^[0-9A-Za-z]{0,128}$/.test(r.peer) || !['confirmed', 'failed'].includes(r.status)) throw new Error('Invalid saved history.');
    return { chain, hash: r.hash, time: r.time, dir: r.dir, symbol: r.symbol, amount: r.amount, peer: r.peer, status: r.status };
  });
}

// Rows of a fresh read merged into the kept ones (the app merges its cache
// with fresh results, dna_engine_wallet.c:1282-1300): one row per
// (hash, symbol, direction), the fresh one wins, newest HISTORY_LIMIT kept.
export function mergeHistory(kept = [], fresh = []) {
  const byKey = new Map();
  for (const r of [...kept, ...fresh]) byKey.set(`${r.hash}|${r.symbol}|${r.dir}`, r);
  return sortRows([...byKey.values()]);
}
