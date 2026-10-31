// Read-only native ALGO. Fixed providers: https://nodely.io/docs/free/endpoints/
// Identities: https://dev.algorand.co/concepts/protocol/networks/
// Schemas: https://dev.algorand.co/reference/rest-api/indexer/operations/lookupblock/
import { base32 } from '@scure/base';
import { sha512_256 } from '@noble/hashes/sha512';
import { request } from '../core.js';

const NETWORKS = Object.freeze({
  mainnet: Object.freeze({ networkId: 'mainnet', algod: 'https://mainnet-api.algonode.cloud', indexer: 'https://mainnet-idx.algonode.cloud', genesisHash: 'wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=' }),
  testnet: Object.freeze({ networkId: 'testnet', algod: 'https://testnet-api.algonode.cloud', indexer: 'https://testnet-idx.algonode.cloud', genesisHash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=' })
});
export function algorandNetwork(networkId = 'mainnet') {
  if (!Object.hasOwn(NETWORKS, networkId)) throw new Error('Unsupported Algorand network.');
  return NETWORKS[networkId];
}
function address(value) {
  if (typeof value !== 'string' || !/^[A-Z2-7]{58}$/.test(value)) throw new Error('Invalid Algorand address.');
  const bytes = base32.decode(value + '======');
  const checksum = sha512_256(bytes.slice(0, 32)).slice(-4);
  if (bytes.length !== 36 || !checksum.every((byte, i) => byte === bytes[32 + i])) throw new Error('Invalid Algorand address checksum.');
  return value;
}
function uint(value) {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw new Error('Unsafe Algorand integer.');
  if (!['number', 'string'].includes(typeof value) || !/^(0|[1-9]\d{0,19})$/.test(String(value))) throw new Error('Invalid Algorand integer.');
  const n = BigInt(value);
  if (n > 18446744073709551615n) throw new Error('Algorand integer exceeds uint64.');
  return n;
}
function decimal(n) { return `${n / 1000000n}.${String(n % 1000000n).padStart(6, '0')}`.replace(/\.?0+$/, ''); }
function cancelled(signal) { signal?.throwIfAborted(); }
async function get(url, options) {
  cancelled(options.signal);
  const data = await request(url, undefined, options);
  cancelled(options.signal);
  if (Array.isArray(data) || data.message) throw new Error('Invalid Algorand response.');
  return data;
}
function identity(data, network) {
  if (data['genesis-hash'] !== network.genesisHash) throw new Error('Algorand provider is connected to the wrong network.');
}
export async function readAlgorandBalances(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  address(account);
  const network = algorandNetwork(networkId), options = { signal, fetcher };
  identity(await get(`${network.algod}/v2/transactions/params`, options), network);
  const data = await get(`${network.algod}/v2/accounts/${account}?exclude=all`, options);
  if (data.address !== account) throw new Error('Algorand returned a different account.');
  return [{ symbol: 'ALGO', balance: decimal(uint(data.amount)) }];
}
// At most 50 top-level payments; no inner transfers, fees, rewards or ASA history.
// Aggregate payment and closing legs per transaction, excluding fees and self legs.
// Multiple external recipients deliberately have no single peer.
export async function readAlgorandHistory(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  address(account);
  const network = algorandNetwork(networkId), options = { signal, fetcher };
  const block = await get(`${network.indexer}/v2/blocks/0?header-only=true`, options);
  identity(block, network);
  if (uint(block.round) !== 0n) throw new Error('Invalid Algorand identity block.');
  const data = await get(`${network.indexer}/v2/accounts/${account}/transactions?tx-type=pay&limit=50`, options);
  const currentRound = uint(data['current-round']);
  if (!Array.isArray(data.transactions) || data.transactions.length > 50) throw new Error('Invalid Algorand history.');
  const rows = [], seen = new Map();
  for (const tx of data.transactions) {
    if (!tx || tx['tx-type'] !== 'pay' || typeof tx.id !== 'string' || !/^[A-Z2-7]{52}$/.test(tx.id)) throw new Error('Invalid Algorand payment.');
    const fingerprint = JSON.stringify(tx);
    if (seen.has(tx.id)) { if (seen.get(tx.id) !== fingerprint) throw new Error('Conflicting Algorand transactions.'); continue; }
    seen.set(tx.id, fingerprint);
    const sender = address(tx.sender), payment = tx['payment-transaction'];
    if (!payment || uint(tx['confirmed-round']) === 0n || uint(tx['confirmed-round']) > currentRound) throw new Error('Invalid Algorand confirmation.');
    const receiver = address(payment.receiver), amount = uint(payment.amount);
    const seconds = uint(tx['round-time']);
    if (seconds === 0n || seconds > BigInt(Math.floor(Number.MAX_SAFE_INTEGER / 1000))) throw new Error('Invalid Algorand time.');
    const close = payment['close-remainder-to'] === undefined ? null : address(payment['close-remainder-to']);
    const closeAmount = close ? uint(payment['close-amount']) : (payment['close-amount'] === undefined ? 0n : uint(payment['close-amount']));
    if (!close && closeAmount !== 0n) throw new Error('Invalid Algorand close payment.');
    if (sender !== account && receiver !== account && close !== account) throw new Error('Unrelated Algorand payment.');
    const legs = [[receiver, amount], ...(close ? [[close, closeAmount]] : [])];
    const outgoing = sender === account;
    const relevant = legs.filter(([to]) => outgoing ? to !== account : to === account);
    const total = relevant.reduce((sum, [, units]) => sum + units, 0n);
    uint(String(total));
    const peers = new Set(relevant.map(([to]) => outgoing ? to : sender));
    const dir = outgoing ? (relevant.length ? 'out' : 'self') : 'in';
    rows.push({ chain: 'algorand', hash: tx.id, time: Number(seconds) * 1000,
      dir, symbol: 'ALGO', amount: decimal(total), peer: peers.size === 1 ? [...peers][0] : '', status: 'confirmed' });
  }
  cancelled(signal);
  return rows.sort((a, b) => b.time - a.time || a.hash.localeCompare(b.hash));
}
