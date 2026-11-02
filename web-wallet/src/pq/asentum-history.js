// Official explorer indexer: asentum-network/asentum-explorer indexer/src/api.js
// Indexer results are untrusted, potentially incomplete and not inclusion proofs.
import { bech32 } from '@scure/base';
import { formatUnits } from 'ethers';
import { request } from '../core.js';

function accountHex(account) {
  try {
    if (typeof account !== 'string' || account !== account.toLowerCase()) throw 0;
    const d = bech32.decode(account), bytes = bech32.fromWords(d.words);
    if (d.prefix !== 'ase' || bytes.length !== 20 || bech32.encode('ase', bech32.toWords(bytes)) !== account) throw 0;
    return '0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  } catch { throw new Error('Invalid Asentum address.'); }
}
export function parseAsentumHistory(data, account) {
  const self = accountHex(account), out = [], seen = new Map(), records = new Map();
  if (!data || !Array.isArray(data.rows) || !Number.isSafeInteger(data.total) || data.total < 0 || data.page !== 1 || data.size !== 50 || data.rows.length > 50) throw new Error('Invalid Asentum history response.');
  for (const t of data.rows) {
    const hash = t?.hash, from = typeof t?.from_addr === 'string' ? t.from_addr.toLowerCase() : null, to = typeof t?.to_addr === 'string' ? t.to_addr.toLowerCase() : null;
    if (typeof hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(hash)) {
      const key = hash.toLowerCase();
      // A self-transfer can occur twice with different index roles; role is not transaction data.
      const facts = JSON.stringify([from, to, t.value, t.timestamp, t.status, t.block_number, t.block_hash, t.has_input]);
      if (records.has(key) && records.get(key) !== facts) throw new Error('Conflicting Asentum history rows.');
      records.set(key, facts);
    }
    if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash) || !/^0x[0-9a-f]{40}$/.test(from || '') || !/^0x[0-9a-f]{40}$/.test(to || '') || (from !== self && to !== self) || typeof t.value !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(t.value) || BigInt(t.value) >= 2n ** 256n || t.value === '0' || !Number.isSafeInteger(t.timestamp) || t.timestamp < 0 || t.timestamp > 999999999999 || ![0, 1].includes(t.status)) continue;
    const key = hash.toLowerCase();
    const row = { chain: 'asentum', hash: key, time: t.timestamp * 1000, dir: from === self && to === self ? 'self' : from === self ? 'out' : 'in', symbol: 'ASE', amount: formatUnits(BigInt(t.value), 18), peer: from === self ? to : from, status: t.status === 1 ? 'confirmed' : 'failed' };
    const previous = seen.get(key);
    if (previous) {
      if (JSON.stringify(previous) !== JSON.stringify(row)) throw new Error('Conflicting Asentum history rows.');
      continue;
    }
    seen.set(key, row); out.push(row);
  }
  return out.sort((a,b) => b.time - a.time || a.hash.localeCompare(b.hash));
}
export async function readAsentumHistory(account, { networkId = 'testnet', signal, fetcher } = {}) {
  const hex = accountHex(account);
  if (networkId !== 'testnet') throw new Error('Unsupported Asentum network.');
  const options = { signal, fetcher };
  signal?.throwIfAborted();
  const chain = await request('https://testnet.asentum.com/chain', undefined, options);
  signal?.throwIfAborted();
  const genesis = await request('https://testnet.asentum.com/genesis', undefined, options);
  signal?.throwIfAborted();
  if (chain.chainId !== '1423' || genesis.chainId !== '1423' || genesis.genesisHash !== '0xc12243eee53d0a642c34845575687144802b79eabb07b213815ee907f0451aa3') throw new Error('Asentum provider is connected to the wrong network.');
  const data = await request(`https://explorer.asentum.com/api/indexer/address/${hex}/txs?page=1&size=50`, undefined, options);
  signal?.throwIfAborted();
  return parseAsentumHistory(data, account);
}
