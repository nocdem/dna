// Read-only total live-cell capacity, not available/spendable capacity.
// Source and trust/synchronization limits: evidence/ckb-source-notes.md (repository root).
import { bech32m } from '@scure/base';
import { rpc } from '../core.js';
const NETWORKS = Object.freeze({
  mainnet: Object.freeze({ networkId: 'mainnet', prefix: 'ckb', rpc: 'https://mainnet.ckb.dev/rpc', genesisHash: '0x92b197aa1fba0f63633922c61c92375c9c074a93e85963554f5499fe1450d0e5', codeHash: '0x302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf', hashType: 'type', hashTypeByte: 1 }),
  testnet: Object.freeze({ networkId: 'testnet', prefix: 'ckt', rpc: 'https://testnet.ckb.dev', genesisHash: '0x10639e0895502b5688a6be8cf69460d76541bfa4821629d86d62ba0aae3f9606', codeHash: '0x147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf', hashType: 'data1', hashTypeByte: 2 })
});
export function ckbNetwork(networkId = 'mainnet') {
  if (!Object.hasOwn(NETWORKS, networkId)) throw new Error('Unsupported CKB network.');
  return NETWORKS[networkId];
}
const hex = bytes => '0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
function lock(address, network) {
  if (typeof address !== 'string' || address !== address.toLowerCase() || address.length > 1023) throw new Error('Invalid CKB address.');
  let decoded, payload;
  try { decoded = bech32m.decode(address, 1023); payload = bech32m.fromWords(decoded.words); }
  catch { throw new Error('Invalid CKB Bech32m address.'); }
  if (decoded.prefix !== network.prefix) throw new Error('CKB address belongs to a different network.');
  if (payload.length !== 66 || payload[0] !== 0 || hex(payload.slice(1, 33)) !== network.codeHash || payload[33] !== network.hashTypeByte) throw new Error('Unsupported CKB lock profile.');
  return { code_hash: network.codeHash, hash_type: network.hashType, args: hex(payload.slice(34)) };
}
function uint(value) {
  if (typeof value !== 'string' || !/^0x(0|[1-9a-f][0-9a-f]{0,15})$/.test(value)) throw new Error('Invalid CKB uint64.');
  return BigInt(value);
}
function hash(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value)) throw new Error('Invalid CKB block hash.');
  return value;
}
function decimal(n) {
  const fraction = String(n % 100000000n).padStart(8, '0').replace(/0+$/, '');
  return String(n / 100000000n) + (fraction ? '.' + fraction : '');
}
export async function readCkbBalances(address, { networkId = 'mainnet', signal, fetcher } = {}) {
  const network = ckbNetwork(networkId), script = lock(address, network), options = { signal, fetcher };
  const call = async (method, params) => {
    signal?.throwIfAborted();
    const result = await rpc(network.rpc, method, params, options);
    signal?.throwIfAborted();
    return result;
  };
  if (await call('get_block_hash', ['0x0']) !== network.genesisHash) throw new Error('CKB provider is connected to the wrong network.');
  const result = await call('get_cells_capacity', [{ script, script_type: 'lock', script_search_mode: 'exact' }]);
  if (!result || Array.isArray(result)) throw new Error('CKB indexer capacity unavailable.');
  const capacity = uint(result.capacity), indexed = uint(result.block_number), indexedHash = hash(result.block_hash);
  // Confirm this indexed snapshot belongs to the checked node chain, and reject a
  // materially lagging indexer. This is a bounded policy, not inclusion proof.
  if (hash(await call('get_block_hash', [result.block_number])) !== indexedHash) throw new Error('CKB indexer snapshot does not match the node chain.');
  const tip = uint(await call('get_tip_block_number', []));
  if (indexed > tip || tip - indexed > 24n) throw new Error('CKB indexer is not synchronized.');
  return [{ symbol: 'CKB', balance: decimal(capacity) }];
}
