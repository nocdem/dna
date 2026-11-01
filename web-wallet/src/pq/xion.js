// Native bank balance only; excludes staking, rewards and spendability.
import { bech32 } from '@scure/base';
import { request } from '../core.js';
const NETWORKS = Object.freeze({
  mainnet: { url: 'https://api.xion-mainnet-1.burnt.com', chain: 'xion-mainnet-1' },
  testnet: { url: 'https://api.xion-testnet-2.burnt.com', chain: 'xion-testnet-2' }
});
function validAddress(value) {
  try {
    if (typeof value !== 'string' || value !== value.toLowerCase()) throw new Error();
    const decoded = bech32.decode(value), bytes = bech32.fromWords(decoded.words);
    if (decoded.prefix !== 'xion' || bytes.length !== 20 || bech32.encode('xion', bech32.toWords(bytes)) !== value) throw new Error();
  } catch { throw new Error('Invalid XION address.'); }
}
async function get(url, options) {
  options.signal?.throwIfAborted();
  const data = await request(url, undefined, options);
  options.signal?.throwIfAborted();
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid XION response.');
  return data;
}
export async function readXionBalances(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  validAddress(account);
  if (!Object.hasOwn(NETWORKS, networkId)) throw new Error('Unsupported XION network.');
  const network = NETWORKS[networkId], options = { signal, fetcher };
  const info = await get(`${network.url}/cosmos/base/tendermint/v1beta1/node_info`, options);
  if (info.default_node_info?.network !== network.chain) throw new Error('XION provider is connected to the wrong network.');
  const data = await get(`${network.url}/cosmos/bank/v1beta1/balances/${encodeURIComponent(account)}/by_denom?denom=uxion`, options);
  const balance = data.balance;
  if (!balance || balance.denom !== 'uxion' || typeof balance.amount !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(balance.amount)) throw new Error('Invalid XION balance.');
  const n = BigInt(balance.amount);
  if (n >= 2n ** 256n) throw new Error('Invalid XION balance.');
  const fraction = String(n % 1000000n).padStart(6, '0').replace(/0+$/, '');
  return [{ symbol: 'XION', balance: String(n / 1000000n) + (fraction ? '.' + fraction : '') }];
}
