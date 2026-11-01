// Committed native account balance; provider state is not an inclusion proof.
import { request } from '../core.js';
const NETWORKS = Object.freeze({
  mainnet: { url: 'https://quantum-rpc.splendor.org', chain: 'splendor-quantum-1' },
  testnet: { url: 'https://quantum-rpc-testnet.splendor.org', chain: 'splendor-quantum-testnet-1' }
});
async function get(url, options) {
  options.signal?.throwIfAborted();
  const data = await request(url, undefined, options);
  options.signal?.throwIfAborted();
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid Splendor response.');
  return data;
}
export async function readSplendorBalances(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  if (typeof account !== 'string' || !/^SQ:[0-9a-f]{64}$/.test(account)) throw new Error('Invalid Splendor address.');
  if (!Object.hasOwn(NETWORKS, networkId)) throw new Error('Unsupported Splendor network.');
  const network = NETWORKS[networkId], options = { signal, fetcher };
  const status = await get(`${network.url}/status`, options);
  if (status.chain_id !== network.chain || status.decimals !== 18 || status.fee_unit !== 'smallest_spld') throw new Error('Splendor provider is connected to the wrong network.');
  const data = await get(`${network.url}/state/account/${encodeURIComponent(account)}`, options);
  if (data.address !== account) throw new Error('Splendor returned a different account.');
  if (typeof data.balance !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(data.balance)) throw new Error('Invalid Splendor balance.');
  const n = BigInt(data.balance);
  if (n >= 2n ** 256n || !Number.isSafeInteger(data.nonce) || data.nonce < 0 || typeof data.has_public_key !== 'boolean' || typeof data.state_root !== 'string' || !/^[0-9a-f]{64}$/.test(data.state_root) || !Number.isSafeInteger(data.block_height) || data.block_height < 0) throw new Error('Invalid Splendor account response.');
  const fraction = String(n % 10n ** 18n).padStart(18, '0').replace(/0+$/, '');
  return [{ symbol: 'SPLD', balance: String(n / 10n ** 18n) + (fraction ? '.' + fraction : '') }];
}
