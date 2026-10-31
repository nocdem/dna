// Read-only Asentum testnet REST API, as documented by the official SDK.
// The genesis hash was observed from testnet.asentum.com; this provider pin is
// an identity consistency check, not cryptographic proof of the chain.
import { bech32 } from '@scure/base';
import { request } from '../core.js';

const PROVIDER = 'https://testnet.asentum.com';
const GENESIS = '0xc12243eee53d0a642c34845575687144802b79eabb07b213815ee907f0451aa3';
function address(value) {
  if (typeof value !== 'string' || value !== value.toLowerCase()) throw new Error('Invalid Asentum address.');
  try {
    const decoded = bech32.decode(value);
    const bytes = bech32.fromWords(decoded.words);
    if (decoded.prefix !== 'ase' || bytes.length !== 20 || bech32.encode('ase', bech32.toWords(bytes)) !== value) throw new Error();
    return '0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  } catch { throw new Error('Invalid Asentum address.'); }
}
async function get(path, options) {
  options.signal?.throwIfAborted();
  const data = await request(PROVIDER + path, undefined, options);
  options.signal?.throwIfAborted();
  if (Array.isArray(data) || data.message) throw new Error('Invalid Asentum response.');
  return data;
}
export async function readAsentumBalances(account, { networkId = 'testnet', signal, fetcher } = {}) {
  const hex = address(account);
  if (networkId !== 'testnet') throw new Error('Unsupported Asentum network.');
  const options = { signal, fetcher };
  const chain = await get('/chain', options);
  if (chain.chainId !== '1423') throw new Error('Asentum provider is connected to the wrong network.');
  const genesis = await get('/genesis', options);
  if (genesis.chainId !== '1423' || genesis.genesisHash !== GENESIS) throw new Error('Asentum provider is connected to the wrong network.');
  const data = await get(`/balance/${account}`, options);
  if (data.address !== account && data.address !== hex) throw new Error('Asentum returned a different account.');
  if (typeof data.balance !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(data.balance)) throw new Error('Invalid Asentum balance.');
  const n = BigInt(data.balance);
  if (n >= 2n ** 256n) throw new Error('Invalid Asentum balance.');
  const balance = `${n / 10n ** 18n}.${String(n % 10n ** 18n).padStart(18, '0')}`.replace(/\.?0+$/, '');
  return [{ symbol: 'ASE', balance }];
}
