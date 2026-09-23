// IXIOS balance read, the Ixios counterpart of src/adapters/cpunk.js readCpunk.
// Pulled in only by the VITE_ENABLE_IXIOS block in src/app.js (dynamic import),
// so a build with the flag off carries none of it.
//
// Network identity is checked by genesis hash, never by eth_chainId: Ixios
// mainnet's chain id is 1, the same as Ethereum's, so an Ethereum RPC would pass
// a chain-id check. The hash is Ixios mainnet's genesis block (ixiosSpark
// params/config.go:27). Requests go through rpc() in src/core.js (HTTPS only,
// timeout, bounded response size).
import { rpc, rawInteger, formatUnits } from '../core.js';
import { parseIxiosAddress } from './address.js';
export const IXIOS_GENESIS_HASH = '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f';
export async function readIxiosBalance(address, endpoint, { signal } = {}) {
  parseIxiosAddress(address);
  const options = { signal };
  const genesis = await rpc(endpoint, 'eth_getBlockByNumber', ['0x0', false], options);
  if (genesis?.hash !== IXIOS_GENESIS_HASH) throw new Error('RPC is connected to the wrong network.');
  const units = rawInteger(await rpc(endpoint, 'eth_getBalance', [address, 'latest'], options));
  return [{ symbol: 'IXIOS', balance: formatUnits(units, 18) }];
}
