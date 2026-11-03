// IXIOS balance read, the Ixios counterpart of src/adapters/cpunk.js readCpunk.
// Pulled in only by the VITE_ENABLE_IXIOS block in src/app.js (dynamic import),
// so a build with the flag off carries none of it.
//
// Network identity is checked by genesis hash, never by eth_chainId: Ixios
// mainnet's chain id is 1, the same as Ethereum's, so an Ethereum RPC would pass
// a chain-id check. The hash is Ixios mainnet's genesis block (ixiosSpark
// params/config.go:27). It is read as block 1's parentHash, not from block 0:
// Ixios' genesis block carries a ~215 KB extraData string (observed 2026-09-23
// on ixios-rpc.innova.limited), which the shared transport's per-string cap
// (src/rpc-transport.js, 65536 characters) rightly refuses; block 1 is ~1.6 KB
// and its parentHash is the genesis hash. Requests go through rpc() in
// src/core.js (HTTPS only, timeout, bounded response size).
import { rpc, rawInteger, formatUnits } from '../core.js';
import { parseIxiosAddress } from './address.js';
export const IXIOS_GENESIS_HASH = '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f';
export async function readIxiosBalance(address, endpoint, { signal } = {}) {
  parseIxiosAddress(address);
  const options = { signal };
  const first = await rpc(endpoint, 'eth_getBlockByNumber', ['0x1', false], options);
  if (first?.number !== '0x1' || first?.parentHash !== IXIOS_GENESIS_HASH) throw new Error('RPC is connected to the wrong network.');
  const units = rawInteger(await rpc(endpoint, 'eth_getBalance', [address, 'latest'], options));
  return [{ symbol: 'IXIOS', balance: formatUnits(units, 18) }];
}
