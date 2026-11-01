// Official SoquShield multi-balance endpoint; confirmed native total includes immature coinbase.
import { bech32m } from '@scure/base';
import { integerJson, atoms, decimalAtoms } from './integer-json.js';
export function witnessAddress(address, prefix, version) {
  try {
    if (typeof address !== 'string' || address !== address.toLowerCase()) throw new Error();
    const decoded = bech32m.decode(address), words = decoded.words;
    const bytes = bech32m.fromWords(words.slice(1));
    if (decoded.prefix !== prefix || words[0] !== version || bytes.length !== 32 || bech32m.encode(prefix, [version, ...bech32m.toWords(bytes)]) !== address) throw new Error();
    return bytes;
  } catch { throw new Error('Invalid witness address.'); }
}
export async function readSoquBalances(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  witnessAddress(account, 'sq', 1);
  if (networkId !== 'mainnet') throw new Error('Unsupported Soqucoin network.');
  const data = await integerJson(`https://mainnet-api.soqu.org/api/v2/multi-balance/${encodeURIComponent(account)}`, { signal, fetcher });
  if (!data || data.address !== account || !data.soq || typeof data.soq !== 'object' || Array.isArray(data.soq)) throw new Error('Invalid Soqucoin account response.');
  return [{ symbol: 'SOQ', balance: decimalAtoms(atoms(data.soq.confirmed)) }];
}
