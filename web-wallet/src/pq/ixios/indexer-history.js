// IXIOS account history of the selected network from that network's public indexer (src/pq/ixios/network.js
// `indexer`, the API its explorer reads): GET /v1/address/{address}, one request, the first page of the address's
// transactions. Observed 2026-11-14 on both networks: the answer names the address it describes (`address`, 96
// lowercase hex characters, no 0x) and lists `transactions.data` rows with `hash` (64 hex, no 0x), `from` and `to`
// (96 hex), `amount` (decimal IXIOS), `timestamp` (milliseconds) and `status`; the explorer's own transaction page
// knows the statuses success, failed, pending and unknown (ixoflow.io js/pages/transaction.js STATUS_PRESENTATION).
//
// Everything it returns is UNTRUSTED DATA, checked like the other providers in src/history.js: an answer about another
// address is refused whole; a row must name this address as sender or receiver and carry a well-formed hash, peer, time
// and a positive amount; "success" is shown as confirmed and "failed" as failed; pending, unknown and anything else
// are left out (this wallet's own sends are tracked in its activity). The amount is the indexer's decimal text, read
// with 18 decimals; a row the wallet cannot read is dropped. Provider-reported, not inclusion-proven.
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { request, amountUnits, formatUnits } from '../../core.js';
import { ixiosNetwork } from './network.js';
import { parseIxiosAddress, ixiosChecksumAddress } from './address.js';

export const IXIOS_HISTORY_LIMIT = 50;
const HASH = /^(?:0x)?([0-9a-f]{64})$/i, ADDRESS = /^(?:0x)?([0-9a-f]{96})$/i;
const STATUS = { success: 'confirmed', failed: 'failed' };

export function parseIxiosIndexerHistory(data, address) {
  const own = bytesToHex(parseIxiosAddress(address));
  if (!data || typeof data !== 'object' || typeof data.address !== 'string' || ADDRESS.exec(data.address)?.[1].toLowerCase() !== own) throw new Error('Unexpected history response.');
  const list = Array.isArray(data.transactions?.data) ? data.transactions.data.slice(0, 200) : [];
  const out = [];
  for (const tx of list) {
    const hash = typeof tx?.hash === 'string' ? HASH.exec(tx.hash)?.[1].toLowerCase() : undefined;
    const from = typeof tx?.from === 'string' ? ADDRESS.exec(tx.from)?.[1].toLowerCase() : undefined;
    const to = typeof tx?.to === 'string' ? ADDRESS.exec(tx.to)?.[1].toLowerCase() : undefined;
    const time = tx?.timestamp, status = Object.hasOwn(STATUS, tx?.status) ? STATUS[tx.status] : undefined;
    if (!hash || !from || !to || (from !== own && to !== own) || !Number.isSafeInteger(time) || time <= 0 || time >= 1e14 || !status) continue;
    let units;
    try { units = amountUnits(tx.amount, 18); } catch { continue; }
    const dir = from === own && to === own ? 'self' : from === own ? 'out' : 'in';
    const peer = dir === 'self' ? '' : ixiosChecksumAddress(hexToBytes(dir === 'out' ? to : from));
    out.push({ chain: 'ixios', hash: '0x' + hash, time, dir, symbol: 'IXIOS', amount: formatUnits(units, 18), peer, status });
  }
  return out.sort((a, b) => b.time - a.time || (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0)).slice(0, IXIOS_HISTORY_LIMIT);
}

export async function readIxiosHistory(address, { networkId = 'mainnet', signal, fetcher } = {}) {
  const net = ixiosNetwork(networkId);
  const own = '0x' + bytesToHex(parseIxiosAddress(address));
  const data = await request(`${net.indexer}/v1/address/${own}`, undefined, { signal, fetcher });
  return parseIxiosIndexerHistory(data, address);
}
