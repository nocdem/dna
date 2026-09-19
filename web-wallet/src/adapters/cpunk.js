// Temporary CF-20 module. No keys, signing, transfer, claim, or multichain dependencies.
import { request, endpointUrl } from '../core.js';
export function validateCellframeAddress(address) {
  // Structural validation only. Ownership/checksum is NOT established by this check.
  if (!/^[1-9A-HJ-NP-Za-km-z]{100,110}$/.test(address)) throw new Error('Enter a Cellframe public address (Base58, 100–110 characters).');
  return address;
}
export function parseCpunkBalance(response) {
  const row = response?.result?.[0]?.[0];
  if (response?.error || (row?.token && row.token !== 'CPUNK')) throw new Error('RPC did not return a CPUNK balance.');
  const balance = row?.balance;
  // Existing cell_chain.c treats this as an already formatted coin amount.
  if (typeof balance !== 'string' || !/^\d+(\.\d{1,18})?$/.test(balance)) throw new Error('RPC returned an unrecognized CPUNK balance; no balance can be shown.');
  return balance;
}
export async function readCpunk({ address, endpoint, signal, fetcher }) {
  validateCellframeAddress(address);
  if (!endpoint) throw new Error('A browser-accessible HTTPS Cellframe RPC is required.');
  const response = await request(endpointUrl(endpoint), { method: 'wallet', subcommand: 'info', arguments: { net: 'Backbone', addr: address, token: 'CPUNK' }, id: 1 }, { signal, fetcher });
  return { balance: parseCpunkBalance(response), address, network: 'Backbone', observedAt: new Date().toISOString() };
}
