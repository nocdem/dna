// Temporary CF-20 module: no keys, signing, transfer or claim functionality.
import { endpointUrl } from '../core.js';
import { CPUNK_ENDPOINT, CPUNK_PATH, cpunkQuery, validateCellframeAddress, parseCpunkBalance, boundedJson } from '../cpunk-protocol.js';
export { validateCellframeAddress, parseCpunkBalance } from '../cpunk-protocol.js';
export async function readCpunk({ address, endpoint = '', signal, fetcher = fetch }) {
  validateCellframeAddress(address);
  const gateway = endpoint === CPUNK_PATH;
  const url = gateway ? CPUNK_PATH : endpointUrl(endpoint || CPUNK_ENDPOINT);
  const combined = signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000);
  let response;
  try {
    response = await fetcher(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(gateway ? { address } : cpunkQuery(address)), signal: combined, credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store' });
    response = await boundedJson(response);
  } catch (error) {
    if (signal?.aborted) throw new Error('Request cancelled.');
    if (combined.aborted) throw new Error('CPUNK connection timed out. Try again later.');
    if (error instanceof TypeError) throw new Error('CPUNK connection unavailable. Check the site service, HTTPS endpoint and browser access.');
    throw error;
  }
  if (response?.result?.[0]?.[0]?.addr !== undefined && response.result[0][0].addr !== address) throw new Error('RPC returned a different address.');
  return { balance: parseCpunkBalance(response), address, network: 'Backbone', observedAt: new Date().toISOString() };
}
