// Temporary CF-20 module: no keys, signing, transfer or claim functionality.
import { endpointUrl } from '../core.js';
import { CPUNK_ENDPOINT, cpunkQuery, validateCellframeAddress, parseCpunkBalance, boundedJson } from '../cpunk-protocol.js';
export { validateCellframeAddress, parseCpunkBalance } from '../cpunk-protocol.js';
export async function readCpunk({ address, endpoint = '', signal, fetcher = fetch }) {
  validateCellframeAddress(address);
  const url = endpointUrl(endpoint || CPUNK_ENDPOINT);
  const combined = signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000);
  let response;
  try {
    // text/plain keeps this a CORS "simple" request: rpc.cellframe.net answers
    // the OPTIONS preflight a JSON content type needs with 405 and no CORS
    // headers, so the browser drops the request (checked 2026-10-01); it
    // answers this POST with Access-Control-Allow-Origin: * and parses the
    // body as JSON either way.
    response = await fetcher(url, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: JSON.stringify(cpunkQuery(address)), signal: combined, credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store' });
    response = await boundedJson(response);
  } catch (error) {
    if (signal?.aborted) throw new Error('Request cancelled.');
    if (combined.aborted) throw new Error('CPUNK connection timed out. Try again later.');
    if (error instanceof TypeError) throw new Error('CPUNK connection unavailable. Check the HTTPS endpoint and browser access.');
    throw error;
  }
  if (response?.result?.[0]?.[0]?.addr !== undefined && response.result[0][0].addr !== address) throw new Error('RPC returned a different address.');
  return { balance: parseCpunkBalance(response), address, network: 'Backbone', observedAt: new Date().toISOString() };
}
