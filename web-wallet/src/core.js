import { parseUnits, formatUnits } from 'ethers';
export { formatUnits };
export function amountUnits(value, decimals) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)(\.\d+)?$/.test(value) || value.length > 90) throw new Error('Enter a positive decimal amount.');
  if ((value.split('.')[1]?.length ?? 0) > decimals) throw new Error(`This asset allows ${decimals} decimal places.`);
  const units = parseUnits(value, decimals);
  if (units <= 0n || units >= 2n ** 256n) throw new Error('Amount is out of range.');
  return units;
}
export function rawInteger(value) {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw new Error('RPC returned an unsafe numeric balance.');
  if (!/^(0x[0-9a-f]+|\d+)$/i.test(String(value))) throw new Error('RPC returned an invalid balance.');
  return BigInt(value);
}
export function endpointUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Enter a valid HTTPS RPC URL.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('RPC must use HTTPS without embedded credentials or fragments.');
  return url.href;
}
export async function request(url, body, { signal, fetcher = fetch } = {}) {
  const timeout = AbortSignal.timeout(15000);
  const combined = signal ? AbortSignal.any([timeout, signal]) : timeout;
  let response;
  try {
    response = await fetcher(endpointUrl(url), { method: body ? 'POST' : 'GET', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, signal: combined, credentials: 'omit', referrerPolicy: 'no-referrer' });
  } catch (error) {
    if (signal?.aborted) throw new Error('Request cancelled.');
    throw new Error('RPC unavailable. Check the HTTPS endpoint, browser CORS access and connection.');
  }
  if (!response.ok) throw new Error(`RPC request failed (HTTP ${response.status}).`);
  const data = await response.json();
  if (!data || typeof data !== 'object' || data.error || data.Error || data.success === false) throw new Error('RPC rejected the request.');
  return data;
}
export async function rpc(url, method, params, options) {
  const data = await request(url, { jsonrpc: '2.0', id: 1, method, params }, options);
  if (!Object.hasOwn(data, 'result')) throw new Error('RPC returned no result.');
  return data.result;
}
