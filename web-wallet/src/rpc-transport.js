import { debugLog, errorFields, hostOf, stopwatch } from './debug-log.js';
const DEFAULT_LIMIT = 256 * 1024;
const LARGE_METHODS = { eth_getBlockByNumber: 2 * 1024 * 1024, getTokenAccountsByOwner: 4 * 1024 * 1024 };
// The public endpoint throttles bursts. Space reads across helpers and SDKs in
// this tab; never queue or retry a signed broadcast, or substitute a provider.
const publicReadPolicy = new Map([
  ['https://public.rpc.solanavibestation.com/', { interval: 1200, nextAt: 0, queue: Promise.resolve() }]
]);
async function pacePublicRead(url, body, signal) {
  const policy = publicReadPolicy.get(url);
  if (!policy) return;
  let method;
  try { method = JSON.parse(body).method; } catch { return; }
  if (typeof method !== 'string' || !method.startsWith('get')) return;
  const turn = policy.queue.then(async () => {
    signal.throwIfAborted();
    const delay = policy.nextAt - Date.now();
    if (delay > 0) await new Promise((resolve, reject) => {
      const cancel = () => { clearTimeout(timer); reject(signal.reason); };
      const timer = setTimeout(() => { signal.removeEventListener('abort', cancel); resolve(); }, delay);
      signal.addEventListener('abort', cancel, { once: true });
    });
    signal.throwIfAborted();
    policy.nextAt = Date.now() + policy.interval;
  });
  policy.queue = turn.catch(() => {});
  await turn;
}
export function endpointUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Enter a valid HTTPS RPC URL.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('RPC must use HTTPS without embedded credentials or fragments.');
  return url.href;
}
function responseLimit(body) {
  if (!body) return DEFAULT_LIMIT;
  try {
    const text = typeof body === 'string' ? body : new TextDecoder().decode(body);
    if (text.length > 32768) throw new Error();
    const data = JSON.parse(text), calls = Array.isArray(data) ? data : [data];
    return Math.max(DEFAULT_LIMIT, ...calls.map(call => Object.hasOwn(LARGE_METHODS, call?.method) ? LARGE_METHODS[call.method] : DEFAULT_LIMIT));
  } catch { return DEFAULT_LIMIT; }
}
export async function boundedBytes(response, limit, signal) {
  if (Number(response.headers.get('content-length')) > limit) { void response.body?.cancel().catch(() => {}); throw new Error('RPC response is too large.'); }
  const reader = response.body?.getReader();
  if (!reader) throw new Error('RPC returned no response body.');
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  const chunks = []; let size = 0;
  try {
    while (true) {
      signal?.throwIfAborted();
      const { done, value } = await reader.read();
      signal?.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('RPC response is too large.');
      chunks.push(value);
    }
  } catch (error) { cancel(); throw error; }
  finally { signal?.removeEventListener('abort', cancel); reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}
function validateJsonShape(value) {
  const stack = [[value, 0]]; let count = 0;
  while (stack.length) {
    const [item, depth] = stack.pop();
    if (++count > 150000 || depth > 24 || (typeof item === 'string' && item.length > 65536)) throw new Error('RPC response exceeds data limits.');
    if (item && typeof item === 'object') {
      const entries = Object.entries(item);
      if (entries.length > 4096) throw new Error('RPC response has too many entries.');
      for (const [key, child] of entries) {
        if (key.length > 256) throw new Error('RPC response field is too long.');
        stack.push([child, depth + 1]);
      }
    }
  }
}
// SDK adapters use this too: bounding only the common JSON-RPC helper is insufficient.
// The JSON-RPC method name of a request body, for the debug line only: the parameters (which can be a signed
// transaction) are never read out. A batch or a body that is not JSON gives a fixed word.
function methodNameOf(body) {
  try {
    const data = JSON.parse(typeof body === 'string' ? body : new TextDecoder().decode(body));
    if (Array.isArray(data)) return 'batch';
    return typeof data?.method === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(data.method) ? data.method : 'unknown';
  } catch { return 'unknown'; }
}
// One debug line per call: host (never the URL), method name, duration, HTTP status or the JSON-RPC error code.
export async function rpcFetch(url, options = {}, config = {}) {
  const elapsed = stopwatch(), note = {};
  let host = 'invalid'; try { host = hostOf(url); } catch { /* the call itself reports the bad URL */ }
  const method = options.body ? methodNameOf(options.body) : 'get';
  try {
    const response = await fetchBounded(url, options, config, note);
    debugLog('rpc', 'call', { host, method, ms: elapsed(), status: response.status, jsonrpc_error: note.jsonrpcError, outcome: response.ok ? 'ok' : 'error' });
    return response;
  } catch (error) {
    debugLog('rpc', 'call', { host, method, ms: elapsed(), ...errorFields(error) });
    throw error;
  }
}
async function fetchBounded(url, options = {}, { fetcher = fetch } = {}, note = {}) {
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000);
  const endpoint = endpointUrl(url);
  await pacePublicRead(endpoint, options.body, signal);
  signal.throwIfAborted();
  const response = await fetcher(endpoint, { ...options, signal, redirect: 'error', credentials: 'omit', referrerPolicy: 'no-referrer' });
  const bytes = await boundedBytes(response, responseLimit(options.body), signal);
  if (response.ok) {
    let data;
    try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new Error('RPC returned invalid JSON.'); }
    validateJsonShape(data);
    if (typeof data?.error?.code === 'number') note.jsonrpcError = data.error.code;
  }
  const headers = new Headers(response.headers);
  headers.delete('content-encoding'); headers.set('content-length', String(bytes.length));
  return new Response(bytes, { status: response.status, statusText: response.statusText, headers });
}
export async function ethersGetUrl(req, signal) {
  signal?.checkSignal();
  const controller = new AbortController();
  signal?.addListener(() => controller.abort());
  const response = await rpcFetch(req.url, { method: req.method, headers: new Headers(Array.from(req)), body: req.body || undefined, signal: controller.signal });
  return { statusCode: response.status, statusMessage: response.statusText, headers: Object.fromEntries(response.headers), body: new Uint8Array(await response.arrayBuffer()) };
}
