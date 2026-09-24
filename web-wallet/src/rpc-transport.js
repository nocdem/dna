const DEFAULT_LIMIT = 256 * 1024;
const LARGE_METHODS = { eth_getBlockByNumber: 2 * 1024 * 1024, getTokenAccountsByOwner: 4 * 1024 * 1024 };
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
export async function rpcFetch(url, options = {}, { fetcher = fetch } = {}) {
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000);
  const response = await fetcher(endpointUrl(url), { ...options, signal, redirect: 'error', credentials: 'omit', referrerPolicy: 'no-referrer' });
  const bytes = await boundedBytes(response, responseLimit(options.body), signal);
  if (response.ok) {
    let data;
    try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new Error('RPC returned invalid JSON.'); }
    validateJsonShape(data);
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
