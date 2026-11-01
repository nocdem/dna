// Bounded transport and exact JSON number lexemes for public indexer responses.
import { rpcFetch } from '../rpc-transport.js';
export async function integerJson(url, { signal, fetcher } = {}) {
  signal?.throwIfAborted();
  const response = await rpcFetch(url, { method: 'GET', signal }, { fetcher });
  signal?.throwIfAborted();
  if (!response.ok) {
    const error = new Error(`RPC request failed (HTTP ${response.status}).`);
    error.status = response.status;
    throw error;
  }
  const text = await response.text();
  signal?.throwIfAborted();
  let data;
  try {
    data = JSON.parse(text, (_key, value, context) => typeof value === 'number' && context?.source !== undefined ? context.source : value);
    // Syntax is already validated by JSON.parse. Track keys by decoded name so
    // escaped spellings cannot mask a duplicate in any nested object.
    const stack = [];
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '"') {
        const start = i++;
        while (i < text.length) {
          if (text[i] === '\\') { i += 2; continue; }
          if (text[i] === '"') break;
          i++;
        }
        let j = i + 1; while (/\s/.test(text[j] || '') && j < text.length) j++;
        if (text[j] === ':') {
          const keys = stack.at(-1);
          if (!keys) throw new Error();
          const key = JSON.parse(text.slice(start, i + 1));
          if (keys.has(key)) throw new Error();
          keys.add(key);
        }
      } else if (c === '{') stack.push(new Set());
      else if (c === '[') stack.push(null);
      else if (c === '}' || c === ']') stack.pop();
    }
  } catch { throw new Error('Invalid or ambiguous JSON response.'); }
  if (!data || typeof data !== 'object' || data.error || data.Error || data.success === false) throw new Error('RPC rejected the request.');
  return data;
}
export function atoms(value) {
  // On engines without reviver source support, numeric values remain numbers
  // and fail closed; canonical string values continue to work.
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,18})$/.test(value)) throw new Error('Invalid balance integer.');
  const n = BigInt(value);
  if (n > 9223372036854775807n) throw new Error('Balance integer exceeds int64.');
  return n;
}
export function decimalAtoms(n) {
  const fraction = String(n % 100000000n).padStart(8, '0').replace(/0+$/, '');
  return String(n / 100000000n) + (fraction ? '.' + fraction : '');
}
