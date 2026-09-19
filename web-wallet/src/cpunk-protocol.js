// Isolated public, read-only CPUNK contract shared by browser and gateway.
export const CPUNK_ENDPOINT = 'https://rpc.cellframe.net/connect';
export const CPUNK_PATH = '/api/cpunk/balance';
export function validateCellframeAddress(address) {
  // Structural only: does not establish checksum validity or ownership.
  if (typeof address !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{100,110}$/.test(address)) throw new Error('Enter a Cellframe public address (Base58, 100–110 characters).');
  return address;
}
export function cpunkQuery(address) {
  return { method: 'wallet', subcommand: 'info', arguments: { net: 'Backbone', addr: validateCellframeAddress(address), token: 'CPUNK' }, id: 1 };
}
export function parseCpunkBalance(response) {
  const row = response?.result?.[0]?.[0];
  if (response?.error || response?.Error || response?.success === false || (response?.id !== undefined && response.id !== 1) || (row?.token !== undefined && row.token !== 'CPUNK')) throw new Error('RPC did not return a CPUNK balance.');
  if (row?.network !== undefined && row.network !== 'Backbone') throw new Error('RPC returned a different network.');
  let balance = row?.balance;
  if (row?.tokens !== undefined) {
    if (!Array.isArray(row.tokens) || row.network !== 'Backbone') throw new Error('RPC returned an unrecognized CPUNK network or tokens.');
    const matches = row.tokens.filter(item => item?.token?.ticker === 'CPUNK');
    if (matches.length !== 1) throw new Error('RPC did not return exactly one CPUNK balance.');
    const token = matches[0]; balance = token.coins;
    if (typeof balance !== 'string' || !/^\d{1,78}(\.\d{1,18})?$/.test(balance) || typeof token.datoshi !== 'string' || !/^\d{1,78}$/.test(token.datoshi)) throw new Error('RPC returned an unrecognized CPUNK balance.');
    const [whole, fraction = ''] = balance.split('.');
    if (BigInt(whole + fraction.padEnd(18, '0')) !== BigInt(token.datoshi)) throw new Error('RPC returned inconsistent CPUNK amounts.');
  }
  if (!Array.isArray(response?.result) || !Array.isArray(response.result[0]) || typeof balance !== 'string' || balance.length > 97 || !/^\d+(\.\d{1,18})?$/.test(balance)) throw new Error('RPC returned an unrecognized CPUNK balance; no balance can be shown.');
  return balance;
}
export async function boundedJson(response, limit = 65536) {
  if (!response.ok) throw new Error(`CPUNK connection unavailable (HTTP ${response.status}). Check the site's CPUNK service or HTTPS endpoint.`);
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('CPUNK service returned an unrecognized response. Check the site configuration.');
  if (Number(response.headers.get('content-length')) > limit) { void response.body?.cancel().catch(() => {}); throw new Error('CPUNK response is too large.'); }
  const reader = response.body?.getReader();
  if (!reader) throw new Error('CPUNK service returned no response.');
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('CPUNK response is too large.');
      chunks.push(value);
    }
  } catch (error) { void reader.cancel().catch(() => {}); throw error; } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('CPUNK service returned invalid JSON.'); }
}
