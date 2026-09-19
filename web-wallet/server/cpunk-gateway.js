import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { CPUNK_ENDPOINT, CPUNK_PATH, cpunkQuery, parseCpunkBalance, boundedJson } from '../src/cpunk-protocol.js';
// Deliberately fixed: neither client input nor environment selects an upstream.
export const UPSTREAM = CPUNK_ENDPOINT;
export function createGateway({ fetcher = fetch, timeoutMs = 10000 } = {}) {
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const reply = (status, body) => { res.writeHead(status); res.end(JSON.stringify(body)); };
    if (req.url !== CPUNK_PATH) return reply(404, { error: 'Not found.' });
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return reply(405, { error: 'Use POST.' }); }
    if (req.headers['sec-fetch-site'] === 'cross-site') return reply(403, { error: 'Cross-site requests are not permitted.' });
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) return reply(415, { error: 'Use application/json.' });
    if (Number(req.headers['content-length']) > 512) return reply(413, { error: 'Request too large.' });
    let query;
    try {
      let size = 0; const chunks = [];
      for await (const chunk of req) { size += chunk.length; if (size > 512) { reply(413, { error: 'Request too large.' }); return; } chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!body || Array.isArray(body) || Object.keys(body).length !== 1 || !Object.hasOwn(body, 'address')) throw new Error('Only address is accepted.');
      query = cpunkQuery(body.address);
    } catch { if (!res.headersSent) reply(400, { error: 'Provide only a valid Cellframe public address.' }); return; }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const disconnect = () => { if (!res.writableEnded) controller.abort(); };
    res.on('close', disconnect);
    try {
      const upstream = await fetcher(UPSTREAM, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(query), signal: controller.signal, redirect: 'error' });
      const data = await boundedJson(upstream);
      if (data?.result?.[0]?.[0]?.addr !== undefined && data.result[0][0].addr !== query.arguments.addr) throw new Error('Address mismatch.');
      const balance = parseCpunkBalance(data);
      reply(200, { id: 1, result: [[{ token: 'CPUNK', balance }]] });
    } catch { if (!res.destroyed) reply(controller.signal.aborted ? 504 : 502, { error: 'CPUNK upstream unavailable or returned an invalid balance. No balance is available.' }); }
    finally { clearTimeout(timer); res.off('close', disconnect); }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.timeout = 15000;
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.CPUNK_PORT || 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid CPUNK_PORT.');
  createGateway().listen(port, '127.0.0.1', () => console.log(`CPUNK read-only service listening on 127.0.0.1:${port}`));
}
