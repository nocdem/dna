import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Explicit public files prevent serving repository files or following arbitrary paths.
import { files } from './public-files.mjs';

const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || '127.0.0.1';
// Read-only local proxy; fixed configured origin, never a URL supplied by a visitor.
const scanOrigin = new URL(process.env.SCAN_API_ORIGIN || 'https://scan.cpunk.io');
if (!['http:', 'https:'].includes(scanOrigin.protocol) || scanOrigin.username || scanOrigin.password || scanOrigin.pathname !== '/') throw new Error('SCAN_API_ORIGIN must be an HTTP(S) origin');
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be between 1 and 65535');
const server = createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  response.setHeader('Cache-Control', 'no-cache');
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD' }).end('Method not allowed');
    return;
  }
  let entry, url;
  try { url = new URL(request.url, 'http://localhost'); entry = files.get(url.pathname); } catch { /* Invalid request is a 404. */ }
  if (url && ['/wiki', '/scan'].includes(url.pathname)) {
    response.writeHead(308, { Location: url.pathname + '/' + url.search }).end(); return;
  }
  if (url?.pathname.startsWith('/scan/api/')) {
    const endpoint = url.pathname.slice('/scan'.length);
    if (!/^\/api\/(stats|blocks|search|block\/[a-fA-F0-9]+|tx\/[a-fA-F0-9]{128}|address\/[a-fA-F0-9]{128})$/.test(endpoint) || request.url.length > 2048) {
      response.writeHead(404).end('Not found'); return;
    }
    try {
      const upstream = await fetch(new URL(endpoint + url.search, scanOrigin), { headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10000) });
      if (!upstream.headers.get('content-type')?.includes('application/json')) throw new Error('Expected JSON');
      const bytes = Buffer.from(await upstream.arrayBuffer());
      response.writeHead(upstream.status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': bytes.length }).end(request.method === 'HEAD' ? undefined : bytes);
    } catch {
      response.writeHead(503, { 'Content-Type': 'application/json' }).end(request.method === 'HEAD' ? undefined : '{"error":"index unavailable"}');
    }
    return;
  }
  if (!entry) { response.writeHead(404).end('Not found'); return; }
  try {
    let bytes = await readFile(fileURLToPath(new URL(entry[0], import.meta.url)));
    if (entry[1].startsWith('text/html')) {
      // Published links retain their real subdomains; the LAN preview visits local copies.
      bytes = Buffer.from(bytes.toString().replace(/(<a\b[^>]*\bhref=")https:\/\/(wiki\.|scan\.)?nodusnetwork\.io\//g, (_, prefix, site) => prefix + (site ? '/' + site.slice(0, -1) + '/' : '/')));
    }
    response.writeHead(200, { 'Content-Type': entry[1], 'Content-Length': bytes.length });
    response.end(request.method === 'HEAD' ? undefined : bytes);
  } catch {
    response.writeHead(500).end('Unable to serve this file');
  }
});
server.on('error', error => { console.error(`Nodus preview: ${error.message}`); process.exitCode = 1; });
server.listen(port, host, () => console.log(`Nodus is running at http://${host}:${port}`));
