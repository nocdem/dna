import { CPUNK_PATH } from '../src/cpunk-protocol.js';
import { readCpunk } from '../src/adapters/cpunk.js';
// Public DNA registration address from messenger/blockchain/cellframe/cellframe_rpc.h.
const address = process.env.CPUNK_PUBLIC_ADDRESS || 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps';
const direct = process.argv[2] === '--direct';
const site = new URL(direct ? 'https://rpc.cellframe.net' : process.argv[2] || 'http://127.0.0.1:8787');
if (site.protocol !== 'https:' && !(site.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(site.hostname))) throw new Error('Use HTTPS or local loopback.');
try {
  const result = await readCpunk({ address, endpoint: direct ? '' : CPUNK_PATH, fetcher: (path, options) => fetch(new URL(path, site), options) });
  console.log(JSON.stringify({ status: 'connected', ...result }, null, 2));
} catch (error) { console.error(`CPUNK verification FAILED: ${error.message}`); process.exitCode = 1; }
