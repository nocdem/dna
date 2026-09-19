import { readCpunk } from '../src/adapters/cpunk.js';
// Public DNA registration address from messenger/blockchain/cellframe/cellframe_rpc.h.
const address = process.env.CPUNK_PUBLIC_ADDRESS || 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps';
const endpoint = process.argv[2] || '';
try {
  const result = await readCpunk({ address, endpoint });
  console.log(JSON.stringify({ status: 'connected', ...result }, null, 2));
} catch (error) { console.error(`CPUNK verification FAILED: ${error.message}`); process.exitCode = 1; }
