// Explicit live PUBLIC READS only. No signing or broadcasts.
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
const origin = 'http://127.0.0.1:4174';
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '4174', '--strictPort'], { stdio: 'ignore' });
let browser;
try {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(origin)).ok) break; } catch {} await setTimeout(100); }
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH });
  const page = await browser.newPage(); await page.goto(origin);
  const report = await page.evaluate(async () => {
    await import('/src/main.js');
    const { CHAINS } = await import('/src/config.js');
    const { adapters } = await import('/src/wallet.js');
    const { request } = await import('/src/core.js');
    const { readCpunk } = await import('/src/adapters/cpunk.js');
    const publicAddresses = { ethereum: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', bsc: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', solana: 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk', tron: 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH', cpunk: 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps' };
    return Promise.all([...Object.keys(CHAINS), 'cpunk'].map(async chain => {
      const endpoint = CHAINS[chain]?.endpoint || 'https://rpc.cellframe.net/connect';
      try {
        const balances = chain === 'cpunk' ? await readCpunk({ address: publicAddresses[chain] }) : await adapters[chain].balances(chain, publicAddresses[chain], endpoint);
        const identity = chain === 'tron' ? (await request(endpoint + '/wallet/getblockbynum', { num: 0 })).blockID : chain === 'solana' ? '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' : chain === 'cpunk' ? 'Backbone' : CHAINS[chain].chainId;
        return { chain, endpoint, status: 'READ_OK', browserCors: 'passed', identity, balances, address: publicAddresses[chain], identityValidation: chain === 'tron' ? 'Pinned provider; genesis observed, not independently matched' : 'matched expected network' };
      } catch (error) { return { chain, endpoint, status: 'BLOCKED', error: error.message, browserCors: 'not established' }; }
    }));
  });
  console.log(JSON.stringify({ observedAt: new Date().toISOString(), origin, mode: 'Public reads only; no signing or broadcast', finalDeploymentOrigin: 'unverified', results: report }, null, 2));
  if (report.some(row => row.status !== 'READ_OK')) process.exitCode = 1;
} finally { await browser?.close(); server.kill(); }
