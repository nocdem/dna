// Explicit live PUBLIC READS only. No signing or broadcasts.
import { CHAINS } from '../src/config.js';
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
const origin = 'http://127.0.0.1:4174';
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '4174', '--strictPort', '--force'], { stdio: 'ignore' });
let browser;
try {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(origin)).ok) break; } catch {} await setTimeout(100); }
  const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy;
  let proxy;
  if (proxyUrl) {
    const url = new URL(proxyUrl);
    proxy = { server: `${url.protocol}//${url.host}`, bypass: '127.0.0.1,localhost' };
    if (url.username) proxy.username = decodeURIComponent(url.username);
    if (url.password) proxy.password = decodeURIComponent(url.password);
  }
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH, proxy });
  const page = await browser.newPage(); const transportErrors = new Set();
  page.on('requestfailed', req => { transportErrors.add(req.failure()?.errorText || 'unknown transport error'); });
  // A minimal same-origin page avoids dev-server dependency optimization races.
  await page.route(origin + '/verify', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Public RPC verification</title>' }));
  await page.goto(origin + '/verify');
  const report = await page.evaluate(async ({ CHAINS }) => {
    async function request(url, body) {
      const response = await fetch(url, { method: body ? 'POST' : 'GET', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, credentials: 'omit', signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json(); if (data.error || data.Error) throw new Error('RPC rejected request'); return data;
    }
    const rpc = async (url, method, params) => (await request(url, { jsonrpc: '2.0', id: 1, method, params })).result;
    const publicAddresses = { ethereum: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', bsc: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', solana: 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk', tron: 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH', cpunk: 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps' };
    return Promise.all([...Object.keys(CHAINS), 'cpunk'].map(async chain => {
      const endpoint = CHAINS[chain]?.endpoint || 'https://rpc.cellframe.net/connect';
      try {
        let identity, balances;
        if (chain === 'ethereum' || chain === 'bsc') {
          identity = await rpc(endpoint, 'eth_chainId', []); if (BigInt(identity) !== BigInt(CHAINS[chain].chainId)) throw new Error('Wrong network');
          balances = await rpc(endpoint, 'eth_getBalance', [publicAddresses[chain], 'latest']); if (!/^0x[0-9a-f]+$/i.test(balances)) throw new Error('Invalid balance');
        } else if (chain === 'solana') {
          identity = await rpc(endpoint, 'getGenesisHash', []); if (identity !== '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp') throw new Error('Wrong network');
          balances = (await rpc(endpoint, 'getBalance', [publicAddresses[chain], { commitment: 'confirmed' }]))?.value;
          if (!Number.isSafeInteger(balances) || balances < 0) throw new Error('Invalid balance');
        } else if (chain === 'tron') {
          identity = (await request(endpoint + '/wallet/getblockbynum', { num: 0 })).blockID;
          if (identity !== '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc') throw new Error('Wrong network');
          const account = await request(endpoint + '/wallet/getaccount', { address: publicAddresses[chain], visible: true }); balances = account.balance ?? 0;
          if (!Number.isSafeInteger(balances) || balances < 0) throw new Error('Invalid balance');
        } else {
          const data = await request(endpoint, { method: 'wallet', subcommand: 'info', arguments: { net: 'Backbone', addr: publicAddresses[chain], token: 'CPUNK' }, id: 1 });
          const row = data.result?.[0]?.[0]; identity = row?.network;
          if (identity !== 'Backbone' || row.addr !== publicAddresses[chain]) throw new Error('Wrong network/address');
          const tokens = row.tokens?.filter(t => t.token?.ticker === 'CPUNK'); if (tokens?.length !== 1) throw new Error('Missing/duplicate CPUNK');
          balances = tokens[0].coins; if (!/^\d+(\.\d{1,18})?$/.test(balances)) throw new Error('Invalid CPUNK balance');
        }
        return { chain, endpoint, status: 'READ_OK', browserCors: 'passed', identity, balances, address: publicAddresses[chain], identityValidation: chain === 'tron' ? 'Pinned provider; genesis observed, not independently matched' : 'matched expected network' };
      } catch (error) { return { chain, endpoint, status: 'BLOCKED', error: error.message, browserCors: 'not established' }; }
    }));
  }, { CHAINS }).catch(error => [{ status: 'HARNESS_BLOCKED', error: error.message }]);
  console.log(JSON.stringify({ observedAt: new Date().toISOString(), origin, mode: 'Public reads only; no signing or broadcast', finalDeploymentOrigin: 'unverified', browserTransportErrors: [...transportErrors], environmentProxyConfigured: !!proxy, results: report }, null, 2));
  if (report.some(row => row.status !== 'READ_OK')) process.exitCode = 1;
} finally { await browser?.close(); server.kill(); }
