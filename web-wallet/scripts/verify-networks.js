// Explicit live PUBLIC READS only. No signing or broadcasts.
import { CHAINS, CELLFRAME } from '../src/config.js';
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
  const report = await page.evaluate(async ({ CHAINS, CELLFRAME }) => {
    async function request(url, body) {
      const response = await fetch(url, { method: body ? 'POST' : 'GET', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, credentials: 'omit', signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json(); if (data.error || data.Error) throw new Error('RPC rejected request'); return data;
    }
    // Every Solana call is spaced 1.2s apart, matching the wallet's own
    // publicReadPolicy pacing for this provider (src/rpc-transport.js).
    const rpc = async (url, method, params, chain) => {
      if (chain === 'solana') await new Promise(resolve => setTimeout(resolve, 1200));
      return (await request(url, { jsonrpc: '2.0', id: 1, method, params })).result;
    };
    const publicAddresses = { ethereum: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', bsc: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', solana: 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk', tron: 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH', cellframe: 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps' };
    // One probe per rpcOptions URL (not one per chain): every listed server is checked.
    const targets = [];
    for (const chain of Object.keys(CHAINS)) for (const option of CHAINS[chain].rpcOptions) targets.push({ chain, option });
    for (const option of CELLFRAME.rpcOptions) targets.push({ chain: 'cellframe', option });
    return Promise.all(targets.map(async ({ chain, option }) => {
      const endpoint = option.url;
      try {
        let identity, balances, extra = {};
        if (chain === 'ethereum' || chain === 'bsc') {
          identity = await rpc(endpoint, 'eth_chainId', [], chain); if (BigInt(identity) !== BigInt(CHAINS[chain].chainId)) throw new Error('Wrong network');
          balances = await rpc(endpoint, 'eth_getBalance', [publicAddresses[chain], 'latest'], chain); if (!/^0x[0-9a-f]+$/i.test(balances)) throw new Error('Invalid balance');
          // Activity tracking (activity.js checkActivity) depends on both of these.
          const finalized = await rpc(endpoint, 'eth_getBlockByNumber', ['finalized', false], chain);
          if (!finalized || !/^0x[0-9a-f]+$/i.test(finalized.number) || !/^0x[0-9a-f]{64}$/i.test(finalized.hash)) throw new Error('Invalid finalized block');
          const gasPrice = await rpc(endpoint, 'eth_gasPrice', [], chain); if (!/^0x[0-9a-f]+$/i.test(gasPrice)) throw new Error('Invalid gas price');
          extra = { finalizedBlock: finalized.number, gasPrice };
        } else if (chain === 'solana') {
          identity = await rpc(endpoint, 'getGenesisHash', [], chain); if (identity !== CHAINS.solana.genesisHash) throw new Error('Wrong network');
          balances = (await rpc(endpoint, 'getBalance', [publicAddresses[chain], { commitment: 'confirmed' }], chain))?.value;
          if (!Number.isSafeInteger(balances) || balances < 0) throw new Error('Invalid balance');
          const nativeLamports = balances, tokens = [];
          for (const token of CHAINS.solana.tokens) {
            const data = await rpc(endpoint, 'getTokenAccountsByOwner', [publicAddresses[chain], { mint: token.address }, { encoding: 'jsonParsed', commitment: 'confirmed' }], chain);
            if (!Array.isArray(data?.value)) throw new Error('Invalid token accounts');
            let amount = 0n;
            for (const account of data.value) {
              const raw = account?.account?.data?.parsed?.info?.tokenAmount?.amount;
              if (typeof raw !== 'string' || !/^\d{1,78}$/.test(raw)) throw new Error('Invalid token amount');
              amount += BigInt(raw);
            }
            tokens.push({ symbol: token.symbol, rawAmount: String(amount), decimals: token.decimals });
          }
          balances = { nativeLamports, tokens };
        } else if (chain === 'tron') {
          identity = (await request(endpoint + '/wallet/getblockbynum', { num: 0 })).blockID;
          if (identity !== CHAINS.tron.genesisHash) throw new Error('Wrong network');
          const account = await request(endpoint + '/wallet/getaccount', { address: publicAddresses[chain], visible: true }); balances = account.balance ?? 0;
          if (!Number.isSafeInteger(balances) || balances < 0) throw new Error('Invalid balance');
        } else {
          const data = await request(endpoint, { method: 'wallet', subcommand: 'info', arguments: { net: 'Backbone', addr: publicAddresses.cellframe, token: 'CPUNK' }, id: 1 });
          const row = data.result?.[0]?.[0]; identity = row?.network;
          if (identity !== 'Backbone' || row.addr !== publicAddresses.cellframe) throw new Error('Wrong network/address');
          const tokens = row.tokens?.filter(t => t.token?.ticker === 'CPUNK'); if (tokens?.length !== 1) throw new Error('Missing/duplicate CPUNK');
          balances = tokens[0].coins; if (!/^\d+(\.\d{1,18})?$/.test(balances)) throw new Error('Invalid CPUNK balance');
        }
        return { chain, endpoint, label: option.label, status: 'READ_OK', browserCors: 'passed', identity, balances, ...extra, address: publicAddresses[chain] ?? publicAddresses.cellframe, identityValidation: chain === 'tron' ? 'Pinned provider; genesis observed, not independently matched' : 'matched expected network' };
      } catch (error) { return { chain, endpoint, label: option.label, status: 'BLOCKED', error: error.message, browserCors: 'not established' }; }
    }));
  }, { CHAINS, CELLFRAME }).catch(error => [{ status: 'HARNESS_BLOCKED', error: error.message }]);
  console.log(JSON.stringify({ observedAt: new Date().toISOString(), origin, mode: 'Public reads only; no signing or broadcast', finalDeploymentOrigin: 'unverified', browserTransportErrors: [...transportErrors], environmentProxyConfigured: !!proxy, results: report }, null, 2));
  if (report.some(row => row.status !== 'READ_OK')) process.exitCode = 1;
} finally { await browser?.close(); server.kill(); }
