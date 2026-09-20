// Fully intercepted read-only portfolio fixtures. Never forward a blockchain request.
import assert from 'node:assert/strict';
import { ASSETS, PRICE_URL } from '../src/portfolio.js';
import { CHAINS } from '../src/config.js';
export function priceFixture(price = 2, timestamp = Math.floor(Date.now() / 1000)) {
  return { coins: Object.fromEntries(ASSETS.map(a => [a.priceId, { symbol: a.symbol, decimals: a.decimals, price, timestamp, confidence: .99 }])) };
}
export async function portfolioRead(route, { ethereum = true, holdings = {}, failures = [], wrongNetwork } = {}) {
  const req = route.request(), url = new URL(req.url());
  if (req.url() === PRICE_URL) {
    assert.equal(req.method(), 'GET'); assert.equal(req.postData(), null);
    await route.fulfill({ json: priceFixture() }); return true;
  }
  const chain = Object.keys(CHAINS).find(c => new URL(CHAINS[c].endpoint).origin === url.origin);
  if (!chain || (chain === 'ethereum' && !ethereum)) return false;
  const body = req.method() === 'POST' ? req.postDataJSON() : null;
  const units = symbol => BigInt(holdings[`${chain}:${symbol}`] || 0);
  if (chain === 'tron') {
    if (url.pathname === '/wallet/getblockbynum') {
      assert.deepEqual(body, { num: 0 });
      await route.fulfill({ json: { blockID: wrongNetwork === chain ? 'wrong-genesis' : CHAINS.tron.genesisHash } }); return true;
    }
    if (/^\/v1\/accounts\/T[1-9A-HJ-NP-Za-km-z]{33}$/.test(url.pathname) && req.method() === 'GET') {
      await route.fulfill({ json: { data: [{ balance: Number(units('TRX')), trc20: CHAINS.tron.tokens.map(t => ({ [t.address]: String(units(t.symbol)) })) }] } }); return true;
    }
    return false;
  }
  const call = body;
  if (!call || Array.isArray(call)) return false;
  let result, symbol;
  if (chain === 'solana') {
    if (call.method === 'getGenesisHash') {
      assert.deepEqual(call.params, []); result = wrongNetwork === chain ? 'wrong-genesis' : CHAINS.solana.genesisHash;
    } else if (call.method === 'getBalance') {
      assert.match(call.params[0], /^[1-9A-HJ-NP-Za-km-z]{32,44}$/); result = { value: Number(units('SOL')) }; symbol = 'SOL';
    } else if (call.method === 'getTokenAccountsByOwner') {
      assert.match(call.params[0], /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
      const token = CHAINS.solana.tokens.find(t => t.address === call.params[1].mint); assert.ok(token); symbol = token.symbol;
      result = { value: [{ account: { data: { parsed: { info: { tokenAmount: { amount: String(units(symbol)) } } } } } }] };
    } else return false;
  } else {
    if (call.method === 'eth_chainId') {
      assert.deepEqual(call.params, []); result = '0x' + (wrongNetwork === chain ? 999 : CHAINS[chain].chainId).toString(16);
    } else if (call.method === 'eth_getBalance') {
      assert.match(call.params[0], /^0x[0-9a-fA-F]{40}$/); symbol = CHAINS[chain].symbol; result = '0x' + units(symbol).toString(16);
    } else if (call.method === 'eth_call') {
      const token = CHAINS[chain].tokens.find(t => t.address.toLowerCase() === call.params[0].to.toLowerCase()); assert.ok(token);
      assert.match(call.params[0].data, /^0x70a08231[0-9a-f]{64}$/i); symbol = token.symbol;
      result = '0x' + units(symbol).toString(16).padStart(64, '0');
    } else return false;
  }
  await route.fulfill({ json: failures.includes(`${chain}:${symbol}`)
    ? { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: 'Fixture unavailable' } }
    : { jsonrpc: '2.0', id: call.id, result } });
  return true;
}
