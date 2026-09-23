// Fully intercepted read-only portfolio fixtures. Never forward a blockchain request.
import assert from 'node:assert/strict';
import { ASSETS, PRICE_URL } from '../src/portfolio.js';
import { CHAINS, CELLFRAME } from '../src/config.js';
import { IXIOS_NETWORK } from '../src/ixios/network.js';
import { IXIOS_GENESIS_HASH } from '../src/ixios/balance.js';
export function priceFixture(price = 2, timestamp = Math.floor(Date.now() / 1000)) {
  return { coins: Object.fromEntries(ASSETS.map(a => [a.priceId, { symbol: a.symbol, decimals: a.decimals, price, timestamp, confidence: .99 }])) };
}
// Cellframe/CPUNK is derived locally (not part of deriveWallet()'s fixed test
// vectors), so — matching how portfolioRead validates other chains' addresses
// by format rather than by exact value (see the Solana/EVM regex checks below)
// — this checks the request shape and the address format, not a specific
// address string. `balance` is the RPC's decimal "coins" string, not raw units.
export async function cellframeRead(route, { balance = '10', fail = false } = {}) {
  const req = route.request();
  if (req.url() !== CELLFRAME.endpoint) return false;
  assert.equal(req.method(), 'POST');
  const body = req.postDataJSON();
  assert.equal(body.method, 'wallet'); assert.equal(body.subcommand, 'info'); assert.equal(body.id, 1);
  assert.deepEqual(Object.keys(body.arguments).sort(), ['addr', 'net', 'token']);
  assert.equal(body.arguments.net, 'Backbone'); assert.equal(body.arguments.token, 'CPUNK');
  assert.match(body.arguments.addr, /^[1-9A-HJ-NP-Za-km-z]{100,110}$/);
  if (fail) { await route.abort(); return true; }
  await route.fulfill({ json: { result: [[{ addr: body.arguments.addr, balance }]] } });
  return true;
}
// Ixios (flag-on builds only): network identity by genesis block 0, then
// eth_getBalance for a 48-byte Q-address. Shape-checked like cellframeRead;
// `balance` is raw units (18 decimals).
export async function ixiosRead(route, { balance = 10n ** 18n } = {}) {
  const req = route.request();
  if (new URL(req.url()).origin !== new URL(IXIOS_NETWORK.endpoint).origin) return false;
  assert.equal(req.method(), 'POST');
  const call = req.postDataJSON();
  let result;
  if (call.method === 'eth_getBlockByNumber') { assert.deepEqual(call.params, ['0x0', false]); result = { number: '0x0', hash: IXIOS_GENESIS_HASH }; }
  else if (call.method === 'eth_getBalance') { assert.match(call.params[0], /^0x[0-9a-fA-F]{96}$/); assert.equal(call.params[1], 'latest'); result = '0x' + balance.toString(16); }
  else assert.fail(`unexpected Ixios RPC method ${call.method}`);
  await route.fulfill({ json: { jsonrpc: '2.0', id: call.id, result } });
  return true;
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
