// The swap bot's HTTP client. The bot is reached directly at BOT_ORIGIN (the web server on the bot's machine,
// deploy/amm-https.conf) under /amm/, never through this page's own origin (plan section 18 change 5; the page's CSP
// connect-src is 'self' https:, deploy/swap-https.conf). Routes and answer shapes: nodus/tools/amm/amm_http.h of branch main-amm.
// BOT_ORIGIN is the one constant the page uses both for these calls and for the botUrl it gives the extension, so the
// two cannot go to different hosts. It is an origin without a path, as the extension requires.
// The answers are shown as given: no signature, no check (givens items 65, 69).
//
// Every call returns { ok, status, json } or { ok: false, unreachable: true }. The bot answers refusals with
// HTTP 200 and a JSON body ({"approved":false,"reason":..}), "bad_request" with 400, an unknown swap with 404:
// the JSON body is read on every status.

import { quoteBody, liquidityQuoteBody, withdrawBody } from './swap-logic.js';

export const BOT_ORIGIN = 'https://62.171.136.77';

export function createBotClient({ fetch, base = `${BOT_ORIGIN}/amm`, timeoutMs = 15000 } = {}) {
  if (typeof fetch !== 'function') throw new TypeError('A fetch function is required.');
  async function call(method, path, body) {
    // No credentials and no redirects, as the extension's own deliveries (extension src/background/swap.js:43).
    const init = { method, headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'omit', redirect: 'error' };
    if (body !== undefined) { init.body = body; init.headers['Content-Type'] = 'application/json'; }
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(timeoutMs);
    let res;
    try { res = await fetch(`${base}${path}`, init); } catch { return { ok: false, unreachable: true }; }
    let json = null;
    try { json = await res.json(); } catch { json = null; }
    return { ok: true, status: res.status, json };
  }
  return {
    base,
    status: () => call('GET', '/status'),
    quote: (direction, rawAmount) => call('POST', '/quote', quoteBody(direction, rawAmount)),
    swapState: requestNumber => call('GET', `/swap/${encodeURIComponent(String(requestNumber))}`),
    liquidityQuote: (side, rawAmount) => call('POST', '/liquidity/quote', liquidityQuoteBody(side, rawAmount)),
    liquidityWithdraw: signed => call('POST', '/liquidity/withdraw', withdrawBody(signed)),
  };
}
