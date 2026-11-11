// The swap and liquidity flows, with no DOM: the bot client, the adapter and the sleep are injected, so the
// order of the steps can be proved against stubs (plan section 19, line 666).
//
// Order of the swap (givens item 68; plan sections 7 and 8; section 18 change 2):
//   loadStatus()  GET /amm/status -- the price is shown                         (step 1)
//   [the user types an amount: nothing is sent anywhere]                        (step 2)
//   press()       POST /amm/quote -- ONLY on the user's press                   (step 3)
//   [the user chooses a tolerance; the minimum is computed on the site]         (step 4)
//   confirm()     the adapter -- ONLY on the user's yes (extension signs, sends, pays)  (steps 4, 5)
//   follow()      GET /amm/swap/<request number>, a bounded number of times     (step 8)
// The bot's answers are shown as given; nothing is verified (givens items 65, 69).

import {
  parseAmount, minimumToReceive, USDT_DECIMALS, NODUS_DECIMALS,
  readQuoteAnswer, readAddQuoteAnswer, refusalText, describeSwapState,
  buildWithdrawText, randomRequestNumber, liquidityMinNodusRaw, isTokenAddress,
} from './swap-logic.js';

// Bounded polling of GET /amm/swap/<id> (plan section 7 step 8). These are this build's values, not plan values:
// 240 reads, 5 s apart = 20 minutes (the bot's USDT payout is final only after payout_final_depth_eth = 64 Ethereum
// blocks, about 13 minutes at 12 s per block; the setting is the bot's, /amm/status does not carry it); after that the site says the swap is still pending and offers a new check.
export const POLL_MAX = 240;
export const POLL_INTERVAL_MS = 5000;

const AMOUNT_WORDS = {
  empty: 'Type an amount first.',
  format: 'The amount must be a number such as 100 or 12.5.',
  too_many_decimals: 'Too many decimal places for this token.',
  zero: 'The amount must be more than zero.',
  too_large: 'That amount is too large.',
};
const NOT_CONNECTED_TEXT = 'Connect the extension first.';
// The text of an extension step announced by the adapter (adapter.js, onStep). Numbered only where the site sees the
// boundary; a call that holds several extension windows says so and does not claim which one is open.
const WHERE = ' The window can open behind this browser window; if you do not see it, click the Nodus extension icon.';
export function stepText(step) {
  const head = step?.n ? `Step ${step.n} of ${step.of}: ` : '';
  switch (step?.id) {
    case 'switch': return `Switching the extension to the bot's Ethereum network. If it asks you to approve the switch, approve it.${WHERE}`;
    case 'hold': return `${head}approve holding your NODUS payment in the extension window.${WHERE}`;
    case 'sign_send': return `${head}approve the Nodus signature in the extension window. After that the extension sends your request to the bot and then your NODUS payment; this page cannot see those parts, so wait and do not press again.${WHERE}`;
    case 'usdt_windows': return `Approve in the extension: two extension windows, one after the other, the signed request and then the USDT payment. This page cannot see which one is open; wait and do not press again.${WHERE}`;
    case 'add_windows': return `${head}approve three extension windows, one after the other: the Ethereum signature, the Nodus signature, then the USDT payment. This page cannot see which one is open; wait and do not press again.${WHERE}`;
    default: return `Approve the request in the extension.${WHERE}`;
  }
}
export const amountProblem = reason => AMOUNT_WORDS[reason] ?? 'The amount is not valid.';

// An error from the adapter (adapter.js) in plain words.
// ctx.requestNumber: the request number of the price the user approved (named in a liquidity add's text).
export function describeAdapterError(err, ctx = {}) {
  if (err?.code === 'not_configured') return { text: 'The extension part of this action is not available yet. Nothing was signed or paid.' };
  if (err?.code === 'no_extension') return { text: 'The Nodus Connect extension was not found. Nothing was signed or paid.' };
  if (err?.code === 'no_token') return { text: 'The USDT contract address is not known to this page. Nothing was signed or paid.' };
  const out = {};
  // The extension's delivery result (givens item 88): the request did not reach the bot, so nothing was paid. Shown
  // plainly; never retried automatically, the user tries again.
  if (err?.delivered === false) {
    // givens item 57 ("the wallet shows the open one"): the bot refused this NEW request because an open approval with
    // the same sender and amount exists; its number is kept so the page follows that open swap.
    if (err.openRequestNumber != null) {
      out.openRequestNumber = String(err.openRequestNumber);
      out.text = `This new request paid nothing. You already have an open swap with the same amount (request ${out.openRequestNumber}); it is shown below.`;
      return out;
    }
    out.text = typeof err.reason === 'string' && err.answered
      ? `The bot did not take the request (${err.reason}). Nothing was paid. You can try again.`
      : 'The request did not reach the bot. Nothing was paid. You can try again.';
    return out;
  }
  // The bot already holds this request number (the request was delivered): the same approval can only produce a bot
  // refusal, so the site does not offer it again. Nothing is retried; the user asks for a new price.
  if (err?.delivered === true) {
    out.delivered = true;
    out.paid = err.paid;
    // A liquidity add: `paid` is the USDT half only; the NODUS half is `nodusSent` (extension swap.js:179-188). A
    // one-sided add matches no approval and is handled by the Foundation (givens items 32, 35).
    if (err.nodusSent === true || err.nodusSent === 'unknown') {
      out.oneSided = true;
      out.nodusSent = err.nodusSent;
      if (err.intentId !== undefined) out.intentId = err.intentId;
      if (err.transferId !== undefined) out.transferId = err.transferId;
      const number = ctx.requestNumber != null ? ` (request ${ctx.requestNumber})` : '';
      const nodus = err.nodusSent === true
        ? `Your NODUS payment was sent${err.transferId ? ` (transfer ${err.transferId})` : ''}.`
        : 'Your NODUS payment may have been sent.';
      const usdt = err.paid === 'unknown' ? 'Your USDT payment may have been sent.' : 'Your USDT payment was not sent.';
      out.text = `The bot has your liquidity add${number}. ${nodus} ${usdt} Do not pay again and do not ask for a new pair. ` +
        `Check the extension's activity. An add with one payment missing is handled by the Foundation: contact the Foundation with the request number.`;
      return out;
    }
    out.text = err.paid === 'unknown'
      ? 'The payment may have been sent. Do not pay again; check the extension\'s activity.'
      : 'The bot has your request but nothing was paid. Ask for a new price to try again.';
    return out;
  }
  if (err?.openRequestNumber != null) out.openRequestNumber = String(err.openRequestNumber);
  if (typeof err?.reason === 'string') out.text = refusalText(err.reason);
  else if ((err?.extensionCode ?? err?.code) === 4001) out.text = 'You rejected the request in the extension. Nothing was paid.';
  else out.text = `The extension did not finish: ${err?.message || 'unknown error'}. Check the extension before trying again.`;
  return out;
}

export function createSwapFlow({
  bot, adapter, signText,
  botUrl,     // the bot's own origin (BOT_ORIGIN, bot.js), https, no path: the extension appends /amm/swap itself (givens item 97)
  usdtToken,  // the USDT contract address, when /amm/status does not carry it (it does not today)
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  pollMax = POLL_MAX, pollIntervalMs = POLL_INTERVAL_MS,
  random,
} = {}) {
  // swapGen / addGen: bumped by every new question and by clearQuote, so an answer that arrives after the inputs changed
  // is discarded (givens item 68: the shown answer belongs to the amount the user chose). followGen: the newest follow
  // ends the older ones. pendingWithdraw: a signed withdrawal whose post outcome is uncertain, kept in memory only.
  const s = { accounts: null, status: null, quote: null, addQuote: null, swapGen: 0, addGen: 0, followGen: 0, pendingWithdraw: null };
  // The extension needs the USDT contract (`token`): the bot's `settings.usdtContract` from /amm/status, else the
  // `usdtToken` option. A status value that is present but not "0x" + 40 hex is NOT replaced by the option: it
  // gives no token, and the adapter refuses with no_token before anything is sent.
  const tokenOf = () => {
    const v = s.status?.settings?.usdtContract;
    if (v === undefined) return usdtToken;
    return isTokenAddress(v) ? v : undefined;
  };
  const minNodus = () => liquidityMinNodusRaw(s.status);

  async function jsonOf(res) {
    if (!res.ok) return { reason: 'unreachable' };
    if (res.json === null || typeof res.json !== 'object') return { reason: 'bad_answer' };
    return { json: res.json };
  }

  // One post of a signed withdrawal body (also the resend of a kept one).
  async function postWithdraw(w) {
    const r = await jsonOf(await bot.liquidityWithdraw(w.body));
    const answered = !r.reason && r.json && (r.json.received === true || typeof r.json.reason === 'string');
    if (!answered) {
      // unreachable or not readable: the bot may have received it. Keep the exact signed body for a resend.
      s.pendingWithdraw = w;
      return {
        ok: false, uncertain: true, reason: r.reason ?? 'bad_answer', requestNumber: w.requestNumber,
        text: `Your withdrawal was signed and sent, but the bot's answer did not arrive, so it may have been received (request ${w.requestNumber}). ` +
          'Press the button again to resend the same signed withdrawal; nothing new is signed.',
      };
    }
    s.pendingWithdraw = null;   // a definite answer: nothing is kept
    if (r.json.received === true) return { ok: true, requestNumber: String(r.json.requestNumber ?? w.requestNumber) };
    if (r.json.reason === 'number_reused') {
      return { ok: true, alreadyReceived: true, requestNumber: w.requestNumber, text: `The bot already has this withdrawal (request ${w.requestNumber}).` };
    }
    return { ok: false, reason: r.json.reason, text: refusalText(r.json.reason) };
  }

  return {
    state: s,
    // A change of the connected account drops a kept signed withdrawal (it is signed by the other account).
    setAccounts(accounts) {
      if (s.pendingWithdraw && s.pendingWithdraw.account !== accounts?.nodus?.address) s.pendingWithdraw = null;
      s.accounts = accounts;
    },
    // The add minimum in force, raw NODUS: the status value, else the fallback constant (swap-logic.js).
    liquidityMin: minNodus,
    // kind: 'swap', 'add' or nothing for both. Also discards an answer still being awaited.
    clearQuote(kind) {
      if (kind !== 'add') { s.quote = null; s.swapGen++; }
      if (kind !== 'swap') { s.addQuote = null; s.addGen++; }
    },
    // The request number of a signed withdrawal waiting to be resent, or null.
    pendingWithdrawNumber() { return s.pendingWithdraw ? s.pendingWithdraw.requestNumber : null; },

    // GET /amm/status (step 1). The answer is kept for the chain ids, addresses and settings the site needs.
    async loadStatus() {
      const r = await jsonOf(await bot.status());
      if (r.reason) return { ok: false, reason: r.reason };
      const j = r.json;
      if (typeof j.foundationNodus !== 'string' || typeof j.nodusChainId !== 'string' || typeof j.settings !== 'object' || j.settings === null) {
        return { ok: false, reason: 'bad_answer' };
      }
      s.status = j;
      return { ok: true, status: j };
    },

    // Step 3: the ONLY place the swap question is sent. Nothing is sent when the extension is not connected (givens
    // item 68: the question follows the connect) or when the amount is not a valid number.
    async press({ direction, amountText }) {
      if (!s.accounts) return { ok: false, reason: 'not_ready', text: NOT_CONNECTED_TEXT };
      const gen = ++s.swapGen;
      const decimals = direction === 'usdt_to_nodus' ? USDT_DECIMALS : NODUS_DECIMALS;
      const p = parseAmount(amountText, decimals);
      if (!p.ok) return { ok: false, local: true, reason: p.reason, text: amountProblem(p.reason) };
      s.quote = null;
      const res = await bot.quote(direction, p.raw);
      if (gen !== s.swapGen) return { ok: false, stale: true, reason: 'stale', text: '' };   // inputs changed while waiting
      const r = await jsonOf(res);
      if (r.reason) return { ok: false, reason: r.reason, text: refusalText(r.reason) };
      const a = readQuoteAnswer(r.json);
      if (!a.approved) return { ok: false, reason: a.reason, text: refusalText(a.reason) };
      s.quote = { ...a.quote, direction, amountRaw: p.raw };
      return { ok: true, quote: s.quote };
    },

    // Step 4: the minimum to receive, from the bot's number, its estimated fee and the user's tolerance.
    minimumFor(toleranceBps) {
      if (!s.quote) throw new Error('Ask the bot for a price first.');
      return minimumToReceive(s.quote.number, s.quote.estimatedFee, toleranceBps);
    },

    // Steps 4-5: the user's yes. The adapter is called once, here; the extension signs, sends the signed request
    // to the bot and pays only if the request reached the bot (givens items 84, 88).
    async confirm({ toleranceBps, onStep }) {
      const q = s.quote;
      if (!q || !s.accounts || !s.status) return { ok: false, reason: 'not_ready', text: 'Connect the extension and ask for a price first.' };
      const min = minimumToReceive(q.number, q.estimatedFee, toleranceBps);
      try {
        if (q.direction === 'usdt_to_nodus') {
          await adapter.usdtToNodus({
            botUrl, ethereumAddress: s.accounts.ethereum, nodusAddress: s.accounts.nodus.address, token: tokenOf(), payTo: q.payTo,
            amountUsdtRaw: q.amountRaw, minimumNodusRaw: min, requestNumber: q.requestNumber,
            ethChainId: s.status.settings.ethChainId,
          }, { onStep });
        } else {
          await adapter.nodusToUsdt({
            botUrl, nodusAddress: s.accounts.nodus.address, ethereumAddress: s.accounts.ethereum, payTo: q.payTo,
            amountNodusRaw: q.amountRaw, minimumUsdtRaw: min, requestNumber: q.requestNumber,
          }, { onStep });
        }
      } catch (err) {
        const info = describeAdapterError(err);
        // delivered: the price is spent (the bot holds the request number); the site follows the swap instead
        if (info.delivered) { s.quote = null; return { ok: false, reason: 'delivered', requestNumber: q.requestNumber, ...info }; }
        return { ok: false, reason: err?.code ?? 'extension_error', ...info };
      }
      return { ok: true, requestNumber: q.requestNumber, minimum: min };
    },

    // Step 8: GET /amm/swap/<request number>, at most `pollMax` reads. A non-final state, an unreadable answer or an
    // unreachable bot is "pending", never "failed". `onState({ info, answer, poll })` is called after every read.
    // Starting a new follow (or stopFollow) ends the older one: its later reads, its onState calls and its result no
    // longer count; it returns { final: false, stopped: true } and the caller must not touch the panel for it.
    // `shouldStop` is an optional extra check of the caller.
    async follow(requestNumber, onState = () => {}, shouldStop = () => false) {
      const gen = ++s.followGen;
      const stale = () => gen !== s.followGen || shouldStop();
      let last = null;
      for (let i = 1; i <= pollMax; i++) {
        const res = await bot.swapState(requestNumber);
        if (stale()) return { final: false, stopped: true };
        let info, answer = null;
        if (res.ok && res.json && typeof res.json.state === 'string') {
          answer = res.json;
          info = describeSwapState(answer);
        } else {
          info = { final: false, kind: 'pending', state: '', text: 'Waiting for the bot\'s answer.' };
        }
        last = { info, answer, poll: i };
        onState(last);
        if (info.final) return { final: true, ...last };
        if (i < pollMax) { await sleep(pollIntervalMs); if (stale()) return { final: false, stopped: true }; }
      }
      return { final: false, exhausted: true, ...last };
    },
    stopFollow() { s.followGen++; },

    // ── liquidity ──────────────────────────────────────────────────────

    // POST /amm/liquidity/quote: the amount of ONE side; the bot answers with the exact pair at its ratio.
    async pressAdd({ side, amountText }) {
      if (!s.accounts) return { ok: false, reason: 'not_ready', text: NOT_CONNECTED_TEXT };
      const gen = ++s.addGen;
      const decimals = side === 'usdt' ? USDT_DECIMALS : NODUS_DECIMALS;
      const p = parseAmount(amountText, decimals);
      if (!p.ok) return { ok: false, local: true, reason: p.reason, text: amountProblem(p.reason) };
      s.addQuote = null;
      const res = await bot.liquidityQuote(side, p.raw);
      if (gen !== s.addGen) return { ok: false, stale: true, reason: 'stale', text: '' };
      const r = await jsonOf(res);
      if (r.reason) return { ok: false, reason: r.reason, text: refusalText(r.reason, 'add', minNodus()) };
      const a = readAddQuoteAnswer(r.json);
      if (!a.approved) return { ok: false, reason: a.reason, text: refusalText(a.reason, 'add', minNodus()) };
      s.addQuote = a.quote;
      return { ok: true, quote: s.addQuote };
    },

    // The user's yes on an add: the extension signs both halves, sends them to the bot and pays both sides only if
    // they reached the bot (plan 6.4.6 steps (3), (4)).
    async confirmAdd({ onStep } = {}) {
      const q = s.addQuote;
      if (!q || !s.accounts || !s.status) return { ok: false, reason: 'not_ready', text: 'Connect the extension and ask for an amount first.' };
      try {
        await adapter.liquidityAdd({
          botUrl, ethereumAddress: s.accounts.ethereum, nodusAddress: s.accounts.nodus.address, token: tokenOf(),
          payEthereum: q.payEthereum, payNodus: q.payNodus, usdtAmountRaw: q.usdtAmount, nodusAmountRaw: q.nodusAmount,
          requestNumber: q.requestNumber, ethChainId: s.status.settings.ethChainId,
        }, { onStep });
      } catch (err) {
        const info = describeAdapterError(err, { requestNumber: q.requestNumber });
        if (info.delivered) { s.addQuote = null; return { ok: false, reason: 'delivered', requestNumber: q.requestNumber, ...info }; }
        return { ok: false, reason: err?.code ?? 'extension_error', ...info };
      }
      return { ok: true, requestNumber: q.requestNumber };
    },

    // Withdraw (plan 6.4.6): the Nodus key signs the text with the EXISTING method nodus_signMessage, and the site
    // posts it to POST /amm/liquidity/withdraw. Basis points 1..10000 of the provider's position.
    //
    // After signing, a post whose outcome is unknown (unreachable, or an answer that is not readable JSON) may have been
    // received. The exact signed body is then kept IN MEMORY ONLY (a page reload loses it: a recorded residual) and the
    // next call resends the SAME body: no new signature, no new request number. The bot answers a resent, already
    // accepted body with "number_reused" (amm_http.c:301), which is shown as "already received", not as a failure. A
    // JSON refusal with a reason is definite and drops the kept body.
    async withdraw({ basisPoints }) {
      if (!s.accounts || !s.status) return { ok: false, reason: 'not_ready', text: 'Connect the extension first.' };
      const pending = s.pendingWithdraw && s.pendingWithdraw.account === s.accounts.nodus.address ? s.pendingWithdraw : null;
      if (pending) return postWithdraw(pending);
      let text;
      try {
        text = buildWithdrawText({
          ethereumAddress: s.accounts.ethereum, nodusAddress: s.accounts.nodus.address, basisPoints,
          chainId: s.status.nodusChainId, requestNumber: random ? random() : randomRequestNumber(),
        });
      } catch {
        return { ok: false, reason: 'bad_request', text: 'The share must be a whole number of basis points from 1 to 10000.' };
      }
      let signature;
      try { signature = await signText(text, s.accounts.nodus.address); }
      catch (err) { return { ok: false, reason: 'extension_error', ...describeAdapterError(err) }; }
      const requestNumber = text.slice(text.lastIndexOf('Request Number: ') + 'Request Number: '.length);
      return postWithdraw({ account: s.accounts.nodus.address, requestNumber, body: { text, publicKey: s.accounts.nodus.publicKey, signature } });
    },
  };
}
