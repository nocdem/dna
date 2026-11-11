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
// 120 reads, 5 s apart = 10 minutes; after that the site says the swap is still pending and offers a new check.
export const POLL_MAX = 120;
export const POLL_INTERVAL_MS = 5000;

const AMOUNT_WORDS = {
  empty: 'Type an amount first.',
  format: 'The amount must be a number such as 100 or 12.5.',
  too_many_decimals: 'Too many decimal places for this token.',
  zero: 'The amount must be more than zero.',
  too_large: 'That amount is too large.',
};
export const amountProblem = reason => AMOUNT_WORDS[reason] ?? 'The amount is not valid.';

// An error from the adapter (adapter.js) in plain words.
export function describeAdapterError(err) {
  if (err?.code === 'not_configured') return { text: 'The extension part of this action is not available yet. Nothing was signed or paid.' };
  if (err?.code === 'no_extension') return { text: 'The Nodus Connect extension was not found. Nothing was signed or paid.' };
  if (err?.code === 'no_token') return { text: 'The USDT contract address is not known to this page. Nothing was signed or paid.' };
  const out = {};
  // The extension's delivery result (givens item 88): the request did not reach the bot, so nothing was paid. Shown
  // plainly; never retried automatically, the user tries again.
  if (err?.delivered === false) {
    out.text = typeof err.reason === 'string' && err.answered
      ? `The bot did not take the request (${err.reason}). Nothing was paid. You can try again.`
      : 'The request did not reach the bot. Nothing was paid. You can try again.';
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
  botUrl,     // the site's own origin, https, no path: the extension appends /amm/swap itself (givens item 97)
  usdtToken,  // the USDT contract address, when /amm/status does not carry it (it does not today)
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  pollMax = POLL_MAX, pollIntervalMs = POLL_INTERVAL_MS,
  random,
} = {}) {
  const s = { accounts: null, status: null, quote: null, addQuote: null };
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

  return {
    state: s,
    setAccounts(accounts) { s.accounts = accounts; },
    // kind: 'swap', 'add' or nothing for both
    // The add minimum in force, raw NODUS: the status value, else the fallback constant (swap-logic.js).
    liquidityMin: minNodus,
    clearQuote(kind) {
      if (kind !== 'add') s.quote = null;
      if (kind !== 'swap') s.addQuote = null;
    },

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

    // Step 3: the ONLY place the swap question is sent. Nothing is sent when the amount is not a valid number.
    async press({ direction, amountText }) {
      const decimals = direction === 'usdt_to_nodus' ? USDT_DECIMALS : NODUS_DECIMALS;
      const p = parseAmount(amountText, decimals);
      if (!p.ok) return { ok: false, local: true, reason: p.reason, text: amountProblem(p.reason) };
      s.quote = null;
      const r = await jsonOf(await bot.quote(direction, p.raw));
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
    async confirm({ toleranceBps }) {
      const q = s.quote;
      if (!q || !s.accounts || !s.status) return { ok: false, reason: 'not_ready', text: 'Connect the extension and ask for a price first.' };
      const min = minimumToReceive(q.number, q.estimatedFee, toleranceBps);
      try {
        if (q.direction === 'usdt_to_nodus') {
          await adapter.usdtToNodus({
            botUrl, ethereumAddress: s.accounts.ethereum, nodusAddress: s.accounts.nodus.address, token: tokenOf(), payTo: q.payTo,
            amountUsdtRaw: q.amountRaw, minimumNodusRaw: min, requestNumber: q.requestNumber,
            ethChainId: s.status.settings.ethChainId,
          });
        } else {
          await adapter.nodusToUsdt({
            botUrl, nodusAddress: s.accounts.nodus.address, ethereumAddress: s.accounts.ethereum, payTo: q.payTo,
            amountNodusRaw: q.amountRaw, minimumUsdtRaw: min, requestNumber: q.requestNumber,
          });
        }
      } catch (err) {
        return { ok: false, reason: err?.code ?? 'extension_error', ...describeAdapterError(err) };
      }
      return { ok: true, requestNumber: q.requestNumber, minimum: min };
    },

    // Step 8: GET /amm/swap/<request number>, at most `pollMax` reads. A non-final state, an unreadable answer or an
    // unreachable bot is "pending", never "failed". `onState({ info, answer, poll })` is called after every read.
    async follow(requestNumber, onState = () => {}) {
      let last = null;
      for (let i = 1; i <= pollMax; i++) {
        const res = await bot.swapState(requestNumber);
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
        if (i < pollMax) await sleep(pollIntervalMs);
      }
      return { final: false, exhausted: true, ...last };
    },

    // ── liquidity ──────────────────────────────────────────────────────

    // POST /amm/liquidity/quote: the amount of ONE side; the bot answers with the exact pair at its ratio.
    async pressAdd({ side, amountText }) {
      const decimals = side === 'usdt' ? USDT_DECIMALS : NODUS_DECIMALS;
      const p = parseAmount(amountText, decimals);
      if (!p.ok) return { ok: false, local: true, reason: p.reason, text: amountProblem(p.reason) };
      s.addQuote = null;
      const r = await jsonOf(await bot.liquidityQuote(side, p.raw));
      if (r.reason) return { ok: false, reason: r.reason, text: refusalText(r.reason, 'add', minNodus()) };
      const a = readAddQuoteAnswer(r.json);
      if (!a.approved) return { ok: false, reason: a.reason, text: refusalText(a.reason, 'add', minNodus()) };
      s.addQuote = a.quote;
      return { ok: true, quote: s.addQuote };
    },

    // The user's yes on an add: the extension signs both halves, sends them to the bot and pays both sides only if
    // they reached the bot (plan 6.4.6 steps (3), (4)).
    async confirmAdd() {
      const q = s.addQuote;
      if (!q || !s.accounts || !s.status) return { ok: false, reason: 'not_ready', text: 'Connect the extension and ask for an amount first.' };
      try {
        await adapter.liquidityAdd({
          botUrl, ethereumAddress: s.accounts.ethereum, nodusAddress: s.accounts.nodus.address, token: tokenOf(),
          payEthereum: q.payEthereum, payNodus: q.payNodus, usdtAmountRaw: q.usdtAmount, nodusAmountRaw: q.nodusAmount,
          requestNumber: q.requestNumber, ethChainId: s.status.settings.ethChainId,
        });
      } catch (err) {
        return { ok: false, reason: err?.code ?? 'extension_error', ...describeAdapterError(err) };
      }
      return { ok: true, requestNumber: q.requestNumber };
    },

    // Withdraw (plan 6.4.6): the Nodus key signs the text with the EXISTING method nodus_signMessage, and the site
    // posts it to POST /amm/liquidity/withdraw. Basis points 1..10000 of the provider's position.
    async withdraw({ basisPoints }) {
      if (!s.accounts || !s.status) return { ok: false, reason: 'not_ready', text: 'Connect the extension first.' };
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
      const r = await jsonOf(await bot.liquidityWithdraw({ text, publicKey: s.accounts.nodus.publicKey, signature }));
      if (r.reason) return { ok: false, reason: r.reason, text: refusalText(r.reason) };
      if (r.json.received === true) return { ok: true, requestNumber: String(r.json.requestNumber ?? '') };
      const reason = typeof r.json.reason === 'string' ? r.json.reason : 'bad_answer';
      return { ok: false, reason, text: refusalText(reason) };
    },
  };
}
