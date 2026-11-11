import { rpcErrors, providerErrors } from '@metamask/rpc-errors';
import { getAddress } from 'ethers';
import { SWAP_METHODS, SWAP_PATHS, assertSwapUsdtToken } from '../constants/swap.js';
import { HEX128, botOrigin, liquidityAddTyped, lowerHex, parseLiquidityAddText, parseNodusToUsdtText, rawAmount, usdtToNodusTyped } from './swap-texts.js';

// The swap and the liquidity add on the extension side (plan 2026-11-08-swap-bot-plan.nodus1.md section 18 change 1;
// givens items 84, 88, 97): the extension that pays signs the user's request, posts it to the bot itself, at the
// address the site names with each request (item 97), and pays ONLY if that request reached the bot. If it did not,
// nothing is paid and the site is told so (item 88: "İstek bota ulaşmadıysa para da gitmez, kullanıcı tekrar dener.").
// The bot's answer is a delivery result, not a second acceptance (items 83, 88).
//
// What "reached the bot" means here (my choice; the plan says "an HTTP answer was received from the bot" and
// the test of plan section 19 names a bot that "answers an error"): an HTTP success answer whose JSON body says
// `"received":true`, the bot's own delivery result (amm_http.h:25-27, amm_http.c:354-361). A refused connection, a
// timeout, a redirect, any other status (a forwarder's 502 or 504 is not the bot), or `"received":false` (the bot
// refusing the request with a reason) does NOT reach the bot, so nothing is paid.

const DELIVERY_TIMEOUT_MS = 15000;
const MAX_ANSWER_BYTES = 65536;
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const hexText = text => `0x${hex(new TextEncoder().encode(text))}`;

function oneObject(params, keys) {
  const request = Array.isArray(params) && params.length === 1 ? params[0] : undefined;
  if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).length !== keys.length || !keys.every(key => Object.hasOwn(request, key))) {
    throw rpcErrors.invalidParams(`Expected one object with exactly: ${keys.join(', ')}.`);
  }
  return request;
}
function evmAddress(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw rpcErrors.invalidParams(`${label} must be an Ethereum address.`);
  try { return getAddress(value); } catch { throw rpcErrors.invalidParams(`${label} is not a valid Ethereum address.`); }
}
const mismatch = () => rpcErrors.invalidParams('The request text does not match the request or the held payment.');

// One POST of the signed request. Never retried here (givens item 88: the user tries again).
async function deliver(origin, path, body) {
  let response;
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);
  try {
    try {
      response = await fetch(`${origin}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
        signal: controller.signal, redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
    } catch { return { reached: false, answered: false, reason: 'unreachable' }; }
    return await classify(response, await readAnswer(response, controller));
  } finally { clearTimeout(timer); }
}
// The answer is read through a reader and counted in bytes: a host that streams more than MAX_ANSWER_BYTES (or announces
// more in Content-Length) is cut off at once, the body cancelled and the request aborted, and the answer counts as
// not JSON. The service worker never holds more than the cap.
async function readAnswer(response, controller) {
  const cut = async () => { try { await response.body?.cancel(); } catch { /* already closed */ } controller.abort(); return null; };
  try {
    const announced = response.headers.get('content-length');
    if (announced !== null && !(/^\d+$/.test(announced) && Number(announced) <= MAX_ANSWER_BYTES)) return await cut();
    if (!response.body) return null;
    const reader = response.body.getReader(), chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_ANSWER_BYTES) { try { await reader.cancel(); } catch { /* already closed */ } controller.abort(); return null; }
      chunks.push(value);
    }
    const joined = new Uint8Array(total); let at = 0;
    for (const chunk of chunks) { joined.set(chunk, at); at += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(joined));
  } catch { return null; /* an answer that is not JSON, or a body that failed */ }
}
function classify(response, answer) {
  if (response.ok && answer?.received === true) return { reached: true, answered: true, answer };
  const word = typeof answer?.reason === 'string' && /^[a-z_]{1,40}$/.test(answer.reason) ? answer.reason : `http_${response.status}`;
  // The open-approval refusal names the open swap (givens item 57; amm_http.c:355-372); the bot's number is a u32
  // (amm_http.c:599), so only a canonical decimal string 1..4294967295 is passed on.
  const open = word === 'open_approval' && typeof answer.openRequestNumber === 'string' && /^[1-9]\d{0,9}$/.test(answer.openRequestNumber) && BigInt(answer.openRequestNumber) <= 4294967295n
    ? { openRequestNumber: answer.openRequestNumber } : {};
  return { reached: false, answered: true, reason: word, ...open };
}
function notDelivered(result) {
  return rpcErrors.internal({ message: result.answered ? `The bot did not take the request (${result.reason}). Nothing was paid.` : 'The request did not reach the bot. Nothing was paid.',
    data: { delivered: false, paid: false, answered: result.answered, reason: result.reason, ...(result.openRequestNumber ? { openRequestNumber: result.openRequestNumber } : {}) } });
}
// A failure after the request was delivered: nothing is rolled back (the bot keeps its approval until it expires),
// and the site is told exactly what was and was not sent. A broadcast that failed after it was recorded may have
// reached the network: `paid` is then 'unknown' (evm.js sendRecorded marks it activityTracked).
function afterDelivery(error, sent = {}) {
  // `broadcastReached` is set by evm.js / nodus.js once the pending record was durable, whatever the error was afterwards.
  const uncertain = error?.data?.activityTracked === true || error?.broadcastReached === true;
  const data = { delivered: true, paid: uncertain ? 'unknown' : false, ...sent };
  if (error?.code === 4001) return providerErrors.userRejectedRequest({ message: 'You rejected the payment. The bot has your request; it expires unpaid.', data });
  return rpcErrors.internal({ message: `The bot has your request but the payment was not completed: ${error?.message ?? 'unknown error'}`, data });
}

export function createSwap({ evm, nodus }) {
  // USDT -> NODUS (plan section 7 steps 4-5): the typed request of 6.4.3 is signed, posted (`POST /amm/swap`, 6.4.7),
  // then the USDT `transfer(FoundationAddress, amount)` is paid.
  async function sendUsdtToNodus(origin, params) {
    const request = oneObject(params, ['from', 'botUrl', 'token', 'payTo', 'destination', 'amount', 'minimumToReceive', 'requestNumber']);
    const bot = botOrigin(request.botUrl), from = evmAddress(request.from, 'from'), token = evmAddress(request.token, 'token'), payTo = evmAddress(request.payTo, 'payTo');
    const destination = lowerHex(request.destination, HEX128, 'destination');
    const amount = rawAmount(request.amount, 'amount', { positive: true }), minimum = rawAmount(request.minimumToReceive, 'minimumToReceive'), number = rawAmount(request.requestNumber, 'requestNumber');
    const session = evm.swapSession(origin, from);
    if (getAddress(session.account) !== from) throw providerErrors.unauthorized();
    assertSwapUsdtToken(session.chain, token); // before any signature, post or payment
    const sender = from.toLowerCase();
    const fields = { sender, destination, amount: amount.toString(), minimumToReceive: minimum.toString(), requestNumber: number.toString() };
    const signature = await session.signTyped(usdtToNodusTyped({ chainId: session.chainId, ...fields }));
    const result = await deliver(bot, SWAP_PATHS.swap, { kind: 'usdt_to_nodus', ...fields, signature });
    if (!result.reached) throw notDelivered(result);
    try {
      const payment = await session.approveUsdtPayment({ token, to: payTo, amount, bot });
      return { delivered: true, paid: true, hash: await payment.send(), answer: result.answer };
    } catch (error) { throw afterDelivery(error); }
  }

  // The held NODUS transfer of a request text (NODUS -> USDT 6.4.4, liquidity add 6.4.6): the text must name exactly the
  // transfer the extension holds, so what the user signs is what is paid.
  function holdFor(origin, holdId) {
    if (typeof holdId !== 'string') throw rpcErrors.invalidParams('holdId must be a string.');
    return nodus.getHold(origin, holdId);
  }
  // A hold that is already past its expiry is refused before anything is signed or posted.
  async function usableHold(origin, holdId) {
    try { return await nodus.checkHold(origin, holdId); } catch (error) { nodus.cancelHold(origin, holdId); throw error; }
  }
  async function signHeldText(origin, hold, text) {
    const signature = await nodus.signMessage(origin, [hexText(text), hold.account]);
    return { text: hexText(text), publicKey: nodus.getAccount().publicKey, signature };
  }

  // NODUS -> USDT (plan section 8 steps 4-5): the transfer was built and signed unsent (holdTransfer); its text is
  // signed, posted (`POST /amm/swap`), and the held transfer is sent only after the request reached the bot.
  async function sendNodusToUsdt(origin, params) {
    const request = oneObject(params, ['holdId', 'botUrl', 'text']);
    const bot = botOrigin(request.botUrl), hold = holdFor(origin, request.holdId), fields = parseNodusToUsdtText(request.text);
    if (fields.sender !== hold.account || fields.amount !== hold.amount || fields.transferId !== hold.wireId || fields.chainId !== hold.chainId) throw mismatch();
    await usableHold(origin, request.holdId);
    let result;
    try {
      const signed = await signHeldText(origin, hold, request.text);
      result = await deliver(bot, SWAP_PATHS.swap, { kind: 'nodus_to_usdt', ...signed });
    } catch (error) { nodus.cancelHold(origin, request.holdId); throw error; }
    if (!result.reached) { nodus.cancelHold(origin, request.holdId); throw notDelivered(result); }
    try {
      const sent = await nodus.sendHeld(origin, request.holdId);
      return { delivered: true, paid: true, intentId: sent.intentId, transferId: sent.transferId, answer: result.answer };
    } catch (error) { nodus.cancelHold(origin, request.holdId); throw afterDelivery(error); }
  }

  // Liquidity add (plan 6.4.6 steps (3), (4)): both halves signed and posted with the flat body of amm_http.h:44-51,
  // both payments only after the post reached the bot. The USDT payment is approved by the user first, then the
  // time-limited NODUS transfer is sent, then the USDT (my choice of order: the plan says "in either order"; this one
  // leaves nothing sent when the held transfer has expired or the user refuses the USDT payment).
  async function sendLiquidityAdd(origin, params) {
    const request = oneObject(params, ['holdId', 'botUrl', 'ethereumAddress', 'token', 'payTo', 'usdtAmount', 'nodusAmount', 'requestNumber', 'text']);
    const bot = botOrigin(request.botUrl), hold = holdFor(origin, request.holdId), ethereumAddress = evmAddress(request.ethereumAddress, 'ethereumAddress');
    const token = evmAddress(request.token, 'token'), payTo = evmAddress(request.payTo, 'payTo');
    const usdt = rawAmount(request.usdtAmount, 'usdtAmount', { positive: true }), nodusAmount = rawAmount(request.nodusAmount, 'nodusAmount', { positive: true });
    const number = rawAmount(request.requestNumber, 'requestNumber'), fields = parseLiquidityAddText(request.text);
    if (fields.ethereumAddress !== ethereumAddress.toLowerCase() || fields.nodusAddress !== hold.account || fields.usdtAmount !== usdt || fields.nodusAmount !== nodusAmount ||
      nodusAmount !== hold.amount || fields.requestNumber !== number || fields.transferId !== hold.wireId || fields.chainId !== hold.chainId) throw mismatch();
    await usableHold(origin, request.holdId);
    let session, result;
    try {
      session = evm.swapSession(origin, ethereumAddress);
      if (getAddress(session.account) !== ethereumAddress) throw providerErrors.unauthorized();
      assertSwapUsdtToken(session.chain, token); // before any signature, post or payment
      const ethSignature = await session.signTyped(liquidityAddTyped({ chainId: session.chainId, ethereumAddress: ethereumAddress.toLowerCase(), nodusAddress: hold.account,
        usdtAmount: usdt.toString(), nodusAmount: nodusAmount.toString(), requestNumber: number.toString() }));
      const signed = await signHeldText(origin, hold, request.text);
      result = await deliver(bot, SWAP_PATHS.liquidityAdd, { ethereumAddress: ethereumAddress.toLowerCase(), nodusAddress: hold.account, usdtAmount: usdt.toString(),
        nodusAmount: nodusAmount.toString(), requestNumber: number.toString(), ethSignature, text: signed.text, publicKey: signed.publicKey, nodusSignature: signed.signature });
    } catch (error) { nodus.cancelHold(origin, request.holdId); throw error; }
    if (!result.reached) { nodus.cancelHold(origin, request.holdId); throw notDelivered(result); }
    let payment, sent;
    try {
      payment = await session.approveUsdtPayment({ token, to: payTo, amount: usdt, bot });
      sent = await nodus.sendHeld(origin, request.holdId);
    } catch (error) { nodus.cancelHold(origin, request.holdId); throw afterDelivery(error, { nodusSent: error?.broadcastReached === true ? 'unknown' : false }); }
    try {
      return { delivered: true, nodusPaid: true, usdtPaid: true, hash: await payment.send(), intentId: sent.intentId, transferId: sent.transferId, answer: result.answer };
    } catch (error) { throw afterDelivery(error, { nodusSent: true, intentId: sent.intentId, transferId: sent.transferId }); }
  }

  return {
    handle(method, origin, params) {
      switch (method) {
        case SWAP_METHODS.holdTransfer: return nodus.holdTransfer(origin, params);
        case SWAP_METHODS.sendNodusToUsdt: return sendNodusToUsdt(origin, params);
        case SWAP_METHODS.sendUsdtToNodus: return sendUsdtToNodus(origin, params);
        case SWAP_METHODS.sendLiquidityAdd: return sendLiquidityAdd(origin, params);
        default: throw rpcErrors.methodNotFound();
      }
    },
  };
}
