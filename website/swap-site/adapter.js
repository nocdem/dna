// THE ADAPTER: the only module that calls the Nodus Connect extension's NEW site methods (plan section 18
// change 1; givens items 84, 88). Everything else on the site uses the extension's existing methods through
// extension.js. The swap site does not sign and does not pay: it tells the extension what to do (givens item 67)
// and the extension signs, posts the signed request to the bot itself, and pays only if the request reached the bot
// (givens items 84, 88).
//
// Method names and parameter shapes are the extension package's (worktree main-swapext, read before wiring):
//   web-wallet/extension/src/constants/swap.js        method names
//   web-wallet/extension/site-sdk/README.md           "Swap and liquidity add"
//   web-wallet/extension/src/background/swap.js       checks and error.data
//   web-wallet/extension/src/background/swap-texts.js text forms (the extension builds the typed data itself)
//   web-wallet/extension/src/background/nodus.js:529-540  holdTransfer parameters
// Each call is provider.request({ method, params: [object] }). The objects carry exactly the listed keys.
//
// botUrl is the site's own origin, an https address WITHOUT a path (the extension appends /amm/swap and
// /amm/liquidity/add itself; givens item 97, "Adresi site her istekte söylesin.").
export const EXTENSION_CALLS = {
  // USDT -> NODUS: signs the typed request, posts it, then pays `amount` USDT of `token` to `payTo`.
  usdtToNodus: {
    method: 'nodus_swapSendUsdtToNodus',
    params: i => [{ from: i.from, botUrl: i.botUrl, token: i.token, payTo: i.payTo, destination: i.destination, amount: i.amount, minimumToReceive: i.minimumToReceive, requestNumber: i.requestNumber }],
  },
  // NODUS step A: build and sign a NODUS transfer of `amount` raw units to `to`, keep it unsent.
  nodusHold: {
    method: 'nodus_swapHoldTransfer',
    params: i => [{ account: i.account, to: i.to, amount: i.amount }],
    interpret: result => ({ holdId: result.holdId, transferId: result.transferId, chainId: result.chainId }),
  },
  // NODUS -> USDT step B: signs `text`, posts it, then sends the held transfer.
  nodusToUsdt: {
    method: 'nodus_swapSendNodusToUsdt',
    params: i => [{ holdId: i.holdId, botUrl: i.botUrl, text: i.text }],
  },
  // Liquidity add: signs both halves, posts the flat add body, then sends both payments.
  liquidityAdd: {
    method: 'nodus_swapSendLiquidityAdd',
    params: i => [{ holdId: i.holdId, botUrl: i.botUrl, ethereumAddress: i.ethereumAddress, token: i.token, payTo: i.payTo, usdtAmount: i.usdtAmount, nodusAmount: i.nodusAmount, requestNumber: i.requestNumber, text: i.text }],
  },
};

// What this module gives the rest of the site:
//   adapter.usdtToNodus(input) / adapter.nodusToUsdt(input) / adapter.liquidityAdd(input)
//     -> Promise<{ delivered: true, result }> when the extension finished (it paid only after the bot received the
//        request), or rejects with an AdapterError:
//          code 'not_configured'   a constant above is not filled in; nothing was sent
//          code 'no_extension'     no extension answered
//          code 'no_token'         the USDT contract address was not given; nothing was sent
//          code 'extension_error'  the extension refused or failed (user rejection included). Fields copied from the
//                                  extension's error and its `data`: `extensionCode`, `delivered` and `paid`
//                                  ({ delivered: false, paid: false } = the request did not reach the bot, nothing was
//                                  paid, never retried automatically, givens item 88), `answered`, `reason`
//                                  (the bot's refusal word), `openRequestNumber` (not set by this extension build),
//                                  and `cause`.
import { buildNodusToUsdtText, buildLiquidityAddText, toBig } from './swap-logic.js';

export class AdapterError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'AdapterError';
    this.code = code;
    Object.assign(this, extra);
  }
}

const raw = v => toBig(v).toString(); // raw units cross to the extension as decimal strings (no BigInt over messaging)
const RE_TOKEN = /^0x[0-9a-fA-F]{40}$/;
function needToken(token) {
  if (typeof token !== 'string' || !RE_TOKEN.test(token)) {
    throw new AdapterError('no_token', 'The USDT contract address is not known. Nothing was signed or paid.');
  }
  return token;
}

// getProvider: async () => the EIP-1193 provider of the extension, or null.
// calls: EXTENSION_CALLS by default; tests may pass their own.
export function createAdapter({ getProvider, calls = EXTENSION_CALLS } = {}) {
  // Refuses before anything is sent to the extension, so a half-configured adapter never opens an approval.
  function assertConfigured(...names) {
    for (const name of names) {
      const spec = calls[name];
      if (!spec || typeof spec.method !== 'string' || spec.method === '' || typeof spec.params !== 'function' ||
          (name === 'nodusHold' && typeof spec.interpret !== 'function')) {
        throw new AdapterError('not_configured', `The extension call "${name}" is not defined yet.`);
      }
    }
  }
  async function request(provider, method, params) {
    try {
      return await provider.request({ method, params });
    } catch (cause) {
      const d = cause?.data && typeof cause.data === 'object' ? cause.data : {};
      throw new AdapterError('extension_error', cause?.message || 'The extension did not complete the request.', {
        cause, extensionCode: cause?.code, delivered: d.delivered, paid: d.paid, answered: d.answered,
        // liquidity add: `paid` is the USDT half only; the NODUS half is nodusSent (true, false or 'unknown'), with the
        // held transfer's ids when it was sent (extension swap.js:179-188)
        nodusSent: d.nodusSent, intentId: d.intentId, transferId: d.transferId,
        reason: cause?.reason ?? d.reason, openRequestNumber: cause?.openRequestNumber ?? d.openRequestNumber,
      });
    }
  }
  async function run(name, input) {
    assertConfigured(name);
    const spec = calls[name];
    const provider = await getProvider();
    if (!provider) throw new AdapterError('no_extension', 'The Nodus Connect extension was not found.');
    return request(provider, spec.method, spec.params(input));
  }
  // Existing method: the extension signs typed data for its selected network only, so the site first asks for the
  // bot's chain id (0xaa36a7 for Ethereum Sepolia; a site may switch to Sepolia after the extension's change 6).
  async function switchEthereumChain(ethChainId) {
    const provider = await getProvider();
    if (!provider) throw new AdapterError('no_extension', 'The Nodus Connect extension was not found.');
    await request(provider, 'wallet_switchEthereumChain', [{ chainId: `0x${BigInt(ethChainId).toString(16)}` }]);
  }
  async function hold(input) {
    const result = await run('nodusHold', input);
    const ids = calls.nodusHold.interpret(result);
    return { result, holdId: ids.holdId, transferId: ids.transferId, chainId: ids.chainId };
  }
  const done = result => ({ delivered: true, result });
  return {
    // input: { botUrl, ethereumAddress, nodusAddress, token, payTo, amountUsdtRaw, minimumNodusRaw, requestNumber, ethChainId }
    async usdtToNodus(input) {
      assertConfigured('usdtToNodus');
      needToken(input.token);
      await switchEthereumChain(input.ethChainId);
      return done(await run('usdtToNodus', {
        from: input.ethereumAddress, botUrl: input.botUrl, token: input.token, payTo: input.payTo,
        destination: input.nodusAddress, amount: raw(input.amountUsdtRaw), minimumToReceive: raw(input.minimumNodusRaw),
        requestNumber: String(input.requestNumber),
      }));
    },
    // input: { botUrl, nodusAddress, ethereumAddress, payTo, amountNodusRaw, minimumUsdtRaw, requestNumber }
    async nodusToUsdt(input) {
      assertConfigured('nodusHold', 'nodusToUsdt');
      const held = await hold({ account: input.nodusAddress, to: input.payTo, amount: raw(input.amountNodusRaw) });
      const text = buildNodusToUsdtText({
        sender: input.nodusAddress, destination: input.ethereumAddress, amountNodusRaw: input.amountNodusRaw,
        minimumUsdtRaw: input.minimumUsdtRaw, transferId: held.transferId, chainId: held.chainId,
        requestNumber: input.requestNumber,
      });
      return done(await run('nodusToUsdt', { holdId: held.holdId, botUrl: input.botUrl, text }));
    },
    // input: { botUrl, ethereumAddress, nodusAddress, token, payEthereum, payNodus, usdtAmountRaw, nodusAmountRaw,
    //          requestNumber, ethChainId }
    async liquidityAdd(input) {
      assertConfigured('liquidityAdd', 'nodusHold');
      needToken(input.token);
      await switchEthereumChain(input.ethChainId);
      const held = await hold({ account: input.nodusAddress, to: input.payNodus, amount: raw(input.nodusAmountRaw) });
      const text = buildLiquidityAddText({
        ethereumAddress: input.ethereumAddress, nodusAddress: input.nodusAddress,
        usdtAmountRaw: input.usdtAmountRaw, nodusAmountRaw: input.nodusAmountRaw,
        transferId: held.transferId, chainId: held.chainId, requestNumber: input.requestNumber,
      });
      return done(await run('liquidityAdd', {
        holdId: held.holdId, botUrl: input.botUrl, ethereumAddress: input.ethereumAddress, token: input.token,
        payTo: input.payEthereum, usdtAmount: raw(input.usdtAmountRaw), nodusAmount: raw(input.nodusAmountRaw),
        requestNumber: String(input.requestNumber), text,
      }));
    },
  };
}
