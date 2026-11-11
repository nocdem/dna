import { getAddress } from 'ethers';
import { rpcErrors } from '@metamask/rpc-errors';
import { CHAINS } from '../../../src/config.js';

// The site methods of the swap and liquidity add (plan 2026-11-08-swap-bot-plan.nodus1.md section 18 change 1).
// Method names, parameters and the approval screen text are choices of this build (the plan leaves them to the
// extension build package). The paths are the bot's (plan 6.4.7; /opt/dna/.claude/worktrees/main-amm/nodus/tools/amm/amm_http.h:44-51).
export const SWAP_METHODS = Object.freeze({
  holdTransfer: 'nodus_swapHoldTransfer',
  sendNodusToUsdt: 'nodus_swapSendNodusToUsdt',
  sendUsdtToNodus: 'nodus_swapSendUsdtToNodus',
  sendLiquidityAdd: 'nodus_swapSendLiquidityAdd',
});
export const SWAP_METHOD_NAMES = Object.freeze(Object.values(SWAP_METHODS));
export const SWAP_PATHS = Object.freeze({ swap: '/amm/swap', liquidityAdd: '/amm/liquidity/add' });
// The approval type of a payment (a held NODUS transfer or the USDT transfer).
export const SWAP_PAYMENT_APPROVAL = 'nodus_swapPayment';

// The one USDT contract a swap payment may name, per selected network. The bot counts only Transfer logs of its
// `usdt_contract` setting (plan 2026-11-08-swap-bot-plan.nodus1.md line 446), so a payment in any other token is lost,
// and a site must not be able to make the screen say USDT for another token. Compared after getAddress normalisation.
// Ethereum: the wallet's own USDT entry, src/config.js:12 (read from there, not copied).
export const SWAP_USDT_CONTRACTS = Object.freeze({
  ethereum: CHAINS.ethereum.tokens.find(entry => entry.symbol === 'USDT').address,
  // MAIN: FILL IN AFTER THE SEPOLIA TEST USDT IS DEPLOYED (plan line 248: "its address written into the setting after
  // the deploy"). While this is null every Sepolia USDT payment is refused.
  sepolia: null,
});
// Throws -32602 unless `token` is the pinned USDT contract of `chain`. Called before any signature, post or payment.
export function assertSwapUsdtToken(chain, token) {
  const pinned = SWAP_USDT_CONTRACTS[chain];
  if (!pinned) throw rpcErrors.invalidParams('The Sepolia test USDT is not set in this extension version, so no USDT payment can be made on this network.');
  if (getAddress(token) !== getAddress(pinned)) throw rpcErrors.invalidParams('The token is not the USDT contract this extension knows for the selected network.');
}
