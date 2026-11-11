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
