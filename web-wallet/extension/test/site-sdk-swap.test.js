import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusConnector, holdTransfer, sendLiquidityAdd, sendNodusToUsdt, sendUsdtToNodus } from '../site-sdk/index.mjs';
import { SWAP_METHODS } from '../src/constants/swap.js';

// The site SDK's four swap calls (plan 2026-11-08-swap-bot-plan.nodus1.md section 18 change 1). Environment: Node >=22.14;
// a stub provider announced through EIP-6963 on an in-memory EventTarget; no flags, no network, no files. This proves
// only that each call reaches the discovered Nodus provider with the exact method name and the one request object the
// extension's background expects (SWAP_METHODS); the background's behaviour is swap-site.test.js. A wrong method name
// in both the SDK and the constants would still pass here, which is why the names are compared with the background's.
test('the SDK swap calls send the exact method and one request object to the Nodus provider', async () => {
  const window = Object.assign(new EventTarget(), { Event, CustomEvent }), requests = [];
  window.addEventListener('eip6963:requestProvider', () => {
    window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: { info: { name: 'Nodus Wallet', rdns: 'io.nodusnetwork.wallet' },
      provider: { async request(args) { requests.push(args); return { ok: args.method }; } } } }));
  });
  const connector = createNodusConnector({ window }), request = { holdId: '1', botUrl: 'https://swap.nodusnetwork.io' };
  assert.deepEqual(await connector.holdTransfer(request), { ok: SWAP_METHODS.holdTransfer });
  await connector.sendNodusToUsdt(request); await connector.sendUsdtToNodus(request); await connector.sendLiquidityAdd(request);
  assert.deepEqual(requests, Object.values(SWAP_METHODS).map(method => ({ method, params: [request] })));
  for (const exported of [holdTransfer, sendNodusToUsdt, sendUsdtToNodus, sendLiquidityAdd]) assert.equal(typeof exported, 'function');
});
