// Read balances: this identity's NODUS (native) balance, its EVM balance and
// nonce, and — with NODUS_TOKEN — its NodusToken balance. Reads only; nothing
// is signed.
//
//   NODUS_PHRASE=…  [NODUS_TOKEN=0x<64 hex>]  [NODUS_ENDPOINT=…]  node examples/read-balance.mjs
import { readFileSync } from 'node:fs';
import { formatRaw, formatWei, formatUnits } from '../src/index.js';
import { env, open } from './_common.mjs';

const abi = JSON.parse(readFileSync(new URL('../../../nodus/tools/evm/examples/out/NodusToken.abi.json', import.meta.url), 'utf8'));
const token = env('NODUS_TOKEN');

const evm = await open();
try {
  const nodus = await evm.nodusBalance();
  console.log(`NODUS: ${formatRaw(nodus.total)} (spendable ${formatRaw(nodus.spendable)})`);
  const acct = await evm.account();
  console.log(`EVM balance: ${formatWei(acct.balanceWei)} NODUS, nonce ${acct.nonce} (at block ${acct.height})`);
  if (token) {
    const r = await evm.call({ to: token, abi, fn: 'balanceOf', args: [evm.address] });
    const symbol = (await evm.call({ to: token, abi, fn: 'symbol' })).values[0];
    console.log(`${symbol}: ${formatUnits(r.values[0], 18)} (at block ${r.height})`);
  }
} finally {
  evm.close();
}
