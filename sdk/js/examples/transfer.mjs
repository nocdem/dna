// Transfer example tokens: transfer(address,uint256) on a deployed
// NodusToken.
//
//   NODUS_PHRASE=…  NODUS_TOKEN=0x<64 hex>  NODUS_TO=0x<64 hex>
//   NODUS_AMOUNT=<token units, e.g. 1.5>  [NODUS_ENDPOINT=…] [NODUS_MAX_FEE=<raw>]
//   node examples/transfer.mjs
// Addresses are 32 bytes (64 hex digits); a 20-byte Ethereum address is refused.
import { readFileSync } from 'node:fs';
import { parseUnits } from '../src/index.js';
import { env, open, confirm, maxFee, show } from './_common.mjs';

const abi = JSON.parse(readFileSync(new URL('../../../nodus/tools/evm/examples/out/NodusToken.abi.json', import.meta.url), 'utf8'));
const token = env('NODUS_TOKEN', { required: true });
const to = env('NODUS_TO', { required: true });
const amount = parseUnits(env('NODUS_AMOUNT', { required: true }), 18);   // NodusToken decimals = 18

const evm = await open();
try {
  const before = await evm.call({ to: token, abi, fn: 'balanceOf', args: [evm.address] });
  console.log(`your token balance: ${before.values[0]} base units`);
  const result = await evm.send({ to: token, abi, fn: 'transfer', args: [to, amount] }, { confirm, maxFee: maxFee() });
  show(result);
  if (result.status === 'applied-failed' && result.receipt) console.log('the contract rejected the call (the fee was still charged)');
} finally {
  evm.close();
}
