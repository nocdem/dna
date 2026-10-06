// Shared by the examples: settings from the ENVIRONMENT only (never argv,
// never a committed file), and an interactive confirm.
//
//   NODUS_PHRASE    the 24-word recovery phrase (required)
//   NODUS_ENDPOINT  optional, e.g. wss://164.68.116.180:443 — default: the
//                   wallet's testnet endpoint list (tried in order)
//   NODUS_MAX_FEE   optional, raw NODUS units (1 NODUS = 100000000); a built
//                   fee above it is refused
import { createInterface } from 'node:readline/promises';
import { NodusEvm, formatRaw } from '../src/index.js';

export function env(name, { required = false } = {}) {
  const v = process.env[name];
  if (required && (v === undefined || v.trim() === '')) {
    console.error(`Set ${name} in the environment.`);
    process.exit(2);
  }
  return v === undefined || v.trim() === '' ? undefined : v.trim();
}

export async function open() {
  const phrase = env('NODUS_PHRASE', { required: true });
  const endpoint = env('NODUS_ENDPOINT');
  const evm = await NodusEvm.connect({ phrase, ...(endpoint ? { endpoint } : {}) });
  console.log(`EVM address: ${evm.displayAddress}`);
  if (!evm.evmActive) {
    console.error('Smart contracts are not active on this node yet (testnet: HF-5, block 79,757).');
    evm.close();
    process.exit(3);
  }
  return evm;
}

export function maxFee() {
  const v = env('NODUS_MAX_FEE');
  if (v === undefined) return undefined;
  if (!/^(0|[1-9]\d*)$/.test(v)) { console.error('NODUS_MAX_FEE is raw units: digits only.'); process.exit(2); }
  return BigInt(v);
}

// Show the review and ask. Only the typed word "yes" confirms; with no
// terminal there is nobody to ask, so nothing is sent.
export async function confirm(review) {
  if (!process.stdin.isTTY) { console.error('No terminal to confirm on: nothing is sent.'); return false; }
  console.log('\n— Review —');
  for (const [label, value] of review.rows) console.log(`${label}: ${value}`);
  console.log(`(fee ${formatRaw(review.fee)} NODUS; this review expires in ${Math.max(0, Math.floor((review.expiresAt - Date.now()) / 1000))} s)`);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try { return (await rl.question('Type yes to sign and send: ')).trim() === 'yes'; } finally { rl.close(); }
}

export function show(result) {
  console.log(`transaction ${result.intentId}`);
  console.log(`status: ${result.status}`);
  if (result.receipt) console.log(`included at block ${result.receipt.height}, gas used ${result.receipt.gasUsed}`);
}
