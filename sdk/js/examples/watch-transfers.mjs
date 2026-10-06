// Watch a NodusToken's Transfer events (evm_logs: address + topic0, a block
// range of at most 10 000, paged by cursor), from NODUS_FROM_HEIGHT (default:
// the tip) on, polling every 10 s. Reads only. Ctrl-C to stop.
//
//   NODUS_PHRASE=…  NODUS_TOKEN=0x<64 hex>  [NODUS_FROM_HEIGHT=<block>]  [NODUS_ENDPOINT=…]
//   node examples/watch-transfers.mjs
// (The phrase opens the session; logs are public, the identity is only the
// connection's.)
import { readFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { Interface, decodeLog, formatUnits, toChecksumAddress, EVM_LOGS_SPAN } from '../src/index.js';
import { env, open } from './_common.mjs';

const abi = JSON.parse(readFileSync(new URL('../../../nodus/tools/evm/examples/out/NodusToken.abi.json', import.meta.url), 'utf8'));
const token = env('NODUS_TOKEN', { required: true });
const topic0 = new Interface(abi).encodeEventTopics('Transfer')[0];
const fromEnv = env('NODUS_FROM_HEIGHT');

const evm = await open();
let stop = false;
process.on('SIGINT', () => { stop = true; });
try {
  let next = fromEnv === undefined ? await evm.tip() : BigInt(fromEnv);
  while (!stop) {
    const tip = await evm.tip();
    while (!stop && next <= tip) {
      const to = next + BigInt(EVM_LOGS_SPAN) - 1n < tip ? next + BigInt(EVM_LOGS_SPAN) - 1n : tip;
      let cursor;
      do {
        const page = await evm.logs({ fromHeight: next, toHeight: to, address: token, topics: [topic0], cursor });
        for (const log of page.logs) {
          const ev = decodeLog(abi, log);
          if (!ev) continue;
          const [from, dest, value] = ev.args.map(a => a.value);
          console.log(`block ${log.height}: ${toChecksumAddress(from)} -> ${toChecksumAddress(dest)} ${formatUnits(value, 18)} (tx ${log.intentId.slice(0, 16)}…)`);
        }
        cursor = page.more ? page.cursor : undefined;
      } while (cursor && !stop);
      next = to + 1n;
    }
    if (!stop) await sleep(10000);
  }
} finally {
  evm.close();
}
