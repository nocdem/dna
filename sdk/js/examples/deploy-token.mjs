// Deploy the example token (nodus/tools/evm/examples/NodusToken.sol, compiled
// by the Nodus solc: out/default/NodusToken.creation.hex, no constructor
// arguments; the whole supply goes to the deployer) and print its address.
//
//   NODUS_PHRASE=… [NODUS_ENDPOINT=wss://<ip>:443] [NODUS_MAX_FEE=<raw>] node examples/deploy-token.mjs
import { readFileSync } from 'node:fs';
import { open, confirm, maxFee, show } from './_common.mjs';

const OUT = new URL('../../../nodus/tools/evm/examples/out/', import.meta.url);
const bytecode = readFileSync(new URL('default/NodusToken.creation.hex', OUT), 'utf8');
const abi = JSON.parse(readFileSync(new URL('NodusToken.abi.json', OUT), 'utf8'));

const evm = await open();
try {
  const result = await evm.deploy({ bytecode, abi }, { confirm, maxFee: maxFee() });
  show(result);
  if (result.address) console.log(`token address: 0x${result.address}`);
  else console.log(`no contract address (created-address check: ${result.createdCheck})`);
} finally {
  evm.close();
}
