import { integer, vaultArgs, escrowArgs, contractAddress } from './config.mjs';

export const HELP = `Nodus developer starter (Linux x86-64, testnet identities)
  doctor                         verify package, compiler and SDK imports; offline
  identity                       derive NODUS/EVM addresses; offline
  compile vault|escrow            recompile and compare the bundled template
  balance [evm-address]           native balance of actor + EVM balance
  deposit <raw>                  move actor's native NODUS into its EVM balance
  pending                        resolve/print the actor's pending reservation
  vault deploy                   constructor from config
  vault fund <wei>                transfer EVM value into receive()
  vault submit <to> <wei>         propose a payment with empty calldata
  vault approve|execute <id>      approve or execute an on-chain proposal
  vault simulate-execute <id>     read-only simulation; no fee or signature
  vault state [id]                owners, threshold, balance and optional proposal
  vault events <from> <to>        decode events over at most 10000 blocks
  escrow deploy                  constructor from config
  escrow fund                    payer sends exactly total() from its EVM balance
  escrow release|refund <index>   settle a milestone as payer
  escrow resolve <index> payee|payer   settle as arbiter
  escrow withdraw                withdraw caller's credit to its EVM balance
  escrow simulate-release <index>     read-only authorization check
  escrow state                   parties, milestones, credits and accounting
  escrow events <from> <to>       decode events over at most 10000 blocks

Config: NODUS_CONFIG or ./starter.config.json (no keys).
Identity: NODUS_PHRASE environment only. Every write requires a terminal and yes.
Amounts are decimal integers: 1 NODUS = 100000000 raw = 1000000000000000000 wei.
`;

function arity(args, min, max = min) {
  if (args.length < min || args.length > max) throw new Error('Wrong number of arguments; run with help.');
}

// Validate all user arguments before deriving a key or opening a connection.
export function prepareCommand(argv, config, sdk) {
  const [kind, action, ...args] = argv;
  if (kind === 'balance') {
    arity(argv, 1, 2);
    return { kind, address: action === undefined ? undefined : sdk.parseAddress(action), write: false };
  }
  if (kind === 'deposit') {
    arity(argv, 2);
    return { kind, amount: integer(action, 'deposit raw amount', { positive: true, bits: 64 }), write: true };
  }
  if (kind === 'pending') { arity(argv, 1); return { kind, write: false }; }
  if (!['vault', 'escrow'].includes(kind)) throw new Error('Unknown command; run with help.');
  if (action === 'deploy') {
    arity(args, 0);
    return { kind, action, args: kind === 'vault' ? vaultArgs(config, sdk) : escrowArgs(config, sdk), write: true };
  }
  const to = contractAddress(config, kind, sdk);
  const result = { kind, action, to, write: true, args: [] };
  if (action === 'events') {
    arity(args, 2);
    const fromHeight = integer(args[0], 'from height', { bits: 64 }), toHeight = integer(args[1], 'to height', { bits: 64 });
    if (toHeight < fromHeight || toHeight - fromHeight >= 10000n) throw new Error('Event range must contain 1 to 10000 blocks.');
    return { ...result, write: false, fromHeight, toHeight };
  }
  if (action === 'state') {
    arity(args, 0, kind === 'vault' ? 1 : 0);
    return { ...result, write: false, id: args.length ? integer(args[0], 'proposal id') : undefined };
  }
  if (kind === 'vault') {
    if (action === 'fund') {
      arity(args, 1);
      return { ...result, valueWei: integer(args[0], 'fund wei', { positive: true }) };
    }
    if (action === 'submit') {
      arity(args, 2);
      const recipient = sdk.parseAddress(args[0]);
      if (/^0{64}$/.test(recipient)) throw new Error('Payment recipient must be nonzero.');
      return { ...result, args: [`0x${recipient}`, integer(args[1], 'payment wei', { positive: true }), '0x'] };
    }
    if (['approve', 'execute', 'simulate-execute'].includes(action)) {
      arity(args, 1);
      return { ...result, args: [integer(args[0], 'proposal id')], write: action !== 'simulate-execute' };
    }
  } else {
    if (['fund', 'withdraw'].includes(action)) { arity(args, 0); return result; }
    if (['release', 'refund', 'simulate-release', 'resolve'].includes(action)) {
      arity(args, action === 'resolve' ? 2 : 1);
      const index = integer(args[0], 'milestone index');
      if (index >= 32n) throw new Error('Milestone index must be below 32.');
      if (action === 'resolve' && !['payee', 'payer'].includes(args[1])) throw new Error('resolve recipient must be payee or payer.');
      return { ...result, args: action === 'resolve' ? [index, args[1] === 'payee'] : [index], write: action !== 'simulate-release' };
    }
  }
  throw new Error('Unknown template action; run with help.');
}

async function events(evm, command, template, sdk, emit) {
  let cursor, previous;
  do {
    const page = await evm.logs({ address: command.to, fromHeight: command.fromHeight, toHeight: command.toHeight, limit: 1000, cursor });
    for (const log of page.logs) emit({ ...log, event: sdk.decodeLog(template.abi, log) });
    if (!page.more) return { complete: true, fromHeight: command.fromHeight, toHeight: command.toHeight };
    cursor = page.cursor;
    const position = [cursor?.height, cursor?.index, cursor?.logIndex];
    if (position.some(value => typeof value !== 'bigint') || position[0] > command.toHeight ||
        (previous && !(position[0] > previous[0] || (position[0] === previous[0] && (position[1] > previous[1] || (position[1] === previous[1] && position[2] > previous[2])))))) {
      throw new Error('Event pagination did not advance within the requested range.');
    }
    previous = position;
  } while (true);
}

export async function executeCommand(command, { evm, options, templates, sdk, emit }) {
  if (command.kind === 'balance') return { actor: evm.displayAddress, native: await evm.nodusBalance(), evmAddress: command.address ?? evm.address, evm: await evm.account(command.address) };
  if (command.kind === 'deposit') return evm.deposit(command.amount, options);
  if (command.kind === 'pending') return { pending: evm.pending() };
  const template = templates[command.kind];
  if (command.action === 'deploy') return evm.deploy({ abi: template.abi, bytecode: template.bytecode, args: command.args }, options);
  // The examples are for these exact templates, not an arbitrary contract
  // at a mistyped address. Read trust remains the SDK's single-node model.
  const code = await evm.code(command.to);
  if (code.code !== template.runtimeBytecode) throw new Error('The address does not contain this packaged template runtime. Check the address, network and compiler configuration.');
  const call = (fn, args = []) => evm.call({ to: command.to, abi: template.abi, fn, args });
  const read = async (fn, args = []) => (await call(fn, args)).values;
  if (command.action === 'events') return events(evm, command, template, sdk, emit);
  if (command.action === 'state') {
    const state = { address: command.to, account: await evm.account(command.to) };
    if (command.kind === 'vault') {
      for (const fn of ['getOwners', 'threshold', 'configVersion', 'proposalCount']) state[fn] = (await read(fn))[0];
      if (command.id !== undefined) state.proposal = await read('getProposal', [command.id]);
    } else {
      for (const fn of ['parties', 'accounting']) state[fn] = await read(fn);
      for (const fn of ['deadline', 'total', 'funded', 'milestoneCount']) state[fn] = (await read(fn))[0];
      if (state.milestoneCount > 32n) throw new Error('Invalid milestone count.');
      state.milestones = [];
      for (let i = 0n; i < state.milestoneCount; i++) state.milestones.push(await read('milestone', [i]));
      state.actorCreditWei = (await read('creditOf', [`0x${evm.address}`]))[0];
    }
    return state;
  }
  if (command.action.startsWith('simulate-')) return call(command.action.slice('simulate-'.length), command.args);
  if (command.kind === 'vault' && command.action === 'fund') return evm.transfer({ to: command.to, valueWei: command.valueWei }, options);
  const valueWei = command.kind === 'escrow' && command.action === 'fund' ? (await read('total'))[0] : 0n;
  return evm.send({ to: command.to, abi: template.abi, fn: command.action, args: command.args, valueWei }, options);
}
