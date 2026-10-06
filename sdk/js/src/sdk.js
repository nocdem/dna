// NodusEvm — one Nodus identity's EVM account for a Node.js script.
//
// Built from the web wallet's parts (./wallet.js): the send module (C ->
// WASM, node-environment build of the SAME sources, release C flags —
// scripts/build-wasm.sh), its client (one operation queue, the lock order),
// and src/evm/contract.js (EvmAccount: estimate -> build + sign -> review ->
// record -> submit -> receipt; ONE pending EVM transaction per sender,
// decision 2026-10-04-nodus-evm-kurultay-k2-summary.md #2).
//
// Lifecycle: open() derives the identity offline (no network); connect()
// opens the pinned tier-2 session over ws(s) and checks the chain id;
// close() locks the module (session closed, linear memory zeroed, instance
// released — web-wallet/src/nodus/client.js lock).
//
// Every answer is ONE node's committed tip state (design §18; the wallet's
// trust model): a receipt's digest is re-checked against its own fields,
// not against the chain (web-wallet/src/evm/rpc.js parseReceipt).
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  createNodusSendModule, createNodusClient, EvmAccount, Contract, Interface, parseAddress, toChecksumAddress,
  revertText, parseBalance, parseRulesetInfo, hexToBytes
} from './wallet.js';
import { deriveIdentity, signingSeed } from './identity.js';
import { resolveNetwork, resolveEvmNetwork } from './network.js';
import { reviewAndSend } from './review.js';

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/, RAW = /^(0|[1-9]\d{0,19})$/;
export const DEFAULT_WASM_DIR = fileURLToPath(new URL('../wasm/', import.meta.url));

const notActive = () => new Error('Smart contracts are not active on the connected node: it does not run the EVM rule-set generation (on the testnet HF-5 switches the EVM on at block 79,757), or the send module was built without them.');

function decimal(value, what) {
  let v;
  try { v = BigInt(value); } catch { throw new Error(`Invalid ${what}.`); }
  if (v < 0n || v >= 2n ** 64n) throw new Error(`Invalid ${what}.`);
  return v.toString();
}
function word(value, what) {
  if (typeof value === 'bigint') {
    if (value < 0n || value >= 2n ** 256n) throw new Error(`Invalid ${what}.`);
    return value.toString(16).padStart(64, '0');
  }
  const t = typeof value === 'string' ? value.trim().replace(/^0x/, '').toLowerCase() : '';
  if (!HEX64.test(t)) throw new Error(`Invalid ${what}: 64 hex characters (32 bytes).`);
  return t;
}
function code(bytecode) {
  if (bytecode instanceof Uint8Array) return bytecode;
  const t = typeof bytecode === 'string' ? bytecode.trim().replace(/^0x/, '') : '';
  if (!t || t.length % 2 || !/^[0-9a-fA-F]+$/.test(t)) throw new Error('The bytecode must be hex (the solc --bin output).');
  return `0x${t}`;
}
function raw(amount, what) {
  if (typeof amount !== 'bigint' || amount <= 0n || amount >= 2n ** 64n) throw new Error(`${what} is a positive BigInt of raw NODUS units (1 NODUS = 100000000n).`);
  return amount;
}
const iface = abi => (abi instanceof Interface ? abi : new Interface(abi));

// A restored record ({ hash, expiryHeight, inputs }) — see `pending` below.
function pendingRow(row) {
  if (!row || typeof row.hash !== 'string' || !HEX128.test(row.hash) || !RAW.test(String(row.expiryHeight)) ||
      !Array.isArray(row.inputs) || !row.inputs.every(i => typeof i === 'string' && HEX128.test(i))) throw new Error('Invalid pending transaction record.');
  return Object.freeze({ hash: row.hash, expiryHeight: String(row.expiryHeight), fromHeight: row.fromHeight === undefined ? undefined : String(row.fromHeight), inputs: Object.freeze([...row.inputs]) });
}

export class NodusEvm {
  #client; #account; #identity; #pending;

  constructor(client, identity, pending = []) {
    this.#client = client;
    this.#identity = identity;
    // In-process record of this account's transactions that may still be
    // included: the wallet's Activity rows, held here (contract.js F8). A
    // record leaves only when its receipt, or the chain passing its expiry
    // block, is seen.
    this.#pending = new Map(pending.map(pendingRow).map(r => [r.hash, r]));
    this.#account = new EvmAccount({
      client,
      fingerprint: identity.fingerprint,
      lockedInputs: () => new Set([...this.#pending.values()].flatMap(r => r.inputs)),
      reservations: () => [...this.#pending.values()].map(r => ({ hash: r.hash, expiryHeight: r.expiryHeight }))
    });
  }

  // Derive the identity from the phrase and load the send module — no
  // network. Options:
  //   phrase       the 24-word recovery phrase (required)
  //   network      a NODUS_SEND_NETWORK-shaped object (default: the
  //                wallet's testnet constants)
  //   endpoint     'wss://<IPv4>:<port>' | 'ws://127.0.0.1:<port>' — replaces
  //                the network's endpoint list (chain id and pins kept)
  //   evm          the EVM ruleset identity (default: the wallet's
  //                NODUS_EVM_NETWORK; null = smart contracts off)
  //   wasmDir      where send-node.mjs is (default sdk/js/wasm/)
  //   pending      restored records from an earlier run ({ hash,
  //                expiryHeight, inputs }, as `pending()` returns them)
  //   moduleFactory  TESTS ONLY: replaces the send module
  static async open({ phrase, network, endpoint, evm, wasmDir = DEFAULT_WASM_DIR, pending = [], moduleFactory } = {}) {
    const net = resolveNetwork({ network, endpoint });
    const evmNet = resolveEvmNetwork(evm);
    const identity = await deriveIdentity(phrase);
    let factory = moduleFactory;
    if (!factory) {
      const glue = `${wasmDir.replace(/\/?$/, '/')}send-node.mjs`;
      if (!existsSync(glue)) throw new Error(`The send module is not built: ${glue} is missing (run scripts/build-wasm.sh).`);
      factory = () => createNodusSendModule(net, { evm: evmNet, loadGlue: () => import(pathToFileURL(glue).href) });
    }
    // the keepalive timer must not keep a finished script alive
    const client = createNodusClient({
      factory,
      setInterval: (fn, ms) => { const t = setInterval(fn, ms); t.unref?.(); return t; },
      clearInterval: t => clearInterval(t)
    });
    // the client checks the module derived the SAME address and wipes the
    // seed on every path (web-wallet/src/nodus/client.js identify)
    await client.identify({ seed: signingSeed(phrase), fingerprint: identity.fingerprint });
    return new NodusEvm(client, identity, pending);
  }

  // open() + connect(); on a failed connection the module is locked.
  static async connect(options) {
    const evm = await NodusEvm.open(options);
    try { await evm.connect(); } catch (error) { evm.close(); throw error; }
    return evm;
  }

  // The pinned session + the chain check (nsw_connect), then whether the
  // node runs the EVM generation (client.js evmGate).
  async connect() { await this.#client.connectNetwork(); }

  // Lock: session closed, module memory zeroed, instance released.
  close() { this.#client.lock(); }

  get fingerprint() { return this.#identity.fingerprint; }      // the Nodus address (128 hex)
  get address() { return this.#identity.evmAddress; }          // the EVM address (64 lowercase hex)
  get displayAddress() { return toChecksumAddress(this.address); }
  get state() { return this.#client.state; }
  get chainId() { return this.#client.chainId; }
  // whether the connected node runs the EVM generation and the module can
  // read and build
  get evmActive() { return this.#client.evmReadable && this.#client.evmBuildable; }
  // the records of transactions that may still be included (persist them
  // and pass them back as `pending` to a later open())
  pending() { return [...this.#pending.values()]; }

  #ready({ build = false } = {}) {
    if (this.#client.state !== 'ready') throw new Error('Nodus connection is not ready (call connect()).');
    if (!this.#client.evmReadable || (build && !this.#client.evmBuildable)) throw notActive();
  }

  // ── reads (one node's committed tip state) ─────────────────────────────

  // The connected node's tip height (BigInt; dnac_ruleset_info).
  async tip() {
    if (this.#client.state !== 'ready') throw new Error('Nodus connection is not ready (call connect()).');
    return parseRulesetInfo(await this.#client.rulesetInfo()).tip;
  }
  // The NODUS (native) balance of this identity: { total, spendable } raw units.
  async nodusBalance() {
    if (this.#client.state !== 'ready') throw new Error('Nodus connection is not ready (call connect()).');
    return parseBalance(await this.#client.balance());
  }
  // { nonce, balanceWei, codeHash, codeSize, height }
  async account(address = this.address) { this.#ready(); return this.#client.evmAccount({ address: parseAddress(address) }); }
  // { code: hex, height }
  async code(address) { this.#ready(); return this.#client.evmCode({ address: parseAddress(address) }); }
  // { value: 64 hex, height }; key: 64 hex or a BigInt slot
  async storage(address, key) { this.#ready(); return this.#client.evmStorage({ address: parseAddress(address), key: word(key, 'storage key') }); }

  // eth_call-like simulation on the tip state (nothing is written, nothing
  // is signed). With `abi` + `fn`: { values, names, gasUsed, height } or a
  // throw carrying the decoded revert reason; with raw `data` instead:
  // { success, output, gasUsed, height }.
  // The simulated sender is this identity's EVM address.
  async call({ to, abi, fn, args = [], data, valueWei = 0n, gas } = {}) {
    this.#ready();
    const opts = { to: parseAddress(to), valueWei };
    if (gas !== undefined) opts.gas = BigInt(gas);
    const run = bytes => this.#account.simulate({ ...opts, data: bytes });
    if (!abi) {
      const bytes = data instanceof Uint8Array ? data : hexToBytes(String(data ?? '').replace(/^0x/, ''));
      return run(bytes);
    }
    const i = iface(abi), f = i.getFunction(fn);
    const r = await run(i.encodeFunctionData(f, args));
    if (!r.success) throw new Error(`The contract refused this call: ${revertText(i.decodeRevert(`0x${r.output}`))}.`);
    return { values: i.decodeFunctionResult(f, `0x${r.output}`), names: f.outputNames, gasUsed: r.gasUsed, height: r.height };
  }

  // The receipt of a transaction (its 128-hex intent id) or null.
  async receipt(intentId) {
    this.#ready();
    if (typeof intentId !== 'string' || !HEX128.test(intentId)) throw new Error('A transaction id is 128 lowercase hex characters.');
    return this.#client.evmReceipt({ intentId });
  }

  // One page of logs: { logs: [{ height, index, logIndex, address, topics,
  // data, intentId }], more, cursor }. Range at most 10 000 blocks, at most
  // `limit` (<= 1000) logs; when `more`, send `cursor` back with the SAME
  // range / address / topics for the next page (a page may be empty).
  async logs({ fromHeight, toHeight, address, topics = [], limit, cursor } = {}) {
    this.#ready();
    const args = { fromHeight: decimal(fromHeight, 'fromHeight'), toHeight: decimal(toHeight, 'toHeight') };
    if (limit !== undefined) args.limit = decimal(limit, 'limit');
    if (address !== undefined) args.address = parseAddress(address);
    if (!Array.isArray(topics) || topics.length > 4) throw new Error('topics: at most 4 (topic0 = the event signature hash; null = any).');
    args.topics = topics.map((t, k) => (t === null || t === undefined ? null : word(t, `topic ${k}`)));
    if (cursor) args.cursor = { height: decimal(cursor.height, 'cursor'), index: decimal(cursor.index, 'cursor'), logIndex: decimal(cursor.logIndex, 'cursor') };
    return this.#client.evmLogs(args);
  }

  // A contract at `address` (the wallet's Contract): read(fn, args),
  // estimate(fn, args), decodeReceiptLogs(receipt), iface.
  contract(address, abi) { return new Contract({ account: this.#account, address, abi }); }

  // ── writes (estimate -> fee -> confirm -> record -> submit -> receipt) ─
  //
  // Every write takes { confirm, maxFee?, onRecord? }:
  //   confirm(review)  REQUIRED; must return exactly true to send. `review`
  //                    = { op, intentId, fee (BigInt raw), feeText, rows
  //                    (the wallet's review lines), decoded (read back from
  //                    the signed bytes), expiresAt }.
  //   maxFee           BigInt raw units; a built fee above it is refused
  //                    (the wallet's own bound, 50 NODUS, always applies).
  //   onRecord(row)    optional; awaited BEFORE the envelope is sent with
  //                    { hash, expiryHeight, fromHeight, inputs } — persist
  //                    it to survive a crash (then pass it back as
  //                    open({ pending })). A throw sends nothing.
  // Resolves { intentId, status: 'applied-success' | 'applied-failed' |
  // 'refused', receipt?, createdCheck, createdExpected }.

  async #write(prepare, { confirm, maxFee, onRecord } = {}) {
    if (typeof confirm !== 'function') throw new Error('A confirm function is required: the SDK never signs and sends without the caller\'s confirmation. Nothing was built.');
    if (onRecord !== undefined && typeof onRecord !== 'function') throw new Error('onRecord must be a function.');
    this.#ready({ build: true });
    await this.checkPending();
    const onBroadcast = async details => {
      const row = pendingRow(details);
      if (onRecord) await onRecord({ ...row, inputs: [...row.inputs] });
      this.#pending.set(row.hash, row);
    };
    try {
      const result = await reviewAndSend(prepare, { confirm, maxFee, onBroadcast });
      this.#pending.delete(result.intentId);
      return result;
    } catch (error) {
      // submitted (or maybe submitted): the record leaves once the receipt
      // or the expiry is seen
      error?.sent?.receipt?.then(() => this.#pending.delete(error.sent.intentId), () => {});
      throw error;
    }
  }

  // Resolve the records of earlier transactions: a receipt, or the chain
  // past the expiry block (then one more receipt read), removes one. Runs
  // before every write; a record still undecided blocks the next write
  // (one pending EVM transaction per sender).
  async checkPending() {
    if (this.#pending.size === 0) return;
    this.#ready();
    for (const row of [...this.#pending.values()]) {
      if (await this.#client.evmReceipt({ intentId: row.hash })) { this.#pending.delete(row.hash); continue; }
      const { tip } = parseRulesetInfo(await this.#client.rulesetInfo());
      if (tip > BigInt(row.expiryHeight)) {
        await this.#client.evmReceipt({ intentId: row.hash });
        this.#pending.delete(row.hash);
      }
    }
  }

  // NODUS -> this identity's EVM balance (amountRaw: BigInt raw units).
  deposit(amountRaw, options) {
    const amount = raw(amountRaw, 'The amount');
    return this.#write(() => this.#account.deposit(amount), options);
  }
  // EVM balance -> NODUS at `dest` (128-hex Nodus address; default: this
  // identity). Whole raw units only; a remainder below 10^10 wei stays.
  withdraw(amountRaw, { dest = this.fingerprint, ...options } = {}) {
    const amount = raw(amountRaw, 'The amount');
    return this.#write(() => this.#account.withdraw(amount, dest), options);
  }
  // Deploy: bytecode = the creation hex (solc --bin of the Nodus solc), abi
  // for the constructor arguments. The result carries `address` = the new
  // contract when the receipt's "cr" equals the address computed from the
  // signed transaction (createdCheck 'match'); otherwise null.
  async deploy({ bytecode, abi = [], args = [], valueWei = 0n, gasLimit }, options) {
    const result = await this.#write(() => Contract.prepareDeploy({ account: this.#account, bytecode: code(bytecode), abi, args, valueWei, gasLimit }), options);
    return { ...result, address: result.createdCheck === 'match' ? result.createdExpected : null };
  }
  // A state-changing call: fn by name or full signature.
  send({ to, abi, fn, args = [], valueWei = 0n, gasLimit }, options) {
    const contract = this.contract(to, abi);
    return this.#write(() => contract.prepareSend(fn, args, { valueWei, gasLimit }), options);
  }
}

// A log ({ topics: [64 hex], data: hex }, as logs() / a receipt returns it)
// decoded with `abi`: { name, signature, args: [{ name, value }] } or null.
export function decodeLog(abi, log) {
  return iface(abi).parseLog({ topics: log.topics.map(t => `0x${t}`), data: `0x${log.data}` });
}
