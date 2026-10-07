// Smart contracts (the Nodus EVM domain) — the wallet-side SDK: an EVM
// account bound to this wallet's Nodus identity, contracts on top of it.
//
// Design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3:
//   §2  every write is ONE envelope [CORE EVMFUND] + [EVM op], built and
//       signed by the module (src/nodus/send-module.js evmBuild) and sent
//       with the existing dnac_spend (client.submit);
//   §4  a CALL / CREATE that starts executing is APPLIED whatever happens:
//       the fee ceiling is paid and the nonce consumed even when it reverts
//       ("applied-failed"); a transaction refused before execution leaves
//       no receipt and pays nothing;
//   §8  the fee is a DECLARED ceiling: units >= static + gas_limit × w_gas
//       + FAIL_RESERVE, fee >= units × gas price — unused gas is not
//       refunded (operator decision k1 #1);
//   §18 reads: evm_account / _code / _storage / _call / _estimate /
//       _receipt / _logs / _ticket (src/nodus/client.js, src/evm/rpc.js).
// Operator decision 2026-10-04-nodus-evm-kurultay-k2-summary.md #2: ONE pending
// EVM transaction per sender — the node refuses a nonce other than the
// account's current one, so this SDK waits for the previous transaction's
// inclusion (or its expiry) before it builds the next (EvmAccount.queue).
//
// Red-team 1 (decision 2026-10-05-nodus-evm-redteam1-kurultay-summary.md):
//   F8  the reservation is DURABLE: confirm(onBroadcast) requires the host's
//       onBroadcast, which writes the wallet's Activity row (the NODUS row
//       shape adapters/nodus.js lockedInputs holds coins by) and saves it
//       BEFORE the envelope leaves the browser; build() refuses while such
//       a row is unresolved (reservations()). An ambiguous submission or a
//       receipt-polling error does NOT release it — only a receipt, or the
//       chain passing the expiry block, does (or the Activity tracker
//       resolving the row).
//   F9  the node's evm_estimate is refused when malformed (used <= ge <=
//       EVM_TX_GAS_CAP; the read-unit bound is the module's,
//       nodus-send-wasm.c nsw_evm_core) and the FINAL fee is refused above
//       EVM_MAX_FEE_RAW (units and gas price both come from the node).
//   F11 a deployment's address is computed from the signed transaction
//       (decoded.created, the module's nsw_evm_built_created) and compared
//       with the receipt's "cr", which is the connected node's report.
import { Interface, decodeRevert } from './abi.js';
import { bytesToHex, evmAddressFromFingerprint, parseAddress, toChecksumAddress } from './address.js';
import { formatRaw, formatWei, weiToWord } from './units.js';
import { NODUS_REVIEW_MS, expiryCapRows, expiryHeightFor, parseBalance, parseCoins, parseRulesetInfo, parseTip } from '../adapters/nodus.js';

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/, RAW = /^(0|[1-9]\d{0,19})$/;
const OPS = Object.freeze(['call', 'create', 'deposit', 'withdraw', 'redeem']);
const OP_TEXT = Object.freeze({ 1: 'Contract call', 2: 'Contract deployment', 3: 'Move NODUS to smart contracts', 4: 'Move NODUS back', 5: 'Collect a withdrawal ticket' });

// Receipt polling: every POLL_MIN_MS at first, ×1.5 up to POLL_MAX_MS,
// until the receipt is there or the chain is past the transaction's expiry
// block (then it can never be included), at most POLL_MAX_ROUNDS reads.
export const POLL_MIN_MS = 2000, POLL_MAX_MS = 15000, POLL_MAX_ROUNDS = 400;

// The largest gas_limit one EVM leg may declare (design §4 EVM_TX_GAS_CAP,
// nodus/src/witness/nodus_witness_runtime.h NODUS_RT_EVM_TX_GAS_CAP). The
// wallet never asks evm_estimate for a `g`, so the node searches up to this.
export const EVM_TX_GAS_CAP = 30000000n;
// The local fee bound (F9): a built fee above it is refused, not offered
// for review. 50 NODUS = 5 × 10^9 raw — a full-cap call (30 000 000 gas ×
// w_gas 1 + EVM_READS_BASE 16 334 reads × w_read 1 + FAIL_RESERVE 4 096 +
// the static units) costs ≈ 36 NODUS at the genesis gas price of 121 raw /
// unit (decision 2026-09-25-gas-price.md). A LOCAL bound, not a chain
// rule — kept at 50 NODUS by the operator after the gas measurement
// (2026-10-07: the costliest valid call ≈ 36.3 NODUS at 121, so the bound
// stops only an abnormal fee); the same value as nodus-cli's
// EVM_FEE_CONFIRM_RAW. Above
// ≈ 166 raw / unit an honest full-cap call is refused here.
export const EVM_MAX_FEE_RAW = 5000000000n;

function raw(value, what) {
  if (typeof value !== 'string' || !RAW.test(value)) throw new Error(`Invalid ${what}.`);
  return BigInt(value);
}
const nodusText = units => `${formatRaw(units)} NODUS`;
const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) { reject(new Error('Request cancelled.')); return; }
  const t = setTimeout(resolve, ms);
  signal?.addEventListener('abort', () => { clearTimeout(t); reject(new Error('Request cancelled.')); }, { once: true });
});

// The module's read-back of a built EVM envelope, checked (G1: the review
// shows only these fields).
export function decodeEvmBuilt(built) {
  const d = built?.decoded, invalid = () => new Error('The Nodus module returned an invalid transaction.');
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw invalid();
  if (!OPS.includes(d.op) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw invalid();
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > 15 || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(i => typeof i === 'string' && HEX128.test(i))) throw invalid();
  const isVm = d.op === 'call' || d.op === 'create';
  if (d.op === 'call' ? !HEX64.test(d.to) : d.to !== '') throw invalid();
  if (isVm ? !HEX64.test(d.valueWei) : d.valueWei !== '') throw invalid();
  if ((d.op === 'withdraw' || d.op === 'redeem') ? !HEX128.test(d.dest) : d.dest !== '') throw invalid();
  if (d.op === 'redeem' ? !HEX128.test(d.ticketId) : d.ticketId !== '') throw invalid();
  // the CREATE address the module computed from the signed sender and
  // nonce; a module without nsw_evm_built_created gives none (null: the
  // receipt's "cr" is then shown unchecked)
  const created = d.created === undefined || d.created === '' ? null : d.created;
  if (created !== null && (d.op !== 'create' || !HEX64.test(created))) throw invalid();
  return {
    envelope: built.envelope, intentId: built.intentId, op: d.op, chainId: d.chainId, inputs: [...d.inputs],
    to: d.to, valueWei: isVm ? BigInt(`0x${d.valueWei}`) : 0n, gasLimit: isVm ? raw(d.gasLimit, 'gas limit') : 0n,
    nonce: d.op === 'redeem' ? null : raw(d.nonce, 'nonce'), units: raw(d.units, 'resource ceiling'),
    amount: isVm ? (d.amount === '' ? 0n : (() => { throw invalid(); })()) : raw(d.amount, 'amount'), dest: d.dest, ticketId: d.ticketId, dataLength: d.dataLength,
    fee: raw(d.fee, 'network fee'), change: raw(d.change, 'change amount'), expiryHeight: raw(d.expiryHeight, 'expiry height'),
    created
  };
}

// A receipt's "cr" against the address computed from the signed CREATE
// (`expected`, null when the module gave none): 'match' | 'mismatch' |
// 'unchecked' | 'none' (not a successful CREATE: no contract).
export function createdCheck(receipt, expected) {
  if (!receipt || receipt.op !== 2 || !receipt.success) return 'none';
  if (expected === null) return 'unchecked';
  return receipt.created === expected ? 'match' : 'mismatch';
}

// One EVM account = this wallet's Nodus identity (its address is the first
// 32 bytes of the fingerprint). `client`: src/nodus/client.js.
// `lockedInputs()`: coins of pending NODUS transactions (adapters/nodus.js
// lockedInputs over the activity) — never offered to the builder.
// `reservations()`: the unresolved Activity rows that may be this account's
// transactions ([{ hash, expiryHeight }], src/app.js evmPending) — the
// durable one-pending reservation (F8), restored with the Activity on load.
export class EvmAccount {
  constructor({ client, fingerprint, lockedInputs = () => new Set(), reservations = () => [] }) {
    if (!client) throw new Error('Nodus connection is not ready.');
    this.client = client;
    this.fingerprint = fingerprint;
    this.address = evmAddressFromFingerprint(fingerprint);
    this.lockedInputs = lockedInputs;
    this.reservations = reservations;
    this.tail = Promise.resolve();     // the one-pending queue (k2 #2)
    this.pending = null;               // { intentId, expiryHeight, receipt }
    this.resolved = new Set();         // intent ids whose receipt / expiry was seen here
  }
  get displayAddress() { return toChecksumAddress(this.address); }

  // The reservations not yet resolved in this tab (a receipt or the expiry
  // seen by waitForReceipt resolves one before the Activity tracker does).
  openReservations() {
    return this.reservations().filter(r => !this.resolved.has(r.hash));
  }
  // Whether a transaction of this account may still be included.
  waiting() { return this.pending !== null || this.openReservations().length > 0; }

  // Poll the receipt of a transaction that may have reached the network.
  // The tab's queue moves on (settle) once polling ends either way; only a
  // receipt or the expiry ('refused') marks the reservation resolved — a
  // polling error leaves it to the Activity tracker (F8).
  watch(intentId, expiryHeight, settle) {
    const receipt = this.waitForReceipt(intentId, expiryHeight);
    this.pending = { intentId, expiryHeight, receipt };
    receipt.then(() => { this.resolved.add(intentId); }, () => {})
      .finally(() => { if (this.pending?.intentId === intentId) this.pending = null; settle(); });
    return receipt;
  }

  ready() {
    if (this.client.state !== 'ready' || this.client.fingerprint !== this.fingerprint) throw new Error('Nodus connection is not ready.');
    if (!this.client.evmReadable) throw new Error('Reading smart contracts from the network is not available in this wallet version.');
  }
  async account(options) { this.ready(); return this.client.evmAccount({ address: this.address }, options); }

  // Simulate a call on the node's tip state (nothing is written).
  async simulate({ to, data, valueWei = 0n, gas }, options) {
    this.ready();
    const args = { from: this.address, data: bytesToHex(data) };
    if (to !== undefined) args.to = to;
    if (valueWei !== 0n) args.value = weiToWord(valueWei);
    if (gas !== undefined) args.gas = gas.toString();
    return this.client.evmCall(args, options);
  }
  async estimate({ to, data, valueWei = 0n }, options) {
    this.ready();
    const args = { from: this.address, data: bytesToHex(data) };
    if (to !== undefined) args.to = to;
    if (valueWei !== 0n) args.value = weiToWord(valueWei);
    return this.client.evmEstimate(args, options);
  }

  // Build + sign one transaction for review, AFTER the previous one of this
  // account was included or expired. request: { op, to?, valueWei?,
  // gasLimit?, data?, accessList?, amountRaw?, dest?, ticketId?, units?,
  // title?, extraRows? }. Returns { review, intentId, fee, cancel(),
  // confirm(onBroadcast) -> { intentId, receipt: Promise } }.
  prepare(request) {
    const run = this.tail.then(() => this.build(request));
    // a failed or cancelled build does not block the next one
    this.tail = run.then(r => r.done, () => undefined);
    return run.then(r => r.review);
  }

  async build(req) {
    this.ready();
    if (!this.client.evmBuildable) throw new Error('Smart contracts are not available in this wallet version.');
    const op = req.op;
    if (!OPS.includes(op)) throw new Error('Unknown smart-contract action.');
    // the durable reservation (F8): a transaction of this account that is
    // still unresolved in Activity — sent in this tab or restored on load
    if (this.openReservations().length) throw new Error('A smart-contract transaction of this account is still waiting to be included or to expire (see Activity). The next one can be prepared after it.');
    const isVm = op === 'call' || op === 'create';
    const data = req.data ?? new Uint8Array(0);
    const valueWei = req.valueWei ?? 0n;
    if (typeof valueWei !== 'bigint' || valueWei < 0n) throw new Error('Invalid value.');
    if (!isVm && (data.length || valueWei !== 0n)) throw new Error('Contract data was given for a transfer.');
    // the nonce: the account's current one (one pending per sender)
    const acct = await this.account();
    let gasLimit = req.gasLimit, units = req.units ?? 0n;
    // the node's evm_estimate (§18): `ue` prices its REFERENCE shape, so it
    // is handed to the module as an estimate — the module adds the read
    // units it implies to the minimum of THIS envelope's shape
    // (nodus/src/client/nodus_v2_evm.h "UNITS") and `units` stays 0
    let estimateUnits = 0n, estimateGas = 0n;
    if (isVm && gasLimit === undefined) {
      const est = await this.estimate({ to: op === 'call' ? req.to : undefined, data, valueWei });
      if (!est.success) {
        const why = decodeRevert(`0x${est.output}`, req.iface);
        throw new Error(`The network expects this ${op === 'create' ? 'deployment' : 'call'} to fail: ${revertText(why)}. Nothing was built.`);
      }
      // ONE node's answer, refused when malformed (F9): the gas it reports
      // used must fit the gas it suggests, and that must stay within the
      // cap the wallet implicitly asked for (no `g` sent: the node searches
      // up to the cap)
      if (est.gasUsed > est.gasLimit || est.gasLimit < 1n || est.gasLimit > EVM_TX_GAS_CAP) throw new Error("The network's estimate for this transaction is malformed. Nothing was built.");
      gasLimit = est.gasLimit;
      if (req.units === undefined) { estimateUnits = est.units; estimateGas = est.gasLimit; }
    }
    if (isVm && (typeof gasLimit !== 'bigint' || gasLimit <= 0n)) throw new Error('Invalid gas limit.');
    const { spendable } = parseBalance(await this.client.balance());
    const listing = await this.client.list();
    const coins = parseCoins(listing);
    if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
    const ruleset = parseRulesetInfo(await this.client.rulesetInfo());
    const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip, ruleset);
    const locked = this.lockedInputs();
    const candidates = coins.filter(c => !locked.has(c.nullifier));
    if (candidates.length === 0) throw new Error(locked.size ? 'Your coins are held by a pending transaction. Wait for it to be included or to expire.' : 'Insufficient NODUS balance for the network fee.');
    const d = decodeEvmBuilt(await this.client.evmBuild({
      op, to: op === 'call' ? req.to : '', valueWei: weiToWord(valueWei), gasLimit: isVm ? gasLimit.toString() : '0',
      nonce: acct.nonce.toString(), data, accessList: req.accessList ?? [], amount: (req.amountRaw ?? 0n).toString(),
      dest: req.dest ?? '', ticketId: req.ticketId ?? '', units: units.toString(), estimateUnits: estimateUnits.toString(),
      estimateGas: estimateGas.toString(), expiryHeight: expiryHeight.toString(), coins: candidates
    }));
    // The signed envelope must be exactly what was requested.
    const same = d.op === op && d.chainId === this.client.chainId && d.expiryHeight === expiryHeight &&
      (op === 'redeem' || d.nonce === acct.nonce) && (!isVm || (d.valueWei === valueWei && d.gasLimit === gasLimit && d.dataLength === data.length)) &&
      (op !== 'call' || d.to === req.to) && (isVm || d.amount === req.amountRaw) &&
      ((op !== 'withdraw' && op !== 'redeem') || d.dest === req.dest) && (op !== 'redeem' || d.ticketId === req.ticketId) &&
      (units === 0n || d.units === units);
    if (!same) throw new Error('The signed transaction does not match your request. Nothing was sent.');
    const amounts = new Map(candidates.map(c => [c.nullifier, BigInt(c.amount)]));
    if (!d.inputs.every(i => amounts.has(i))) throw new Error('The signed transaction uses coins it may not use. Nothing was sent.');
    const inSum = d.inputs.reduce((s, i) => s + amounts.get(i), 0n);
    const lock = op === 'deposit' ? d.amount : 0n;
    if (inSum !== lock + d.fee + d.change) throw new Error('The signed transaction does not add up. Nothing was sent.');
    // the FINAL fee against the local bound (F9): its units and gas price
    // are both the node's numbers
    if (d.fee > EVM_MAX_FEE_RAW) throw new Error(`The network fee for this transaction would be ${nodusText(d.fee)}, above this wallet's limit of ${nodusText(EVM_MAX_FEE_RAW)}. Nothing was sent.`);

    const review = [['Network', 'Nodus testnet — smart contracts'], ['Action', req.title || OP_TEXT[{ call: 1, create: 2, deposit: 3, withdraw: 4, redeem: 5 }[op]]], ['From', this.displayAddress]];
    if (op === 'call') review.push(['To (contract)', toChecksumAddress(d.to)]);
    if (op === 'create') review.push(['To', d.created ? `A new contract at ${toChecksumAddress(d.created)} (computed from this signed transaction)` : 'A new contract (its address is shown once it is included)']);
    if (isVm) review.push(['Value sent', `${formatWei(d.valueWei)} NODUS`], ['Gas limit', d.gasLimit.toString()]);
    if (op === 'deposit') review.push(['Amount', nodusText(d.amount)], ['Arrives at', `${this.displayAddress} (your smart-contract balance)`]);
    if (op === 'withdraw' || op === 'redeem') review.push(['Amount', nodusText(d.amount)], ['Paid to', d.dest], ['Address check', 'Nodus addresses have no checksum. Compare all 128 characters with your source.']);
    if (op === 'redeem') review.push(['Ticket', d.ticketId]);
    review.push(...(req.extraRows || []));
    review.push(['Network fee (most it can cost)', nodusText(d.fee)], ['Resource ceiling', `${d.units} units`], ['Change back to you', nodusText(d.change)],
      ['Valid until block', d.expiryHeight.toString()], ...expiryCapRows(tip, d.expiryHeight, ruleset), ['Chain ID', d.chainId]);
    review.push(isVm
      ? ['Fee note', 'The whole fee shown is charged once the network runs this transaction, even if the contract rejects it; unused gas is not refunded.']
      : ['Fee note', 'If the network refuses this transaction, nothing is charged.']);
    if (listing.truncated === true) review.push(['Coin list', 'Your coin list may be incomplete; only the coins listed are used.']);

    let used = false, settled, timer;
    const done = new Promise(resolve => { settled = resolve; });
    const settle = () => { clearTimeout(timer); settled(); };
    const expiresAt = Date.now() + NODUS_REVIEW_MS;
    const account = this;
    // a review left open past its time closes itself, so it never holds the
    // account's queue
    timer = setTimeout(() => { if (!used) { used = true; settle(); } }, NODUS_REVIEW_MS);
    const view = {
      review, intentId: d.intentId, fee: nodusText(d.fee), expiresAt, op, decoded: d,
      cancel() { if (!used) { used = true; settle(); } },
      // onBroadcast(details) is REQUIRED (F8): the host writes the Activity
      // row — details = { hash, expiryHeight, fromHeight, inputs }, the
      // NODUS pending-send shape (src/activity.js validNodusPending) — and
      // makes it durable before this returns; nothing is sent without it.
      // Resolves { intentId, receipt }; receipt resolves the §18 outcome
      // with `createdCheck` (F11). After the record exists, a failed or
      // refused submission REJECTS with error.sent = the same object: the
      // outcome is uncertain, the reservation stays, the receipt is polled.
      async confirm(onBroadcast) {
        if (used) throw new Error('This review is already closed.');
        used = true;
        clearTimeout(timer);
        try {
          if (Date.now() >= expiresAt) throw new Error('Review expired. Prepare it again.');
          if (typeof onBroadcast !== 'function') throw new Error('This transaction cannot be recorded in Activity. Nothing was sent.');
          // the record is durable before the envelope leaves the browser
          await onBroadcast({ hash: d.intentId, expiryHeight: d.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...d.inputs] });
        } catch (error) { settle(); throw error; }
        // From here the envelope may reach the network: the next
        // transaction of this account waits for this one's receipt or
        // expiry, whatever the submission answers.
        let result, failure = null;
        try { result = await account.client.submit({ envelope: d.envelope }); } catch (error) { failure = error?.message || 'Sending failed.'; }
        if (failure === null && (!result || result.accepted !== true)) failure = `The Nodus network did not accept this transaction.${typeof result?.message === 'string' && result.message ? ` ${result.message}` : ''}`;
        const receipt = account.watch(d.intentId, d.expiryHeight, settle)
          .then(outcome => ({ ...outcome, createdCheck: createdCheck(outcome.receipt, d.created), createdExpected: d.created }));
        const sent = { intentId: d.intentId, receipt };
        if (failure !== null) throw Object.assign(new Error(`${failure} The outcome is tracked in Activity; its coins stay held until it is included or its expiry block passes.`), { sent });
        return sent;
      }
    };
    return { review: view, done };
  }

  // The receipt of `intentId`, polled with bounded backoff. Resolves
  // { status: 'applied-success' | 'applied-failed', receipt } or { status:
  // 'refused' } once the chain is past `expiryHeight` without a receipt
  // (refused before execution, or never included: nothing was charged).
  async waitForReceipt(intentId, expiryHeight, { signal } = {}) {
    let delay = POLL_MIN_MS;
    for (let round = 0; round < POLL_MAX_ROUNDS; round++) {
      const receipt = await this.client.evmReceipt({ intentId }, { signal });
      if (receipt) return { status: receipt.status, receipt };
      const tip = parseRulesetInfo(await this.client.rulesetInfo({ signal })).tip;
      if (tip > expiryHeight) {
        // one more read: the receipt may have landed in the last block seen
        const last = await this.client.evmReceipt({ intentId }, { signal });
        return last ? { status: last.status, receipt: last } : { status: 'refused' };
      }
      await sleep(delay, signal);
      delay = Math.min(POLL_MAX_MS, Math.floor(delay * 1.5));
    }
    throw new Error('No answer about this transaction yet. Check it again later.');
  }

  // Bridge helpers (design §2 ops 3-5). amountRaw: BigInt raw units.
  deposit(amountRaw) { return this.prepare({ op: 'deposit', amountRaw }); }
  withdraw(amountRaw, dest = this.fingerprint) {
    if (typeof dest !== 'string' || !HEX128.test(dest)) throw new Error('Enter a Nodus address: 128 characters, 0-9 and a-f.');
    return this.prepare({ op: 'withdraw', amountRaw, dest });
  }
  async redeem(ticketId, dest = this.fingerprint) {
    if (typeof ticketId !== 'string' || !HEX128.test(ticketId)) throw new Error('Invalid withdrawal ticket.');
    const t = await this.ticket(ticketId);
    if (!t.pending) throw new Error('This ticket was already collected, or it does not exist.');
    if (t.dest !== dest) throw new Error('This ticket pays a different Nodus address.');
    return this.prepare({ op: 'redeem', ticketId, amountRaw: t.amountRaw, dest });
  }
  async ticket(id, options) { this.ready(); return this.client.evmTicket({ id }, options); }
}

export function revertText(r) {
  switch (r.kind) {
    case 'error': return `"${r.message}"`;
    case 'panic': return `${r.message} (code 0x${r.code.toString(16)})`;
    case 'custom': return `${r.name}(${r.args.map(a => String(a.value)).join(', ')})`;
    case 'empty': return 'no reason given';
    default: return 'an unrecognized reason';
  }
}

// A contract at `address` with ABI `abi` (JSON text or array), used through
// `account` (EvmAccount).
export class Contract {
  constructor({ account, address, abi }) {
    this.account = account;
    this.address = parseAddress(address);
    this.iface = abi instanceof Interface ? abi : new Interface(abi);
  }

  // A read-only call on the node's tip state -> decoded outputs, or throws
  // with the revert reason.
  async read(fn, args = [], options) {
    const f = this.iface.getFunction(fn);
    const r = await this.account.simulate({ to: this.address, data: this.iface.encodeFunctionData(f, args) }, options);
    if (!r.success) throw new Error(`The contract refused this call: ${revertText(this.iface.decodeRevert(`0x${r.output}`))}.`);
    return { values: this.iface.decodeFunctionResult(f, `0x${r.output}`), names: f.outputNames, gasUsed: r.gasUsed, height: r.height };
  }

  async estimate(fn, args = [], { valueWei = 0n } = {}) {
    const f = this.iface.getFunction(fn);
    return this.account.estimate({ to: this.address, data: this.iface.encodeFunctionData(f, args), valueWei });
  }

  // Build a write for review (see EvmAccount.prepare).
  prepareSend(fn, args = [], { valueWei = 0n, gasLimit, units } = {}) {
    const f = this.iface.getFunction(fn);
    if (valueWei !== 0n && !f.payable) throw new Error(`${f.name} does not accept value.`);
    return this.account.prepare({
      op: 'call', to: this.address, data: this.iface.encodeFunctionData(f, args), valueWei, gasLimit, units, iface: this.iface,
      title: `Call ${f.signature}`, extraRows: [['Function', f.signature], ['Arguments', describeArgs(f.inputNames, args)]]
    });
  }

  // Deploy: initcode = bytecode ‖ constructor arguments (abi.js
  // encodeDeploy). Resolves the review; the new address is the receipt's
  // `created`.
  static prepareDeploy({ account, bytecode, abi, args = [], valueWei = 0n, gasLimit, units }) {
    const iface = abi instanceof Interface ? abi : new Interface(abi);
    const data = iface.encodeDeploy(bytecode, args);
    return account.prepare({ op: 'create', data, valueWei, gasLimit, units, iface, title: 'Deploy a contract', extraRows: [['Code size', `${data.length} bytes`], ['Constructor arguments', describeArgs(iface.constructorEntry?.inputNames || [], args)]] });
  }

  // Events of this contract in a receipt, decoded with its ABI.
  decodeReceiptLogs(receipt) {
    return receipt.logs.filter(l => l.address === this.address).map(l => ({ log: l, event: this.iface.parseLog({ topics: l.topics.map(t => `0x${t}`), data: `0x${l.data}` }) }));
  }
}

export function describeArgs(names, args) {
  if (!args.length) return '(none)';
  return args.map((a, i) => `${names[i] || `#${i + 1}`} = ${stringify(a)}`).join(', ');
}
function stringify(v) {
  if (typeof v === 'bigint') return v.toString();
  if (v instanceof Uint8Array) return `0x${bytesToHex(v)}`;
  if (Array.isArray(v)) return `[${v.map(stringify).join(', ')}]`;
  if (v && typeof v === 'object') return `{${Object.entries(v).map(([k, x]) => `${k}: ${stringify(x)}`).join(', ')}}`;
  return String(v);
}
